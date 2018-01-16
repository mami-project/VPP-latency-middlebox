/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/* High-level overview:
 * 
 * Used data structures:
 * - A bihash_16_8 (bounded-index extensible hash) - 16 byte key and 8 byte value.
 * - A pool is used to save the state for each PLUS flow (fixed sized struct)
 * - A timer wheel (2t_1w_2048sl = 2 timers per object, 1 wheel, 2048 slots)
 *
 * The key in the hash table consist of (XOR is used to match both directions):
 *   "5 tuple":
 *    - XOR of src and dst IP
 *    - XOR of src and dst port
 *    - protocol
 *   CAT
 *
 * The value corresponding to a key (in the hash table) is the pool index
 * for the state of the matching PLUS flow.
 *
 * Besides the actual "state" of the flow we also save e.g. counters, RTT
 * estimates, ...
 *
 * The timer wheel is used to implement the various timeout values in the
 * PLUS state machine. If a flow times out, all the state is deleted.
 * The timer wheel advances every time the main loop (in node.c) is executed.
 * Therefore, if we only observe a few PLUS packets, it can happen that some
 * flows are still displayed as "active", even though they are already timed out.
 * They will be deleted as soon as the main loop is executed again.
 *
 * Currently, only one extended header is detected - a hop count of PLUS-aware MBs.
 * PCF type = 1, PCF len = 1, PCF II = 0 (not protected), PCF Value = hop count
 * The implementation will increase the PCF value by one.
 */

#ifndef __included_plus_h__
#define __included_plus_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/* We use the bihash_16_8 hash function*/
/* 16 byte key and 8 byte value */
#include <vppinfra/bihash_16_8.h>

#include <vppinfra/pool.h>

/* Timer wheel (2 timers, 1 wheel, 2048 slots) */
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

/* Defines all the PLUS states */
#define foreach_plus_state \
_(ZERO, "no flow") \
_(UNIFLOW, "flow in one direction") \
_(ASSOCIATING, "also flow in reverse direction") \
_(ASSOCIATED, "flow confirmed") \
_(STOPWAIT, "stop signal in one direction") \
_(STOPPING, "stop signal also in other direction") \
_(ERROR, "error state")

typedef enum {
#define _(sym,str) PLUS_STATE_##sym,
  foreach_plus_state
#undef _
} plus_state_t;

/* Endian correction */
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  #define MAGIC_MASK 0xf0ffffff
  #define MAGIC 0xf07f00d8
  #define STOP 0x02000000
  #define EXTENDED 0x01000000
#else
  #define MAGIC_MASK 0xfffffff0
  #define MAGIC 0xd8007ff0
  #define STOP 0x00000002
  #define EXTENDED 0x00000001
#endif

/* Max values for advancement checks  */
#define MAX_PSN 4294967296
#define MAX_SKIP 100

/* State for each observed PLUS session */
typedef struct
{
  u8 state;
  /* PSN which moved state to ASSOCIATING */
  u32 psn_associating;
  /* PSN which moved state to STOPWAIT */
  u32 psn_stopwait;
  u32 src_ip_dir;
  u64 cat;
  /* Pool index (saved in hash table) */
  u32 index;
  u32 timer;
  u64 key[2];
  u32 src;
  /* For RTT estimations */
  u32 psn_src;
  f64 time_src;
  f64 rtt_src;
  u32 psn_dst;
  f64 time_dst;
  f64 rtt_dst;
  /* Number of observed packets */
  u32 pkt_count;
} plus_session_t;

/* Main plus struct */
typedef struct {
  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vnet_main_t * vnet_main;
    
  /* Hash table */
  BVT (clib_bihash) plus_table;

  /* Session pool */
  plus_session_t * session_pool;

  /* Counter values*/
  u32 total_flows;
  u32 active_flows;

  /* Timer wheel*/
  tw_timer_wheel_2t_1w_2048sl_t tw;
} plus_main_t;

/* Hash key struct */
typedef CLIB_PACKED (struct {
  union
  {
    struct
    {
      /* IP and port XOR */
      u32 s_x_d_ip;
      u16 s_x_d_port;
      /* Protocol (8 -> 16 bit for better alignment) */
      u16 protocol;
      u64 cat;
    };
    u64 as_u64[2];
  };
}) plus_key_t;

plus_main_t plus_main;

extern vlib_node_registration_t plus_node;

u64 get_state(plus_key_t * kv_in);
void update_state(plus_key_t * kv_in, uword new_state);
void make_key(plus_key_t * kv, ip4_address_t * src_ip, ip4_address_t * dst_ip,
                u16 src_p, u16 dst_p, u8 protocol, u64 cat);
plus_session_t * get_session_from_key(plus_key_t * kv_in);
u32 create_session(u64 cat);
void update_rtt_estimate(plus_session_t * session, f64 now, u32 src_address,
                u32 psn, u32 pse);
void clean_session(u32 index);

/**
 * @brief get plus session for index
 */
always_inline plus_session_t * get_plus_session(u32 index) 
{
  if (pool_is_free_index (plus_main.session_pool, index))
    return 0;
  return pool_elt_at_index (plus_main.session_pool, index);
}

/**
 * @brief start a timer in the timer wheel
 */
always_inline void start_timer(plus_session_t * session, u64 interval) {
  session->timer = tw_timer_start_2t_1w_2048sl (&plus_main.tw,
                  session->index, 0, interval);
}

/**
 * @brief update the timer
 */
always_inline void update_timer(plus_session_t * session, u64 interval) {
  if(session->timer != ~0) {
    tw_timer_stop_2t_1w_2048sl (&plus_main.tw, session->timer);
  }
  session->timer = tw_timer_start_2t_1w_2048sl (&plus_main.tw,
                  session->index, 0, interval);
}

/**
 * @brief expire timers
 */
always_inline void expire_timers(f64 now) {
  tw_timer_expire_timers_2t_1w_2048sl (&plus_main.tw, now);
}

/**
 * @brief check if a sequence number comes logically after another one.
 * Supports sequence number overflow.
 * Distance must be smaller than MAX_SKIP.
 */
always_inline bool comes_after_u32(u32 now, u32 old) {
  i64 ret = (now - old) % MAX_PSN;
  if (ret < 0) {
    ret += MAX_PSN;
  }
  return ret < MAX_SKIP;
}

#define PLUS_PLUGIN_BUILD_VER "0.2"

#endif /* __included_plus_h__ */
