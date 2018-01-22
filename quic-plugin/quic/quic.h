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
 * - A bihash_8_8 (bounded-index extensible hash) - 8 byte key and 8 byte value.
 * - A pool is used to save the state for each QUIC flow (fixed sized struct)
 * - A timer wheel (2t_1w_2048sl = 2 timers per object, 1 wheel, 2048 slots)
 *
 * The key in the hash table consist of (XOR is used to match both directions):
 *   "5 tuple":
 *    - XOR of src and dst IP
 *    - XOR of src and dst port
 *    - protocol
 *
 * The value corresponding to a key (in the hash table) is the pool index
 * for the state of the matching QUIC flow.
 *
 * Besides the actual "state" of the flow we also save e.g. counters, RTT
 * estimates, ...
 *
 * The timer wheel is currently only used to free memory for terminated flows.
 *
 * Currently, the RTT estimation only looks at the 1-bit spin.
 * It accepts all packets which have the valid bit set.
 * Reordered packets will generate additional spin edges.
 */

#ifndef __included_quic_h__
#define __included_quic_h__

/* Select which observers to run */
#define QUIC_BASIC_SPINBIT_OBSERVER
#define QUIC_PN_SPINBIT_OBSERVER
#define QUIC_PN_VALID_SPINBIT_OBSERVER
#define QUIC_TWO_BIT_SPIN_OBSERVER



#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/* We use the bihash_8_8 hash function*/
/* 8 byte key and 8 byte value */
/* Not the same size as in the PLUS plugin */
#include <vppinfra/bihash_8_8.h>

#include <vppinfra/pool.h>

/* Timer wheel (2 timers, 1 wheel, 2048 slots) */
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

/* Defines all the QUIC states */
#define foreach_quic_state \
_(ACTIVE, "default state") \
_(ERROR, "error state")

typedef enum {
#define _(sym,str) QUIC_STATE_##sym,
  foreach_quic_state
#undef _
} quic_state_t;

/* Max values for advancement checks  */
/* TODO: adapt, currently not used */
#define MAX_PSN 4294967296
#define MAX_SKIP 100

#define QUIC_PORT 4433

#define TWO_BIT_SPIN 0xc0
#define ONE_BIT_SPIN 0x40
#define VALID_BIT 0x20
#define BLOCKING_BIT 0x10
/* Not used at the moment */
#define MOVE_TWO_BIT_SPIN 6

typedef struct {
  bool spin_client;
  bool spin_server;
  f64 time_last_spin_client;
  f64 time_last_spin_server;
  f64 rtt_client;
  f64 rtt_server;
} basic_spin_observer_t;

typedef struct {
  bool spin_client;
  bool spin_server;
  f64 time_last_spin_client;
  f64 time_last_spin_server;
  f64 rtt_client;
  f64 rtt_server;
  u32 pn_client;
  u32 pn_server;
} pn_spin_observer_t;

typedef struct {
  bool spin_client;
  bool spin_server;
  f64 time_last_spin_client;
  f64 time_last_spin_server;
  f64 rtt_client;
  f64 rtt_server;
  u32 pn_client;
  u32 pn_server;
} pn_valid_spin_observer_t;

typedef struct {
  u8 spin_client;
  u8 spin_server;
  f64 time_last_spin_client;
  f64 time_last_spin_server;
  f64 rtt_client;
  f64 rtt_server;
} two_bit_spin_observer_t;


/* State for each observed QUIC session */
typedef struct
{
  u8 state;
  u64 connection_id;
  /* Pool index (saved in hash table) */
  u32 index;
  u32 timer;
  u64 key;
  u32 src;
  u64 id;

  /* Data structures for the various spin bit observers */
  basic_spin_observer_t basic_spinbit_observer;
  pn_spin_observer_t pn_spin_observer;
  pn_valid_spin_observer_t pn_valid_spin_observer;
  two_bit_spin_observer_t two_bit_spin_observer;

  /* Number of observed packets */
  u32 pkt_count;
} quic_session_t;

/* Main quic struct */
typedef struct {
  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vnet_main_t * vnet_main;
    
  /* Hash table */
  BVT (clib_bihash) quic_table;

  /* Session pool */
  quic_session_t * session_pool;

  /* Counter values*/
  u32 total_flows;
  u32 active_flows;

  /* Timer wheel*/
  tw_timer_wheel_2t_1w_2048sl_t tw;
} quic_main_t;

/* Hash key struct */
typedef CLIB_PACKED (struct {
  union
  {
    struct
    {
      /* IP and port XOR */
      u32 s_x_d_ip;
      u16 s_x_d_port;
      /* Protocol not really needed but good for alignment */
      u16 protocol;
    };
    u64 as_u64;
  };
}) quic_key_t;

quic_main_t quic_main;

extern vlib_node_registration_t quic_node;

u64 get_state(quic_key_t * kv_in);
void update_state(quic_key_t * kv_in, uword new_state);
void make_key(quic_key_t * kv, ip4_address_t * src_ip, ip4_address_t * dst_ip,
                u16 src_p, u16 dst_p, u8 protocol);
quic_session_t * get_session_from_key(quic_key_t * kv_in);
u32 create_session();
void update_rtt_estimate(vlib_main_t * vm, quic_session_t * session, f64 now,
                u16 src_port, u8 measurement, u32 packet_number);
void clean_session(u32 index);

/**
 * @brief get quic session for index
 */
always_inline quic_session_t * get_quic_session(u32 index) 
{
  if (pool_is_free_index (quic_main.session_pool, index))
    return 0;
  return pool_elt_at_index (quic_main.session_pool, index);
}

/**
 * @brief start a timer in the timer wheel
 */
always_inline void start_timer(quic_session_t * session, u64 interval) {
  session->timer = tw_timer_start_2t_1w_2048sl (&quic_main.tw,
                  session->index, 0, interval);
}

/**
 * @brief update the timer
 */
always_inline void update_timer(quic_session_t * session, u64 interval) {
  if(session->timer != ~0) {
    tw_timer_stop_2t_1w_2048sl (&quic_main.tw, session->timer);
  }
  session->timer = tw_timer_start_2t_1w_2048sl (&quic_main.tw,
                  session->index, 0, interval);
}

/**
 * @brief expire timers
 */
always_inline void expire_timers(f64 now) {
  tw_timer_expire_timers_2t_1w_2048sl (&quic_main.tw, now);
}

/**
 * @brief check if a sequence number comes logically after another one.
 * Supports sequence number overflow.
 * Distance must be smaller than MAX_SKIP.
 */
 /* TODO adapt, currently not used  */
always_inline bool comes_after_u32(u32 now, u32 old) {
  i64 ret = (now - old) % MAX_PSN;
  if (ret < 0) {
    ret += MAX_PSN;
  }
  return ret < MAX_SKIP;
}

#define QUIC_PLUGIN_BUILD_VER "0.1"

#endif /* __included_quic_h__ */
