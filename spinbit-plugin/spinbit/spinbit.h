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
 * - A pool is used to save the state for each SPINBIT flow (fixed sized struct)
 * - A timer wheel (2t_1w_2048sl = 2 timers per object, 1 wheel, 2048 slots)
 *
 * The key in the hash table consist of (XOR is used to match both directions):
 *   "5 tuple":
 *    - XOR of src and dst IP
 *    - XOR of src and dst port
 *    - protocol
 *
 *    - for PLUS packets we also take the CAT value into the hash key
 *
 * The value corresponding to a key (in the hash table) is the pool index
 * for the state of the matching SPINBIT flow.
 *
 * Besides the actual "state" of the flow we also save e.g. counters, RTT
 * estimates, ...
 */

#ifndef __included_spinbit_h__
#define __included_spinbit_h__

/* Quic handshake states for handshake RTT measurement */
#define SPINBIT_HANDSHAKE_IDLE               0
#define SPINBIT_HANDSHAKE_CLIENT_INITIAL     1
#define SPINBIT_HANDSHAKE_SERVER_CLEARTEXT   2
#define SPINBIT_HANDSHAKE_CLIENT_CLEARTEXT   3

/* Quic header types */
#define SPINBIT_PACKET_LONG_VERSION_NEGOTIATION      0x81
#define SPINBIT_PACKET_LONG_CLIENT_INITIAL           0x82
#define SPINBIT_PACKET_LONG_SERVER_STATELESS_RETRY   0x83
#define SPINBIT_PACKET_LONG_SERVER_CLEARTEXT         0x84
#define SPINBIT_PACKET_LONG_CLIENT_CLEARTEXT         0x85
#define SPINBIT_PACKET_LONG_0_RTT_PROTECTED          0x86
#define SPINBIT_PACKET_LONG_1_RTT_PROTECTED_PHASE_1  0x87
#define SPINBIT_PACKET_LONG_1_RTT_PROTECTED_PHASE_2  0x88
#define SPINBIT_PACKET_SHORT_1_OCTET                 0x01
#define SPINBIT_PACKET_SHORT_2_OCTET                 0x02
#define SPINBIT_PACKET_SHORT_4_OCTET                 0x03

#define SPINBIT_PACKET_SHORT_MASK                    0b10011111
#define SPINBIT_PACKET_LONG_MASK                     0b11111111

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/* We use the bihash_8_8 hash function*/
/* 8 byte key and 8 byte value */
#include <vppinfra/bihash_8_8.h>

#include <vppinfra/pool.h>

/* Timer wheel (2 timers, 1 wheel, 2048 slots) */
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

/* Defines all the SPINBIT states */
#define foreach_spinbit_state \
_(ACTIVE, "default state for TCP and QUIC") \
_(P_ZERO, "PLUS: no flow") \
_(P_UNIFLOW, "PLUS: flow in one direction") \
_(P_ASSOCIATING, "PLUS: also flow in reverse direction") \
_(P_ASSOCIATED, "PLUS: flow confirmed") \
_(P_STOPWAIT, "PLSU: stop signal in one direction") \
_(P_STOPPING, "PLSU: stop signal also in other direction") \
_(ERROR, "error state for all flows")

typedef enum {
#define _(sym,str) SPINBIT_STATE_##sym,
  foreach_spinbit_state
#undef _
} spinbit_state_t;

#define foreach_protocol \
_(TCP, "TCP flow") \
_(QUIC, "QUIC flow") \
_(PLUS, "PLUS flow") \
_(UNKNOWN, "UNKNOWN flow")

typedef enum {
#define _(sym,str) P_##sym,
  foreach_protocol
#undef _
} sup_protocols_t;

/* For output */
#define TIME_PRECISION 8
#define RTT_PRECISION 4
#define STAT_PRECISION 8

#define SPIN_NOT_KNOWN 255

#define TWO_BIT_SPIN 0xc0
#define ONE_BIT_SPIN 0x40
#define VALID_BIT 0x20
#define BLOCKING_BIT 0x10
#define TWO_BIT_SPIN_OFFSET 6
#define VALID_EDGE_BIT 0x01
#define STATUS_MASK 0x0c
#define STATUS_SHIFT 2
#define TCP_SPIN 0x01
#define TCP_VEC_MASK 0x06
#define TCP_VEC_SHIFT 1

/* Endian correction
 * Could also be solved by converting input first */
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

#define MAX_PSN 4294967296
#define MAX_SKIP 100

/* To save current time in hashes */
typedef struct {
  f64 time;
} time_test_t;

/* Structs for the different spin observers */
typedef struct {
  u8 spin_client;
  u8 spin_server;
  f64 time_last_spin_client;
  f64 time_last_spin_server;
  f64 rtt_client;
  f64 rtt_server;
  bool new_client;
  bool new_server;
} basic_spin_observer_t;

typedef struct {
  u8 spin_client;
  u8 spin_server;
  f64 time_last_spin_client;
  f64 time_last_spin_server;
  f64 rtt_client;
  f64 rtt_server;
  u32 pn_client;
  u32 pn_server;
  bool new_client;
  bool new_server;
} pn_spin_observer_t;

#define STATUS_INVALID      0b00
#define STATUS_HANDSHAKE_1  0b01
#define STATUS_HANDSHAKE_2  0b10
#define STATUS_VALID        0b11
typedef struct {
  u8 spin_client;
  u8 spin_server;
  f64 time_last_spin_client;
  f64 time_last_spin_server;
  f64 rtt_client;
  f64 rtt_server;
  bool new_client;
  bool new_server;
} status_spin_observer_t;

#define DYNA_HEUR_THRESHOLD 0.1
#define DYNA_HEUR_HISTORY_SIZE 10
#define DYNA_HEUR_MAX_REJECT 5
typedef struct {
  u8 spin_client;
  u8 spin_server;
  f64 time_last_spin_client;
  f64 time_last_spin_server;
  f64 rtt_client[DYNA_HEUR_HISTORY_SIZE];
  f64 rtt_server[DYNA_HEUR_HISTORY_SIZE];
  u8 index_client;
  u8 index_server;
  u8 rejected_client;
  u8 rejected_server;
  bool new_client;
  bool new_server;
} dyna_heur_spin_observer_t;

/* main QUIC observer struct */
typedef struct {
  u64 id;

  /* Data structures for the various spin bit observers */
  basic_spin_observer_t basic_spin_observer;
  pn_spin_observer_t pn_spin_observer;
  status_spin_observer_t status_spin_observer;
  dyna_heur_spin_observer_t dyna_heur_spin_observer;
} quic_observer_t;

/* structs for the different TCP TS observers */
typedef struct { 
  f64 time_init_client;
  f64 time_init_server;
  f64 rtt_client;
  f64 rtt_server;
  u32 ts_init_client;
  u32 ts_init_server;
  u32 ts_ack_client;
  u32 ts_ack_server;
  bool new_client;
  bool new_server;
} timestamp_observer_single_RTT_t;

typedef struct {
  uword *hash_init_client;
  uword *hash_init_server;
  uword *hash_ack_client;
  uword *hash_ack_server;
  f64 rtt_client;
  f64 rtt_server;
  bool new_client;
  bool new_server;
} timestamp_observer_all_RTT_t;

/* main TCP observer struct */
typedef struct {
  /* Data structures for the spinbit and timestamp observer */
  status_spin_observer_t status_spin_observer;
  status_spin_observer_t vec_ne_zero;
  timestamp_observer_single_RTT_t ts_one_RTT_observer;
  timestamp_observer_all_RTT_t ts_all_RTT_observer;
} tcp_observer_t;

/* struct for PLUS PSE/PSN observer */
typedef struct {
  u32 psn_src;
  f64 time_src;
  f64 rtt_src;
  u32 psn_dst;
  f64 time_dst;
  f64 rtt_dst;
  bool new_server;
  bool new_client;
} plus_single_observer_t;

/* main PLUS observer struct */
typedef struct {
  u8 state;
  /* PSN which moved state to ASSOCIATING */
  u32 psn_associating;
  /* PSN which moved state to STOPWAIT */
  u32 psn_stopwait;
  u64 cat;

  plus_single_observer_t plus_single_observer;
} plus_observer_t;

/* State for each observed SPINBIT session */
typedef struct {
  spinbit_state_t state;

  sup_protocols_t p_type;

  /* Pool index (saved in hash table) */
  u32 index;
  u32 timer;
  u64 key;
  u64 key_reverse;
  
  u32 init_src_ip;
  u16 init_src_port;
  u32 new_dst_ip;
  
  /* Number of observed packets */
  u32 pkt_count;

  /* QUIC and TCP observers
   * only required values are allocated */
  quic_observer_t * quic;
  tcp_observer_t * tcp;
  plus_observer_t * plus;
} spinbit_session_t;

/* Main spinbit struct */
typedef struct {
  /* API message ID base */
  u16 msg_id_base;

  /* single MB IP */
  u32 mb_ip;

  /* convenience */
  vnet_main_t * vnet_main;
    
  /* Hash table */
  BVT (clib_bihash) spinbit_table;

  /* Session pool */
  spinbit_session_t * session_pool;

  /* Contains all ports that indicated QUIC traffic */
  uword *hash_quic_ports;

  /* To translate dst port to required dst IP */
  uword *hash_server_ports_to_ips;
          
  /* Counter values*/
  u32 total_flows;
  u32 active_flows;
  u32 active_tcp;
  u32 active_quic;

  /* Timer wheel*/
  tw_timer_wheel_2t_1w_2048sl_t tw;
} spinbit_main_t;

/* Hash key struct */
typedef CLIB_PACKED (struct {
  union {
    struct {
      /* IP and port XOR */
      u32 s_x_d_ip;
      u16 s_x_d_port;
      u16 protocol;
    };
    u64 as_u64;
  };
}) spinbit_key_t;

spinbit_main_t spinbit_main;

extern vlib_node_registration_t spinbit_node;

u64 get_state(spinbit_key_t * kv_in);
void update_state(spinbit_key_t * kv_in, uword new_state);
void make_key(spinbit_key_t * kv, u32 src_ip, u32 dst_ip,
                u16 src_p, u16 dst_p, u8 protocol);
void make_plus_key(spinbit_key_t * kv, u32 src_ip, u32 dst_ip,
                u16 src_p, u16 dst_p, u8 protocol, u64 cat);
spinbit_session_t * get_session_from_key(spinbit_key_t * kv_in);
u32 create_session(sup_protocols_t p_type);

void update_quic_rtt_estimate(vlib_main_t * vm, quic_observer_t * session,
        f64 now, u16 src_port, u16 init_src_port, u8 measurement,
        u32 packet_number, u32 pkt_count);
bool basic_spinbit_estimate(vlib_main_t * vm, basic_spin_observer_t *observer,
        f64 now, u16 src_port, u16 init_src_port, bool spin);
bool pn_spinbit_estimate(vlib_main_t * vm, pn_spin_observer_t *observer,
        f64 now, u16 src_port, u16 init_src_port, bool spin, u32 packet_number);
bool status_estimate(vlib_main_t * vm, status_spin_observer_t *observer,
        f64 now, u16 src_port, u16 init_src_port, bool spin, u8 status);
bool vec_ne_zero_estimate(vlib_main_t * vm, status_spin_observer_t *observer,
      f64 now, u16 src_port, u16 init_src_port, bool spin, u8 status);
bool heuristic_estimate(vlib_main_t * vm, dyna_heur_spin_observer_t *observer,
        f64 now, u16 src_port, u16 init_src_port, bool spin);
void update_tcp_rtt_estimate(vlib_main_t * vm, tcp_observer_t * session,
        f64 now, u16 src_port, u16 init_src_port, u8 measurement, u32 tsval,
        u32 tsecr, u32 pkt_count, u32 seq_num);
bool ts_single_estimate(vlib_main_t * vm,
        timestamp_observer_single_RTT_t * observer,
        f64 now, u16 src_port, u16 init_src_port, u32 tsval, u32 tsecr);
bool ts_all_estimate(vlib_main_t * vm, timestamp_observer_all_RTT_t * observer,
        f64 now, u16 src_port, u16 init_src_port, u32 tsval, u32 tsecr);
int tcp_options_parse_mod (tcp_header_t * th, u32 * tsval, u32 * tsecr);
void update_plus_rtt_estimate(vlib_main_t * vm, plus_observer_t * session,
        f64 now, u16 src_port, u16 init_src_port, u32 psn,
        u32 pse, u64 cat, u32 pkt_count);
bool psn_single_estimate(vlib_main_t * vm, plus_single_observer_t * session,
        u16 src_port, u16 init_src_port, u32 psn, u32 pse, f64 now);
bool ip_nat_translation(ip4_header_t *ip0, u32 init_src_ip, u32 new_dst_ip);

void clean_session(u32 index);
void spinbit_printf (int flush, char *fmt, ...);
void tcp_printf (int flush, char *fmt, ...);
void test_printf (int flush, char *fmt, ...);
void plus_printf (int flush, char *fmt, ...);

/**
 * @brief get spinbit session for index
 */
always_inline spinbit_session_t * get_spinbit_session(u32 index) {
  if (pool_is_free_index (spinbit_main.session_pool, index))
    return 0;
  return pool_elt_at_index (spinbit_main.session_pool, index);
}

/**
 * @brief start a timer in the timer wheel
 */
always_inline void start_timer(spinbit_session_t * session, u64 interval) {
  session->timer = tw_timer_start_2t_1w_2048sl (&spinbit_main.tw,
                   session->index, 0, interval);
}

/**
 * @brief update the timer
 */
always_inline void update_timer(spinbit_session_t * session, u64 interval) {
  if(session->timer != ~0) {
    tw_timer_stop_2t_1w_2048sl (&spinbit_main.tw, session->timer);
  }
  session->timer = tw_timer_start_2t_1w_2048sl (&spinbit_main.tw,
                  session->index, 0, interval);
}

always_inline bool is_quic(u16 src_port, u16 dst_port) {
  return hash_get(spinbit_main.hash_quic_ports, src_port)
          || hash_get(spinbit_main.hash_quic_ports, dst_port);
}

always_inline void get_new_dst(u32 *new_dst_ip, u16 src_port) {
  uword* temp_ip = hash_get(spinbit_main.hash_server_ports_to_ips, src_port);
  if (temp_ip) {
    *new_dst_ip = *((u32 *) temp_ip);
    return;
  }
  *new_dst_ip = 0;
  return;
}

always_inline bool comes_after_u32(u32 now, u32 old) {
  i64 ret = (now - old) % MAX_PSN;
  if (ret < 0) {
    ret += MAX_PSN;
  }
  return ret < MAX_SKIP;
}

/**
 * @brief expire timers
 */
always_inline void expire_timers(f64 now) {
  tw_timer_expire_timers_2t_1w_2048sl (&spinbit_main.tw, now);
}

#define SPINBIT_PLUGIN_BUILD_VER "0.1"

#endif /* __included_spinbit_h__ */
