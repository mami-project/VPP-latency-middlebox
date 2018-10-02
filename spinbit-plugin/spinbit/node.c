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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/session/stream_session.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <spinbit/spinbit.h>
#include <spinbit/plus_packet.h>

/* Register the spinbit node */
vlib_node_registration_t spinbit_node;

/* Used to display SPINBIT packets in the packet trace */
typedef struct {
  u8 state;
  bool id_bit;
  bool key_bit;
  u8 type;
  u64 id;
  u32 number;
  bool spin_2;
  bool spin_1;
  bool valid;
  bool block;
} spinbit_trace_t;

/* packet trace format function */
static u8 * format_spinbit_trace (u8 * s, va_list * args) {
  /* Ignore two first arguments */
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  
  spinbit_trace_t * t = va_arg (*args, spinbit_trace_t *);
  
  /* Show SPINBIT packet */
  s = format (s, "SPINBIT packet: ID: %lu, packet number: %u\n",
              t->id, t->number);
  const char * stateNames[] = {"ACTIVE", "ERROR"};
  s = format (s, "  Current state: %s, C: %u, K: %u, type: %u\n",
              stateNames[t->state], t->id_bit ? 1 : 0,
              t->key_bit ? 1 : 0, t->type);
  s = format (s, "  Measurement byte: spin 2: %u, spin 1: %u, valid: %u, block: %u",
              t->spin_2 ? 1 : 0, t->spin_1 ? 1 : 0,
              t->valid ? 1 : 0, t->block ? 1 : 0);
  return s;
}

/* Current implementation does not drop any packets */
#define foreach_spinbit_error \
_(TEMP, "Currently not used")

typedef enum {
#define _(sym,str) SPINBIT_ERROR_##sym,
  foreach_spinbit_error
#undef _
  SPINBIT_N_ERROR,
} spinbit_error_t;


static char * spinbit_error_strings[] = {
#define _(sym,string) string,
  foreach_spinbit_error
#undef _
};

/* Protocols */
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

/* Header sizes in bytes */
#define SIZE_IP4 20
#define SIZE_UDP 8
#define SIZE_TCP 20
#define SIZE_QUIC_MIN 3
#define SIZE_PLUS 20
#define SIZE_PLUS_EXT_HELLO 3

/* QUIC bits */
#define IS_LONG 0x80
#define HAS_ID 0x40
#define KEY_FLAG 0x20
#define SPINBIT_TYPE 0x1F
#define SIZE_TYPE 1

/* Only true for current pinq implementation (IETF draft 05)
   https://github.com/pietdevaere/minq */
#define P_NUMBER_8 0x01
#define P_NUMBER_16 0x02
#define P_NUMBER_32 0x03

#define SIZE_NUMBER_8 1
#define SIZE_NUMBER_16 2
#define SIZE_NUMBER_32 4

#define SIZE_ID 8
#define SIZE_VERSION 4
#define SIZE_SPINBIT_SPIN 1

/* For reserved bits
 * spin in data_offset_and_reserved 00001110 */
#define TCP_SPINBIT_MASK 0x0E
#define TCP_SPINBIT_SHIFT 1

/* Timeout values (in 100ms) */
#define TIMEOUT 300

/* PLUS timeouts */
#define TO_IDLE 100
#define TO_ASSOCIATED 30
#define TO_STOP 20

/* We run before IP4_lookup node */
typedef enum {
  IP4_LOOKUP,
  SPINBIT_N_NEXT,
} spinbit_next_t;

/**
 * @brief Main loop function
 * */
static uword
spinbit_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                 vlib_frame_t * frame) {
  
  u32 n_left_from, * from, * to_next;
  spinbit_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0) {

    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index,
                         to_next, n_left_to_next);

    /* Currently, only single loop implemented 
     * TODO: implement double loop */
    while (n_left_from > 0 && n_left_to_next > 0) {

      /* Advance timer wheel */
      expire_timers(vlib_time_now (vm));

      u32 bi0;
      vlib_buffer_t * b0;
      u32 next0 = 0;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      /* Keeps track of all the buffer movement */
      u8 total_advance = 0;
      bool make_measurement = true;

      /* Contains TCP, QUIC or PLUS session */
      spinbit_session_t * session = NULL;

      if (PREDICT_TRUE(b0->current_length >= SIZE_IP4)) {

        /* Get IP4 header */
        // TODO: add support for IP options and IPv6 headers
        ip4_header_t *ip0 = vlib_buffer_get_current(b0);
        vlib_buffer_advance (b0, SIZE_IP4);
        total_advance += SIZE_IP4;

        /* Ignore IPv6 packets */
        if (PREDICT_FALSE((ip0->ip_version_and_header_length & 0xF0) == 0x60)) {
          goto skip_packet;
        }

        if (ip0->protocol == UDP_PROTOCOL && b0->current_length >= SIZE_UDP) {
          /* Get UDP header */
          udp_header_t *udp0 = vlib_buffer_get_current(b0);
          vlib_buffer_advance (b0, SIZE_UDP);
          total_advance += SIZE_UDP;

          /* QUIC "detection", see if either endpoint is on the QUIC_PORT */
          if (is_quic(udp0->src_port, udp0->dst_port) &&
              b0->current_length >= SIZE_QUIC_MIN) {
              
            /* Get QUIC header */
            u64 connection_id;
            u32 packet_number, CLIB_UNUSED(spinbit_version);
            u8 *type = vlib_buffer_get_current(b0);

            /* LONG HEADER */
            /* We expect most packets to have the short header */
            if (PREDICT_FALSE(*type & IS_LONG)) {
              vlib_buffer_advance(b0, SIZE_TYPE);
              total_advance += SIZE_TYPE;

              /* Get connection ID */
              u64 *temp_id = vlib_buffer_get_current(b0);
              connection_id = clib_net_to_host_u64(*temp_id);
              vlib_buffer_advance(b0, SIZE_ID);
              total_advance += SIZE_ID;

              /* Get packet number PN */
              u32* temp_pn = vlib_buffer_get_current(b0);
              packet_number = clib_net_to_host_u32(*temp_pn);
              vlib_buffer_advance(b0, SIZE_NUMBER_32);
              total_advance += SIZE_NUMBER_32;

              /* Get version */
              u32 *temp_version = vlib_buffer_get_current(b0);
              spinbit_version = clib_net_to_host_u32(*temp_version);
              vlib_buffer_advance(b0, SIZE_VERSION);
              total_advance += SIZE_VERSION;

            /* SHORT HEADER */
            } else {
              vlib_buffer_advance (b0, SIZE_TYPE);
              total_advance += SIZE_TYPE;

              /* No spinbit version in the short header */
              spinbit_version = 0;

              /* Get connection ID */
              connection_id = 0;
              
              /* Only true for current pinq implementation (IETF draft 05)
               * For newest IETF draft (08) HAS_ID meaning is reversed */
              if (*type & HAS_ID && b0->current_length >= SIZE_ID) {
                u64 *temp_id = vlib_buffer_get_current(b0);
                connection_id = clib_net_to_host_u64(*temp_id);

                vlib_buffer_advance (b0, SIZE_ID);
                total_advance += SIZE_ID;
              }

              /* Get the packet number */
              switch (*type & SPINBIT_TYPE) {
                case P_NUMBER_8:
                  if (PREDICT_TRUE(b0->current_length >= SIZE_NUMBER_8)) {
                    u8 *temp_8 = vlib_buffer_get_current(b0);
                    packet_number = *temp_8;
                    vlib_buffer_advance (b0, SIZE_NUMBER_8);
                    total_advance += SIZE_NUMBER_8;
                  } else {
                    goto skip_packet;
                  }
                  break;

                case P_NUMBER_16:
                  if (PREDICT_TRUE(b0->current_length >= SIZE_NUMBER_16)) {
                    u16 *temp_16 = vlib_buffer_get_current(b0);
                    packet_number = clib_net_to_host_u16(*temp_16);
                    vlib_buffer_advance (b0, SIZE_NUMBER_16);
                    total_advance += SIZE_NUMBER_16;
                  } else {
                    goto skip_packet;
                  }
                  break;

                case P_NUMBER_32:
                  if (PREDICT_TRUE(b0->current_length >= SIZE_NUMBER_32)) {
                    u32 *temp_32 = vlib_buffer_get_current(b0);
                    packet_number = clib_net_to_host_u32(*temp_32);
                    vlib_buffer_advance (b0, SIZE_NUMBER_32);
                    total_advance += SIZE_NUMBER_32;
                  } else {
                    goto skip_packet;
                  }
                  break;

                default:
                  goto skip_packet;
              }
            }

            u8 measurement;
            if (PREDICT_TRUE(b0->current_length >= SIZE_SPINBIT_SPIN)) {
              u8 *temp_m = vlib_buffer_get_current(b0);
              measurement = *temp_m;
            } else {
              goto skip_packet;
            }

            spinbit_key_t kv;

            make_key(&kv, ip0->src_address.as_u32, ip0->dst_address.as_u32, udp0->src_port,
                     udp0->dst_port, ip0->protocol);

            /* Try to get a session for the key */
            session = get_session_from_key(&kv);

            /* Only for the first packet of a flow we do not have a matching session */
            if (PREDICT_FALSE(!session)) {
              
              /* Only consider flows for known dst (dst port) */
              u32 new_dst_ip;
              get_new_dst(&new_dst_ip, udp0->dst_port);
              if (!new_dst_ip) {
                goto skip_packet;
              }

              /* Create new session */
              u32 index = create_session(P_QUIC);
              session = get_spinbit_session(index);

              /* Save key for reverse lookup */
              session->key = kv.as_u64;

              /* Initialize values */
              session->quic->id = connection_id;
              session->init_src_port = udp0->src_port;
              session->init_src_ip = ip0->src_address.as_u32;
              session->new_dst_ip = new_dst_ip;
              
              update_state(&kv, session->index);

              /* Packets in reverse direction will get same session
               * Necessary because we rewrite the IPs */
              make_key(&kv, 0, new_dst_ip, udp0->src_port,
                       udp0->dst_port, ip0->protocol);
              update_state(&kv, session->index);
              
              session->key_reverse = kv.as_u64;
              
              session->pkt_count = 0;

              start_timer(session, TIMEOUT);
            }

            if (!ip_nat_translation(ip0, session->init_src_ip, session->new_dst_ip)) {
              goto skip_packet;
            }
            
            /* Packets to server */
            //if (ip0->src_address.as_u32 == session->init_src_ip) {
            //  ip0->src_address.as_u32 = IP_MB;
            //  ip0->dst_address.as_u32 = session->new_dst_ip;
            //} else {
              /* Packets to client */
            //  if (ip0->src_address.as_u32 == session->new_dst_ip) {
            //    ip0->src_address.as_u32 = IP_MB;
            //    ip0->dst_address.as_u32 = session->init_src_ip;
            //  } else {
            //    goto skip_packet;
            //  }
            //}

            /* Update UDP and IP checksum */
            udp0->checksum = 0;
            udp0->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip0); 
            ip0->checksum = ip4_header_checksum (ip0);

            /* Keep track of packets for each flow */
            session->pkt_count ++;

            /* Do spinbit RTT estimation */
            update_quic_rtt_estimate(vm, session->quic, vlib_time_now (vm),
                          udp0->src_port, session->init_src_port, measurement,
                          packet_number, session->pkt_count);
            
            /* Currently only ACTIVE and ERROR state
             * The timer is just used to free memory if flow is no longer observed */
            switch (session->state) {  
              case SPINBIT_STATE_ACTIVE:
                update_timer(session, TIMEOUT);
              break;

              case SPINBIT_STATE_ERROR:
              break;

              default:
              break;
            }
          } else {
            if (b0->current_length >= SIZE_PLUS) {
              plus_header_t *plus0 = vlib_buffer_get_current(b0);
              vlib_buffer_advance (b0, SIZE_PLUS);
              total_advance += SIZE_PLUS;
              if (PREDICT_TRUE((plus0->magic_and_flags & MAGIC_MASK) == MAGIC)) {
                spinbit_key_t kv;
                make_plus_key(&kv, ip0->src_address.as_u32, ip0->dst_address.as_u32,
                                udp0->src_port, udp0->dst_port, ip0->protocol,
                                plus0->CAT);
                
                session = get_session_from_key(&kv);

                if (PREDICT_FALSE(!session)) {

                  /* Only consider flows for known dst (dst port) */
                  u32 new_dst_ip;
                  get_new_dst(&new_dst_ip, udp0->dst_port);
                  if (!new_dst_ip) {
                    goto skip_packet;
                  }

                  /* Create new session */
                  u32 index = create_session(P_PLUS);
                  session = get_spinbit_session(index);

                  /* Save key for reverse lookup */
                  session->key = kv.as_u64;
                  session->plus->cat = plus0->CAT;

                  /* Initialize values */
                  session->init_src_port = udp0->src_port;
                  session->init_src_ip = ip0->src_address.as_u32;
                  session->new_dst_ip = new_dst_ip;
                  update_state(&kv, session->index);

                  /* Packets in reverse direction will get same session
                   * Necessary because we rewrite the IPs */
                  make_plus_key(&kv, 0, new_dst_ip, udp0->src_port,
                           udp0->dst_port, ip0->protocol,
                           plus0->CAT);

                  update_state(&kv, session->index);
                  
                  session->key_reverse = kv.as_u64;
                  
                  session->pkt_count = 0;

                  start_timer(session, TIMEOUT);
                }
 
                if (!ip_nat_translation(ip0, session->init_src_ip, session->new_dst_ip)) {
                  goto skip_packet;
                }

                /* Packets to server */
                //if (ip0->src_address.as_u32 == session->init_src_ip) {
                //  ip0->src_address.as_u32 = IP_MB;
                //  ip0->dst_address.as_u32 = session->new_dst_ip;
                //} else {
                  /* Packets to client */
                //  if (ip0->src_address.as_u32 == session->new_dst_ip) {
                //    ip0->src_address.as_u32 = IP_MB;
                //    ip0->dst_address.as_u32 = session->init_src_ip;
                //  } else {
                //    goto skip_packet;
                //  }
                //}

                /* Keep track of packets for each flow */
                session->pkt_count ++; 

                /* Do spinbit RTT estimation */
                update_plus_rtt_estimate(vm, session->plus, vlib_time_now (vm),
                              udp0->src_port, session->init_src_port,
                              clib_net_to_host_u32(plus0->PSN),
                              clib_net_to_host_u32(plus0->PSE),
                              clib_net_to_host_u64(plus0->CAT),
                              session->pkt_count);

                /* TODO: move to separate function/node */
                /* Handle extended header */
                plus_ext_hop_c_h_t *plus_ext_hop_c0;
                
                /* Enough space for extended header */
                if ((plus0->magic_and_flags & EXTENDED) && b0->current_length
                     >= SIZE_PLUS + SIZE_PLUS_EXT_HELLO) {
                  plus_ext_hop_c0 = vlib_buffer_get_current(b0);
                
                  u8 ii = plus_ext_hop_c0->PCF_len_and_II & 0x03;
                  /* "Hop count" header */
                  if (plus_ext_hop_c0->PCF_type == 1 && ii == 0) {
                    plus_ext_hop_c0->PCF_hop_c += 1;
                  }
                }

                /* Moved to the end, in case we have to change an extended PLUS header */
                udp0->checksum = 0;
                udp0->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip0); 
                ip0->checksum = ip4_header_checksum (ip0);
                
                switch (session->state) {  
                  case SPINBIT_STATE_P_ZERO:
                    session->state = SPINBIT_STATE_P_UNIFLOW;
                    start_timer(session, TO_IDLE);
                    /* Save direction for future state transitions */
                    session->init_src_ip = ip0->src_address.as_u32;
                  break;

                  case SPINBIT_STATE_P_UNIFLOW:
                    update_timer(session, TO_IDLE);
                    
                    /* Packet observation in other direction */
                    if (session->init_src_ip != ip0->src_address.as_u32) {
                      session->state = SPINBIT_STATE_P_ASSOCIATING;
                      session->plus->psn_associating = clib_net_to_host_u32(plus0->PSN);
                    }
                    break;

                  case SPINBIT_STATE_P_ASSOCIATING:
                    update_timer(session, TO_IDLE);
                    
                    /* Confirmation */
                    if (session->init_src_ip == ip0->src_address.as_u32
                                      && comes_after_u32(
                                            clib_net_to_host_u32(plus0->PSE),
                                            session->plus->psn_associating)) {
                      session->state = SPINBIT_STATE_P_ASSOCIATED;
                    }
                    break;

                  case SPINBIT_STATE_P_ASSOCIATED:
                    update_timer(session, TO_ASSOCIATED);

                    /* Unlikely that the flow ends */
                    if (PREDICT_FALSE(plus0->magic_and_flags & STOP)) {
                      session->state = SPINBIT_STATE_P_STOPWAIT;
                      session->init_src_ip = ip0->src_address.as_u32;
                      session->plus->psn_stopwait = clib_net_to_host_u32(plus0->PSN);
                    }
                    break;

                  case SPINBIT_STATE_P_STOPWAIT:
                    update_timer(session, TO_ASSOCIATED);

                    /* Stop bit in other direction and matching PSE value */
                    if (plus0->magic_and_flags & STOP && session->init_src_ip !=
                             ip0->src_address.as_u32 && session->plus->psn_stopwait ==
                             clib_net_to_host_u32(plus0->PSE)) {
                      /* Timer is not reset */
                      update_timer(session, TO_STOP);
                      session->state = SPINBIT_STATE_P_STOPPING;
                    }
                    break;
                    
                  case SPINBIT_STATE_P_STOPPING:
                    break;
                    
                  default:
                    break;
                }
              }
            }
          }
        } else {
          if (ip0->protocol == TCP_PROTOCOL && b0->current_length >= SIZE_TCP) {
                
            /* Get TCP header */
            tcp_header_t *tcp0 = vlib_buffer_get_current(b0);
            vlib_buffer_advance (b0, SIZE_TCP);
            total_advance += SIZE_TCP;

            /* For timestamp values */
            u32 tsval = 0;
            u32 tsecr = 0;

            int parse_ret = tcp_options_parse_mod(tcp0, &tsval, &tsecr);

            if (parse_ret) {
              goto skip_packet;
            }

            /* Ignore SYN ACK packets, no VEC  */
            if (PREDICT_FALSE(tcp_syn(tcp0) && tcp_ack(tcp0))) {
              make_measurement = false;             
            }


            /* VEC data from reserved space y*/
            u8 measurement = (tcp0->data_offset_and_reserved & TCP_SPINBIT_MASK)
                    >> TCP_SPINBIT_SHIFT;

            //tcp_printf(1, "VEC: %d\n", measurement);

            spinbit_key_t kv;
            make_key(&kv, ip0->src_address.as_u32, ip0->dst_address.as_u32,
                     tcp0->src_port, tcp0->dst_port, ip0->protocol);

            session = get_session_from_key(&kv);

            /* Only first packet in a flow should not have a session */
            if (PREDICT_FALSE(!session)) {

              /* Only consider flows for known dst (dst port) */
              u32 new_dst_ip;
              get_new_dst(&new_dst_ip, tcp0->dst_port);
              if (!new_dst_ip) {
                goto skip_packet;
              }

              /* Create new session */
              u32 index = create_session(P_TCP);
              session = get_spinbit_session(index);

              /* Save key for reverse lookup */
              session->key = kv.as_u64;

              /* Initialize values */
              session->init_src_port = tcp0->src_port;
              session->init_src_ip = ip0->src_address.as_u32;
              session->new_dst_ip = new_dst_ip;
              update_state(&kv, session->index);

              /* Packets in reverse direction will get same session
               * Necessary because we rewrite the IPs */
              make_key(&kv, 0, new_dst_ip, tcp0->src_port,
                       tcp0->dst_port, ip0->protocol);
              update_state(&kv, session->index);
              
              session->key_reverse = kv.as_u64;
              
              session->pkt_count = 0;

              start_timer(session, TIMEOUT);
            }

            if (!ip_nat_translation(ip0, session->init_src_ip, session->new_dst_ip)) {
              goto skip_packet;
            }

            /* Packets to server */
            //if (ip0->src_address.as_u32 == session->init_src_ip) {
            //  ip0->src_address.as_u32 = IP_MB;
            //  ip0->dst_address.as_u32 = session->new_dst_ip;
            //} else {
              /* Packets to client */
            //  if (ip0->src_address.as_u32 == session->new_dst_ip) {
            //    ip0->src_address.as_u32 = IP_MB;
            //    ip0->dst_address.as_u32 = session->init_src_ip;
            //  } else {
            //    goto skip_packet;
            //  }
            //}

            /* Update TCP and IP checksum*/
            tcp0->checksum = 0;
            tcp0->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip0); 
            ip0->checksum = ip4_header_checksum (ip0);

            session->pkt_count ++;

            /* Do timestamp and spinbit RTT estimation */
            if (PREDICT_TRUE(make_measurement)) {
              update_tcp_rtt_estimate(vm, session->tcp, vlib_time_now (vm),
                        tcp0->src_port, session->init_src_port, measurement,
                        tsval, tsecr, session->pkt_count,
                        clib_net_to_host_u32(tcp0->seq_number));
            }
            /* Currently only ACTIVE and ERROR state
             * The timer is just used to free memory if flow is no longer observed */
            switch (session->state) {  
              case SPINBIT_STATE_ACTIVE:
                update_timer(session, TIMEOUT);
              break;

              case SPINBIT_STATE_ERROR:
              break;

              default:
              break;
            }
          }
        
          // TODO: adapt! 
          /* If packet trace is active */
          // if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
          //     && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            
            /* Set correct trace value */
            //spinbit_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            //t->state = session->state;
            //t->id_bit = *type & HAS_ID;
            //t->key_bit = *type & KEY_FLAG;
            //t->type = *type & SPINBIT_TYPE; 
            //t->id = connection_id;
            //t->number = packet_number;
            //t->spin_2 = measurement & TWO_BIT_SPIN;
            //t->spin_1 = measurement & ONE_BIT_SPIN;
            //t->valid = measurement & VALID_BIT;
            //t->block = measurement & BLOCKING_BIT;
          //}
        }

        /* Move buffer pointer back such that next node gets expected position */
skip_packet:
        vlib_buffer_advance (b0, -total_advance);
      }
      
      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                       n_left_to_next, bi0, next0);
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  return frame->n_vectors;
}


VLIB_REGISTER_NODE (spinbit_node) = {
  .function = spinbit_node_fn,
  .name = "spinbit",
  .vector_size = sizeof (u32),
  .format_trace = format_spinbit_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(spinbit_error_strings),
  .error_strings = spinbit_error_strings,

  .n_next_nodes = SPINBIT_N_NEXT,

  /* Next node is the ethernet-input node */
  .next_nodes = {
    [IP4_LOOKUP] = "ip4-lookup", //"ethernet-input",
  },
};
