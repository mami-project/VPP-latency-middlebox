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
#include <quic/quic.h>

/* Register the quic node */
vlib_node_registration_t quic_node;

/* Used to display QUIC packets in the packet trace */
/* Only for short headers at the moment */
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
} quic_trace_t;

/* packet trace format function */
static u8 * format_quic_trace (u8 * s, va_list * args)
{
  /* Ignore two first arguments */
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  
  quic_trace_t * t = va_arg (*args, quic_trace_t *);
  
  /* Show QUIC packet */
  s = format (s, "QUIC packet: ID: %lu, packet number: %u\n", t->id, t->number);
  const char * stateNames[] = {"ACTIVE", "ERROR"};
  s = format (s, "  Current state: %s, C: %u, K: %u, type: %u\n",
                  stateNames[t->state], t->id_bit ? 1 : 0,
                  t->key_bit ? 1 : 0, t->type);
  s = format (s, "  Measurement byte: spin 2: %u, spin 1: %u, valid: %u, block: %u",
                  t->spin_2 ? 1 : 0, t->spin_1 ? 1 : 0, t->valid ? 1 : 0,
                  t->block ? 1 : 0);
  return s;
}

/* Current implementation does not drop any packets */
#define foreach_quic_error \
_(TEMP, "Currently not used")

typedef enum {
#define _(sym,str) QUIC_ERROR_##sym,
  foreach_quic_error
#undef _
  QUIC_N_ERROR,
} quic_error_t;


static char * quic_error_strings[] = {
#define _(sym,string) string,
  foreach_quic_error
#undef _
};

/* Header sizes in bytes */
#define SIZE_ETHERNET 14
#define SIZE_IP4 20
#define SIZE_UDP 8

/* 8 bit type, 8 bit packet number, 8 bit measurement byte*/
#define SIZE_QUIC_MIN 3

#define IS_LONG 0x80
#define HAS_ID 0x40
#define KEY_FLAG 0x20
#define QUIC_TYPE 0x1F
#define SIZE_TYPE 1
/* Only true for current minq implementation (IETF draft 05)
 * Newest IETF draft (08):
 * 8:  0x1F
 * 16: 0x1E
 * 32: 0x1D */
#define P_NUMBER_8 0x01
#define P_NUMBER_16 0x02
#define P_NUMBER_32 0x03

#define SIZE_NUMBER_8 1
#define SIZE_NUMBER_16 2
#define SIZE_NUMBER_32 4

#define SIZE_ID 8
#define SIZE_VERSION 4
#define SIZE_QUIC_SPIN 1

/* Timeout values (in 100ms) */
#define TIMEOUT 50

/* We run before ethernet_input node */
/* TODO: change if either pcap file is adapted
 * or new traces are generated */
typedef enum {
  ETHERNET_INPUT,
  QUIC_N_NEXT,
} quic_next_t;

/**
 * @brief Main loop function
 * */
static uword
quic_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame) {
  u32 n_left_from, * from, * to_next;
  quic_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0) {

    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index,
		to_next, n_left_to_next);

    /* Single loop */
    while (n_left_from > 0 && n_left_to_next > 0) {    
      /* Advance timer wheel */
      /* f64 start_t = vlib_time_now (vm); */
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
      
      /* Currently, most packets should be QUIC packets */
      /* TODO: adapt to new position once the node is moved 
       * E.g. ETHERNET movement is no longer needed */
      if (PREDICT_TRUE(b0->current_length >=
                              SIZE_ETHERNET + SIZE_IP4 + SIZE_UDP + SIZE_QUIC_MIN)) {
        vlib_buffer_advance (b0, SIZE_ETHERNET);
        total_advance += SIZE_ETHERNET;

      /* Get IP4 header */
        ip4_header_t *ip0 = vlib_buffer_get_current(b0);
        vlib_buffer_advance (b0, SIZE_IP4);
        total_advance += SIZE_IP4;

        /* Get UDP header */
        udp_header_t *udp0 = vlib_buffer_get_current(b0);
        vlib_buffer_advance (b0, SIZE_UDP);
        total_advance += SIZE_UDP;

        /* QUIC "detection", see if either endpoint is on the QUIC_PORT */
        if (PREDICT_TRUE(clib_net_to_host_u16(udp0->src_port) == QUIC_PORT ||
                                clib_net_to_host_u16(udp0->dst_port) == QUIC_PORT)) {
          /* Get QUIC header */

          /* Could be problematic if id == 0. Is that even possible? */
          u64 connection_id;
          u32 packet_number, CLIB_UNUSED(quic_version);
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
            quic_version = clib_net_to_host_u32(*temp_version);
            vlib_buffer_advance(b0, SIZE_VERSION);
            total_advance += SIZE_VERSION;

          /* SHORT HEADER */
          } else {
            vlib_buffer_advance (b0, SIZE_TYPE);
            total_advance += SIZE_TYPE;

            /* No quic version in the short header */
            quic_version = 0;

            /* Get connection ID */
            connection_id = 0;
            /* Only true for current minq implementation (IETF draft 05)
            * For newest IETF draft (08) HAS_ID meaning is reversed */
            if (*type & HAS_ID && b0->current_length >= SIZE_ID) {
              u64 *temp_id = vlib_buffer_get_current(b0);
              connection_id = clib_net_to_host_u64(*temp_id);

              vlib_buffer_advance (b0, SIZE_ID);
              total_advance += SIZE_ID;
            }

            /* Get the packet number, grmblgrmblgrbml */
            switch (*type & QUIC_TYPE) {
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
          if (PREDICT_TRUE(b0->current_length >= SIZE_QUIC_SPIN)) {
            u8 *temp_m = vlib_buffer_get_current(b0);
            measurement = *temp_m;
          } else {
            goto skip_packet;
          }

          quic_key_t kv;
          make_key(&kv, &ip0->src_address, &ip0->dst_address, udp0->src_port,
                          udp0->dst_port, ip0->protocol);
            
          /* Try to get a session for the key */
          quic_session_t * session = get_session_from_key(&kv);

          /* Only for the first packet of a flow we do not have a matching session */
          if (PREDICT_FALSE(!session)) {
            /* Create new session */  
            u32 index = create_session();
            session = get_quic_session(index);

            /* Save key for reverse lookup */
            session->key = kv.as_u64;
             
            /* Initialize values */
            /* TODO: currently the only place the connection_id is saved
             * What if we did not have a connection_id in this packet? */
            session->id = connection_id;
            
            update_state(&kv, session->index);
            session->pkt_count = 0;
            
            start_timer(session, TIMEOUT);
          }

          /* Keep track of packets for each flow */
          session->pkt_count ++;
          session->updated_rtt = false;


          /* Do handshake RTT estimation */
          update_handshake_rtt(vm, session, vlib_time_now (vm),
                          clib_net_to_host_u16(udp0->src_port), *type);

          /* Do spinbit RTT estimation */
          update_rtt_estimate(vm, session, vlib_time_now (vm),
                          clib_net_to_host_u16(udp0->src_port), measurement,
                          packet_number); 

          /* Currently only ACTIVE and ERROR state
           * The timer is just used to free memory if flow is no longer observed */
          switch ((quic_state_t) session->state) {  
            case QUIC_STATE_ACTIVE:
              update_timer(session, TIMEOUT);
              break;

            case QUIC_STATE_ERROR:
              break;

            default:
              break;
          }
            
          /* If packet trace is active */
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            /* Set correct trace value */
            quic_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            t->state = session->state;
            t->id_bit = *type & HAS_ID;
            t->key_bit = *type & KEY_FLAG;
            t->type = *type & QUIC_TYPE; 
            t->id = connection_id;
            t->number = packet_number;
            t->spin_2 = measurement & TWO_BIT_SPIN;
            t->spin_1 = measurement & ONE_BIT_SPIN;
            t->valid = measurement & VALID_BIT;
            t->block = measurement & BLOCKING_BIT;
          }
        }

        /* Move buffer pointer back such that next node gets expected position */
skip_packet:
        vlib_buffer_advance (b0, -total_advance);

      }
      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
             to_next, n_left_to_next,
             bi0, next0);
      /* vlib_cli_output(vm, "Time in loop: %.*lfs", vlib_time_now (vm) - start_t, 9); */
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  
  return frame->n_vectors;
}


VLIB_REGISTER_NODE (quic_node) = {
  .function = quic_node_fn,
  .name = "quic",
  .vector_size = sizeof (u32),
  .format_trace = format_quic_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(quic_error_strings),
  .error_strings = quic_error_strings,

  .n_next_nodes = QUIC_N_NEXT,

  /* Next node is the ethernet-input node */
  /* TODO: change if either pcap file is adapted
   * or new traces are generated */
  .next_nodes = {
        [ETHERNET_INPUT] = "ethernet-input",
  },
};
