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
#include <plus/plus.h>
#include <plus/plus_packet.h>

/* Register the plus node */
vlib_node_registration_t plus_node;

/* Used to display PLUS packets in the packet trace */
typedef struct {
  u64 cat;
  u32 psn;
  u32 pse;
  u8 state;
  u32 stop;
  u32 extended;
  u8 pcf_type;
  u8 pcf_len;
  u8 pcf_ii;
  u8 pcf_value;
} plus_trace_t;

/* packet trace format function */
static u8 * format_plus_trace (u8 * s, va_list * args)
{
  /* Ignore two first arguments */
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  
  plus_trace_t * t = va_arg (*args, plus_trace_t *);
  
  /* Show PLUS packet */
  s = format (s, "PLUS packet: CAT: %lu, PSN: %u, PSE: %u\n", t->cat, t->psn, t->pse);
  const char * stateNames[] = {"ZERO", "UNIFLOW", "ASSOCIATING", "ASSOCIATED",
                               "STOPWAIT", "STOPPING", "ERROR"};
  s = format (s, "  Current state: %s, stop bit: %u, extended bit: %u\n",
                  stateNames[t->state], t->stop ? 1 : 0, t->extended ? 1 : 0);
  if (t->pcf_type)
  s = format (s, "  PCF type: %u, PCF len: %u, PCF II: %u, PCF hop count value: %u",
                  t->pcf_type, t->pcf_len, t->pcf_ii, t->pcf_value);
  return s;
}

/* Current implementation does not drop any packets */
#define foreach_plus_error \
_(TEMP, "Currently not used")

typedef enum {
#define _(sym,str) PLUS_ERROR_##sym,
  foreach_plus_error
#undef _
  PLUS_N_ERROR,
} plus_error_t;


static char * plus_error_strings[] = {
#define _(sym,string) string,
  foreach_plus_error
#undef _
};

/* Header sizes in bytes */
#define SIZE_IP4 20
#define SIZE_UDP 8
#define SIZE_PLUS 20
#define SIZE_PLUS_EXT_HELLO 3

/* Timeout values (in 100ms) */
#define TO_IDLE 100
#define TO_ASSOCIATED 30
#define TO_STOP 20

/* We run before ip4-lookup node */
typedef enum {
  IP4_LOOKUP,
  PLUS_N_NEXT,
} plus_next_t;

/**
 * @brief Main loop function
 * */
static uword
plus_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame) {
  u32 n_left_from, * from, * to_next;
  plus_next_t next_index;

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
      
      /* Currently, most packets should be PLUS packets */
      if (PREDICT_TRUE(b0->current_length >= SIZE_IP4 + SIZE_UDP + SIZE_PLUS)) {
        /* Get IP4 header */
        ip4_header_t *ip0 = vlib_buffer_get_current(b0);

        vlib_buffer_advance (b0, SIZE_IP4);
        total_advance += SIZE_IP4;

        /* Get UDP header */
        udp_header_t *udp0 = vlib_buffer_get_current(b0);

        vlib_buffer_advance (b0, SIZE_UDP);
        total_advance += SIZE_UDP;

        /* Get PLUS header */
        plus_header_t *plus0 = vlib_buffer_get_current(b0);

        /* Most packets should have valid magic number.
           Masks and so on defined in plus.h */    
        if (PREDICT_TRUE((plus0->magic_and_flags & MAGIC_MASK) == MAGIC)) {  
          /* Stores the corresponding key */
          plus_key_t kv;
          make_key(&kv, &ip0->src_address, &ip0->dst_address, udp0->src_port,
                          udp0->dst_port, ip0->protocol , plus0->CAT);
            
          /* Try to get a session for the key */
          plus_session_t * session = get_session_from_key(&kv);
            
          /* Only for the first packet of a flow we do not have a matching session */
          if (PREDICT_FALSE(!session)) {
            /* Create new session */  
            u32 index = create_session(plus0->CAT);
            session = get_plus_session(index);

            /* Save key for reverse lookup */
            session->key[0] = kv.as_u64[0];
            session->key[1] = kv.as_u64[1];
             
            /* Initialize values */ 
            session->psn_src = plus0->PSN;
            session->psn_dst = 0;
            session->src = ip0->src_address.as_u32;
            update_state(&kv, session->index);
            session->pkt_count = 0;
            session->time_src = 0;
            session->time_dst = 0;
          }

          /* Keep track of packets for each flow */
          session->pkt_count ++;
           
          u32 src_ip = ip0->src_address.as_u32;
          u32 psn = clib_net_to_host_u32(plus0->PSN);
          u32 pse = clib_net_to_host_u32(plus0->PSE);

          /* RTT estimation update */
          update_rtt_estimate(session, vlib_time_now (vm), src_ip, psn, pse); 

          /* State update 
           * Delayed/reordered packets do currently reset the timers.
           * */
          switch ((plus_state_t) session->state) {  
            case PLUS_STATE_ZERO:
              session->state = PLUS_STATE_UNIFLOW;
              start_timer(session, TO_IDLE);
              /* Save direction for future state transitions */
              session->src_ip_dir = src_ip;
              break;

            case PLUS_STATE_UNIFLOW:
              update_timer(session, TO_IDLE);
              
              /* Packet observation in other direction */
              if (session->src_ip_dir != src_ip)
              {
                session->state = PLUS_STATE_ASSOCIATING;
                session->psn_associating = psn;
              }
              break;

            case PLUS_STATE_ASSOCIATING:
              update_timer(session, TO_IDLE);
              
              /* Confirmation */
              if (session->src_ip_dir == src_ip && comes_after_u32(
                                      pse, session->psn_associating)) {
                session->state = PLUS_STATE_ASSOCIATED;
              }
              break;

            case PLUS_STATE_ASSOCIATED:
              update_timer(session, TO_ASSOCIATED);

              /* Unlikely that the flow ends */
              if (PREDICT_FALSE(plus0->magic_and_flags & STOP)) {
                session->state = PLUS_STATE_STOPWAIT;
                session->src_ip_dir = src_ip;
                session->psn_stopwait = psn;
              }
              break;

            case PLUS_STATE_STOPWAIT:
              update_timer(session, TO_ASSOCIATED);

              /* Stop bit in other direction and matching PSE value */
              if (plus0->magic_and_flags & STOP && session->src_ip_dir != src_ip
                  && session->psn_stopwait == pse) {
                /* Timer is not reset */
                update_timer(session, TO_STOP);
                session->state = PLUS_STATE_STOPPING;
              }
              break;
              
            case PLUS_STATE_STOPPING:
              break;
              
            default:
              break;
          }
            
          /* Handle extended header */
          plus_ext_hop_c_h_t *plus_ext_hop_c0;
          bool ext_hop_c = false;

          /* Enough space for extended header */
          if ((plus0->magic_and_flags & EXTENDED) && b0->current_length
               >= SIZE_PLUS + SIZE_PLUS_EXT_HELLO) {
            vlib_buffer_advance (b0, SIZE_PLUS);
            total_advance += SIZE_PLUS;
            plus_ext_hop_c0 = vlib_buffer_get_current(b0);
          
            u8 ii = plus_ext_hop_c0->PCF_len_and_II & 0x03;
            /* "Hop count" header */
            if (plus_ext_hop_c0->PCF_type == 1 && ii == 0) {
              plus_ext_hop_c0->PCF_hop_c += 1;
              ext_hop_c = true;
            }
          }

          /* If packet trace is active */
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            /* Set correct trace value */
            plus_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            t->cat = clib_net_to_host_u64(plus0->CAT);
            t->psn = psn;
            t->pse = pse;
            t->stop = plus0->magic_and_flags & STOP;
            t->extended = plus0->magic_and_flags & EXTENDED;
            t->state = session->state;
            if (ext_hop_c) {
              t->pcf_type = plus_ext_hop_c0->PCF_type; 
              t->pcf_len = (plus_ext_hop_c0->PCF_len_and_II & 0xFC) >> 2;
              t->pcf_ii = plus_ext_hop_c0->PCF_len_and_II & 0x03;
              t->pcf_value = plus_ext_hop_c0->PCF_hop_c;
            } else {
              t->pcf_type = 0;
            }
          }
        }
      
        /* Move buffer pointer back such that ip4-lookup get expected position */
        vlib_buffer_advance (b0, -total_advance);
      }
      /* verify speculative enqueue, maybe switch current next frame */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
             to_next, n_left_to_next,
             bi0, next0);
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (plus_node) = {
  .function = plus_node_fn,
  .name = "plus",
  .vector_size = sizeof (u32),
  .format_trace = format_plus_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(plus_error_strings),
  .error_strings = plus_error_strings,

  .n_next_nodes = PLUS_N_NEXT,

  /* Next node is the ip4-lookup node */
  .next_nodes = {
        [IP4_LOOKUP] = "ip4-lookup",
  },
};
