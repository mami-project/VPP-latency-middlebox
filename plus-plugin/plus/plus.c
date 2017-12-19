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
/**
 * @file
 * @brief Plus plugin, plugin API / trace / CLI handling.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <plus/plus.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <plus/plus_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <plus/plus_all_api_h.h> 
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <plus/plus_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <plus/plus_all_api_h.h> 
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <plus/plus_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE pm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */
#define foreach_plus_plugin_api_msg                           \
_(PLUS_ENABLE_DISABLE, plus_enable_disable)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = PLUS_PLUGIN_BUILD_VER,
    .description = "PLUS middlebox VPP Plugin",
};
/* *INDENT-ON* */

/**
 * @brief Enable/disable the plugin. 
 *
 * Action function shared between message handler and debug CLI.
 */

int plus_enable_disable (plus_main_t * pm, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (pm->vnet_main->interface_main.sw_interfaces, 
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (pm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  
  vnet_feature_enable_disable ("ip4-unicast", "plus",
                               sw_if_index, enable_disable, 0, 0);
  return rv;
}

static clib_error_t *
plus_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  plus_main_t * pm = &plus_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;
    
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "disable"))
      enable_disable = 0;
    else if (unformat (input, "%U", unformat_vnet_sw_interface,
                       pm->vnet_main, &sw_if_index))
      ;
    else
      break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");
    
  rv = plus_enable_disable (pm, sw_if_index, enable_disable);

  switch(rv) {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return 
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "plus_enable_disable returned %d",
                              rv);
  }
  return 0;
}

/**
 * @brief format function (print each active flow)
 */
u8 * format_sessions(u8 *s, va_list *args) {
  plus_main_t * pm = &plus_main;
  const char * stateNames[] = {"ZERO", "UNIFLOW", "ASSOCIATING", "ASSOCIATED", "STOPWAIT", "STOPPING", "ERROR"};
  s = format(s, "Total flows: %u, total active flows: %u\n", pm->total_flows, pm->active_flows);
  plus_session_t * session;
  s = format(s, "=======================================================\n");
  /* Iterate through all pool entries */
  pool_foreach (session, pm->session_pool, ({
    s = format(s, "Flow CAT: %lu, observed packets: %u\n", clib_net_to_host_u64(session->cat), session->pkt_count);
    f64 rtt_estimation = session->rtt_src + session->rtt_dst;
    s = format(s, "Current state: %s, estimated RTT: %.*lfs\n", stateNames[session->state], rtt_estimation, 3);
    s = format(s, "=======================================================\n");
  }));
  return s;
}

static clib_error_t * plus_show_stats_fn(vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vl_print(vm, "%U", format_sessions);
  return 0;
}

/**
 * @brief CLI command to enable/disable the plus plugin.
 */
VLIB_CLI_COMMAND (sr_content_command, static) = {
  .path = "plus",
  .short_help = 
  "plus <interface-name> [disable]",
  .function = plus_enable_disable_command_fn,
};

/**
 * @brief CLI command to show all active flows
 */
VLIB_CLI_COMMAND (sr_content_command_stats, static) = {
  .path = "plus stats",
  .short_help = "Show PLUS middlebox stats",
  .function = plus_show_stats_fn,
};

/**
 * @brief PLUS API message handler.
 */
static void vl_api_plus_enable_disable_t_handler
(vl_api_plus_enable_disable_t * mp)
{
  vl_api_plus_enable_disable_reply_t * rmp;
  plus_main_t * pm = &plus_main;
  int rv;

  rv = plus_enable_disable (pm, ntohl(mp->sw_if_index), 
                                      (int) (mp->enable_disable));
  
  REPLY_MACRO(VL_API_PLUS_ENABLE_DISABLE_REPLY);
}

/**
 * @brief Set up the API message handling tables.
 */
static clib_error_t *
plus_plugin_api_hookup (vlib_main_t *vm)
{
  plus_main_t * pm = &plus_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + pm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_plus_plugin_api_msg;
#undef _

    return 0;
}

#define vl_msg_name_crc_list
#include <plus/plus_all_api_h.h>
#undef vl_msg_name_crc_list

static void 
setup_message_id_table (plus_main_t * pm, api_main_t *am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + pm->msg_id_base);
  foreach_vl_msg_name_crc_plus;
#undef _
}

/**
 *  @brief create the hash key
 */
void make_key(plus_key_t * kv, ip4_address_t * src_ip, ip4_address_t * dst_ip, u16 src_p, u16 dst_p, u8 protocol, u64 cat)
{
  kv->s_x_d_ip = src_ip->as_u32 ^ dst_ip->as_u32;
  kv->s_x_d_port = src_p ^ dst_p;
  kv->protocol = protocol;
  kv->cat = cat;
}

/**
 *  @brief get session pointer if corresponding key is known
 */
plus_session_t * get_session_from_key(plus_key_t * kv_in)
{
  BVT(clib_bihash_kv) kv, kv_return;
  plus_main_t *pm = &plus_main;
  BVT(clib_bihash) *bi_table;
  bi_table = &pm->plus_table;
  kv.key[0] = kv_in->as_u64[0];
  kv.key[1] = kv_in->as_u64[1];
  int rv = BV(clib_bihash_search) (bi_table, &kv, &kv_return);
  if (rv != 0) {
    /* Key does not exist */
    return 0;
  } else {
    return get_plus_session(kv_return.value);
  }
}

/**
 * @brief update RTT estimations.
 * TODO: Currently, serial number overflow is not supported
 */
void update_rtt_estimate(plus_session_t * session, f64 now, u32 src_address, u32 psn, u32 pse) {
  /* Decide direction */
  if (src_address == session->src) {
    /* Is a new packet */ 
    if (psn > session->psn_src) {
      session->psn_src = psn;
      session->time_src = now;
      if (pse >= session->psn_dst) {
        session->rtt_src = session->time_src - session->time_dst;
      }
    }
  } else if (psn > session->psn_dst) {
    session->psn_dst = psn;
    session->time_dst = now;
    if (pse >= session->psn_src) {
      session->rtt_dst = session->time_dst - session->time_src;
    }
  }
}

/**
 * @brief update the state of the session with the given key
 */
void update_state(plus_key_t * kv_in, uword new_state)
{
  BVT(clib_bihash_kv) kv;
  plus_main_t *pm = &plus_main;
  BVT(clib_bihash) *bi_table;
  bi_table = &pm->plus_table;
  kv.key[0] = kv_in->as_u64[0];
  kv.key[1] = kv_in->as_u64[1];
  kv.value = new_state;
  BV(clib_bihash_add_del) (bi_table, &kv, 1 /* is_add */);
}

/**
 * @brief create a new session for a new flow
 */
u32 create_session(u64 cat) {
  plus_session_t * session;
  plus_main_t * pm = &plus_main;
  pm->active_flows ++;
  pm->total_flows ++;
  pool_get (pm->session_pool, session);
  memset (session, 0, sizeof (*session));
  /* Correct session index */
  session->index = session - pm->session_pool;
  session->state = 0;
  session->cat = cat;
  return session->index;
}

/**
 * @brief clean session after timeout
 */
void clean_session(u32 index)
{
  plus_main_t * pm = &plus_main;
  plus_session_t * session = get_plus_session(index);
  
  /* If main loop (in node.c) is executed sparsely, it can happen that the timer wheel triggers multiple times for the same session. */
  /* We remove/clean the session only the first time. */
  if (session == 0) {
    return;
  }
  pm->active_flows --;
  
  BVT(clib_bihash_kv) kv;
  BVT(clib_bihash) * bi_table;
  bi_table = &pm->plus_table;
  kv.key[0] = session->key[0];
  kv.key[1] = session->key[1];
  
  /* clear hash and pool entry */
  BV(clib_bihash_add_del) (bi_table, &kv, 0 /* is_add */);
  pool_put (pm->session_pool, session);
}

/**
 * @brief callback function for expired timer
 */
static void timer_expired_callback(u32 * expired_timers)
{
  int i;
  u32 index, timer_id;
  
  /* Iterate over all expired timers */
  for (i = 0; i < vec_len(expired_timers); i = i+1)
  {
    /* Extract index and timer wheel id */
    index = expired_timers[i] & 0x7FFFFFFF;
    timer_id = expired_timers[i] >> 31;
    
    /* Only use timer with ID 0 at the moment */
    ASSERT (timer_id == 0);

    clean_session(index);
  }
}

/**
 * @brief Initialize the plus plugin.
 */
static clib_error_t * plus_init (vlib_main_t * vm)
{
  plus_main_t * pm = &plus_main;
  clib_error_t * error = 0;
  u8 * name;

  pm->vnet_main =  vnet_get_main ();
  name = format (0, "plus_%08x%c", api_version, 0);
  
  /* Ask for a correctly-sized block of API message decode slots */
  pm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);
  
  error = plus_plugin_api_hookup (vm);
  
  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (pm, &api_main);
  
  /* Init bihash */
  BV (clib_bihash_init) (&pm->plus_table, "plus", 2048, 512<<20);

  /* Timer wheel has 2048 slots, so we predefine pool with 2048 entries as well */ 
  pool_init_fixed(pm->session_pool, 2048);

  /* Init timer wheel with 100ms resolution */
  tw_timer_wheel_init_2t_1w_2048sl (&pm->tw, timer_expired_callback, 100e-3, ~0);
  pm->tw.last_run_time = vlib_time_now (vm);
  
  /* Set counters to zero*/
  pm->total_flows = 0;
  pm->active_flows = 0;

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (plus_init);

/**
 * @brief Hook the PLUS plugin into the VPP graph hierarchy.
 */
VNET_FEATURE_INIT (plus, static) = 
{
  /* It runs in the ip4-unicast arc before the ip4-lookup */
  .arc_name = "ip4-unicast",
  .node_name = "plus",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
