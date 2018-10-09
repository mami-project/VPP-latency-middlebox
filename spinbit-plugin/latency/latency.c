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
 * @brief Latency plugin, plugin API / trace / CLI handling.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <latency/latency.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <latency/latency_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <latency/latency_all_api_h.h> 
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <latency/latency_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <latency/latency_all_api_h.h> 
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <latency/latency_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE pm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */
#define foreach_latency_plugin_api_msg                           \
_(LATENCY_ENABLE_DISABLE, latency_enable_disable)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = LATENCY_PLUGIN_BUILD_VER,
  .description = "LATENCY middlebox VPP Plugin",
};
/* *INDENT-ON* */

/**
 * @brief Enable/disable the plugin. 
 *
 * Action function shared between message handler and debug CLI.
 */
int latency_enable_disable (latency_main_t * pm, u32 sw_if_index,
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
  
 
  vnet_feature_enable_disable ("ip4-unicast", "latency",
                               sw_if_index, enable_disable, 0, 0);
  return rv;
}

static clib_error_t *
latency_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  latency_main_t * pm = &latency_main;
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
    
  rv = latency_enable_disable (pm, sw_if_index, enable_disable);

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
    return clib_error_return (0, "latency_enable_disable returned %d",
                              rv);
  }
  return 0;
}

/**
 * @brief format function (print each active flow)
 */
u8 * format_sessions(u8 *s, va_list *args) {
  latency_main_t * pm = &latency_main;

  s = format(s, "Total flows: %u, total active flows: %u\n",
                  pm->total_flows, pm->active_flows);
  latency_session_t * session;
  
  s = format(s, "=======================================================\n");
  
  /* Iterate through all pool entries */
  pool_foreach (session, pm->session_pool, ({
    switch (session->p_type) {
      case P_TCP:
        s = format(s, "TCP: observed packets: %u\n", session->pkt_count);
        s = format(s, "VEC (client, server): %.*lfs %.*lfs\n",
                   STAT_PRECISION, session->tcp->status_spin_observer.rtt_client,
                   STAT_PRECISION, session->tcp->status_spin_observer.rtt_server);
        s = format(s, "TS single (client, server): %.*lfs %.*lfs\n",
                   STAT_PRECISION, session->tcp->ts_one_RTT_observer.rtt_client,
                   STAT_PRECISION, session->tcp->ts_one_RTT_observer.rtt_server);
        s = format(s, "TS all (client, server): %.*lfs %.*lfs\n",
                   STAT_PRECISION, session->tcp->ts_all_RTT_observer.rtt_client,
                   STAT_PRECISION, session->tcp->ts_all_RTT_observer.rtt_server);
      break;
      
      case P_QUIC:
        s = format(s, "QUIC: observed packets: %u\n", session->pkt_count);
        s = format(s, "Spin basic (client, server): %.*lfs %.*lfs\n",
                   STAT_PRECISION, session->quic->basic_spin_observer.rtt_client,
                   STAT_PRECISION, session->quic->basic_spin_observer.rtt_server);
        s = format(s, "Spin pn (client, server): %.*lfs %.*lfs\n",
                   STAT_PRECISION, session->quic->pn_spin_observer.rtt_client,
                   STAT_PRECISION, session->quic->pn_spin_observer.rtt_server);
        s = format(s, "VEC (client, server): %.*lfs %.*lfs\n",
                   STAT_PRECISION, session->quic->status_spin_observer.rtt_client,
                   STAT_PRECISION, session->quic->status_spin_observer.rtt_server);
        s = format(s, "Spin heur (client, server): %.*lfs %.*lfs\n",
                   STAT_PRECISION, session->quic->dyna_heur_spin_observer.rtt_client[session->quic->dyna_heur_spin_observer.index_client],
                   STAT_PRECISION, session->quic->dyna_heur_spin_observer.rtt_server[session->quic->dyna_heur_spin_observer.index_server]);
      break;
      
      case P_PLUS:
        s = format(s, "PLUS: observed packets: %u\n", session->pkt_count);
        s = format(s, "PSN/PSE (client, server): %.*lfs %.*lfs\n",
                   STAT_PRECISION, session->plus->plus_single_observer.rtt_src,
                   STAT_PRECISION, session->plus->plus_single_observer.rtt_dst);
      break;

      default:
        s = format(s, "Unknown protocol type - error!");
      break;
    } 
    s = format(s, "=======================================================\n");
  }));
  return s;
}

static clib_error_t * latency_show_stats_fn(vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd) {
  vl_print(vm, "%U", format_sessions);
  return 0;
}

static clib_error_t * latency_show_version_fn(vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd) {
  vl_print(vm, "V 0.1, support for TCP, QUIC and PLUS");
  return 0;
}

static clib_error_t * latency_add_port_fn(vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd) {
  latency_main_t * pm = &latency_main;
  u32 quic_port = 0;
    
  if (!unformat (input, "%d", &quic_port)) {
    return clib_error_return (0, "Please specify a correct port.");
  }
  if (quic_port >= 65536) {
    return clib_error_return (0, "Please specify a correct port."); 
  }

  hash_set(pm->hash_quic_ports, clib_host_to_net_u16(quic_port), 1);
  
  return 0;
}

static clib_error_t * latency_add_nat_fn(vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd) {
  latency_main_t * pm = &latency_main;
  u32 port, ip[4];
  ip4_address_t ip4;

  if (!unformat(input, "%d.%d.%d.%d %d", &ip[0], &ip[1], &ip[2], &ip[3], &port)) {
    return clib_error_return (0, "Please enter a correct IP and port, e.g.: latency nat 1.2.3.4 555");
  }
  if (ip[0] >= 256 || ip[1] >= 256 || ip[2] >= 256 || ip[3] >= 256) {
    return clib_error_return (0, "Please enter a correct IP and port, e.g.: latency nat 1.2.3.4 555");
  }
  if (port >= 65536) {
    return clib_error_return (0, "Please enter a correct IP and port, e.g.: latency nat 1.2.3.4 555"); 
  }

  ip4.as_u8[3] = ip[0];
  ip4.as_u8[2] = ip[1];
  ip4.as_u8[1] = ip[2];
  ip4.as_u8[0] = ip[3];

  hash_set(pm->hash_server_ports_to_ips,
           clib_host_to_net_u16(port),
           clib_host_to_net_u32(ip4.as_u32));

  return 0;
}

static clib_error_t * latency_add_ip_fn(vlib_main_t * vm,
              unformat_input_t * input, vlib_cli_command_t * cmd) {
  latency_main_t * pm = &latency_main;
  u32 ip[4];
  ip4_address_t ip4;

  if (!unformat(input, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])) {
    return clib_error_return (0, "Please enter a correct IP, e.g.: latency ip 10.0.0.1");
  }
  if (ip[0] >= 256 || ip[1] >= 256 || ip[2] >= 256 || ip[3] >= 256) {
    return clib_error_return (0, "Please enter a correct IP, e.g.: latency ip 10.0.0.1");
  }

  ip4.as_u8[3] = ip[0];
  ip4.as_u8[2] = ip[1];
  ip4.as_u8[1] = ip[2];
  ip4.as_u8[0] = ip[3];

  pm->mb_ip = clib_host_to_net_u32(ip4.as_u32);
  
  return 0;
}

/**
 * @brief CLI command to enable/disable the latency plugin.
 */
VLIB_CLI_COMMAND (sr_content_command, static) = {
  .path = "latency interface",
  .short_help = 
  "latency interface <interface-name> [disable]",
  .function = latency_enable_disable_command_fn,
};

/**
 * @brief CLI command to show all active flows
 */
VLIB_CLI_COMMAND (sr_content_command_stats, static) = {
  .path = "latency stats",
  .short_help = "Show LATENCY middlebox stats",
  .function = latency_show_stats_fn,
};

/**
 * @brief CLI command to show version
 */
VLIB_CLI_COMMAND (sr_content_command_version, static) = {
  .path = "latency version",
  .short_help = "LATENCY plugin version information",
  .function = latency_show_version_fn,
};

/**
 * @brief CLI command to add QUIC dst port
 */
VLIB_CLI_COMMAND (sr_content_command_port, static) = {
  .path = "latency quic_port",
  .short_help = "Add QUIC dst port: latency port <port>",
  .function = latency_add_port_fn,
};

/**
 * @brief CLI command to add IP port "NAT" entry
 */
VLIB_CLI_COMMAND (sr_content_command_nat, static) = {
  .path = "latency nat",
  .short_help = "Add middlebox NAT functionality: latency nat <IPv4 (dot)> <port>",
  .function = latency_add_nat_fn,
};

/**
 * @brief CLI command to add MB IP
 */
VLIB_CLI_COMMAND (sr_content_command_ip, static) = {
  .path = "latency mb_ip",
  .short_help = "Set IP of the VPP middlebox: <IPv4 (dot)>",
  .function = latency_add_ip_fn,
};

/**
 * @brief LATENCY API message handler.
 */
static void vl_api_latency_enable_disable_t_handler
         (vl_api_latency_enable_disable_t * mp) {
  vl_api_latency_enable_disable_reply_t * rmp;
  latency_main_t * pm = &latency_main;
  int rv;

  rv = latency_enable_disable (pm, ntohl(mp->sw_if_index), 
                               (int) (mp->enable_disable));
  
  REPLY_MACRO(VL_API_LATENCY_ENABLE_DISABLE_REPLY);
}

/**
 * @brief Set up the API message handling tables.
 */
static clib_error_t *
latency_plugin_api_hookup (vlib_main_t *vm) {
  latency_main_t * pm = &latency_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + pm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_latency_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <latency/latency_all_api_h.h>
#undef vl_msg_name_crc_list

static void 
setup_message_id_table (latency_main_t * pm, api_main_t *am) {
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + pm->msg_id_base);
  foreach_vl_msg_name_crc_latency;
#undef _
}

/**
 *  @brief create the hash key
 */
void make_key(latency_key_t * kv, u32 src_ip, u32 dst_ip,
              u16 src_p, u16 dst_p, u8 protocol) {
  if (src_ip == 0) {
    src_ip = latency_main.mb_ip;
  }
  kv->s_x_d_ip = src_ip ^ dst_ip;
  kv->s_x_d_port = src_p ^ dst_p;
  kv->protocol = protocol;
}

void make_plus_key(latency_key_t * kv, u32 src_ip, u32 dst_ip,
                u16 src_p, u16 dst_p, u8 protocol, u64 cat) {
  make_key(kv, src_ip, dst_ip, src_p, dst_p, protocol);
  kv->as_u64 = kv->as_u64 ^ cat;
}

/**
 *  @brief get session pointer if corresponding key is known
 */
latency_session_t * get_session_from_key(latency_key_t * kv_in) {
  BVT(clib_bihash_kv) kv, kv_return;
  latency_main_t *pm = &latency_main;
  BVT(clib_bihash) *bi_table;
  bi_table = &pm->latency_table;
  kv.key = kv_in->as_u64;
  int rv = BV(clib_bihash_search) (bi_table, &kv, &kv_return);
  if (rv != 0) {
    /* Key does not exist */
    return 0;
  } else {
    return get_latency_session(kv_return.value);
  }
}

bool ip_nat_translation(ip4_header_t *ip0, u32 init_src_ip, u32 new_dst_ip) {
  if (ip0->src_address.as_u32 == init_src_ip) {
    ip0->src_address.as_u32 = latency_main.mb_ip;
    ip0->dst_address.as_u32 = new_dst_ip;
    return true;
  }
  if (ip0->src_address.as_u32 == new_dst_ip) {
    ip0->src_address.as_u32 = latency_main.mb_ip;
    ip0->dst_address.as_u32 = init_src_ip;
    return true;
  }
  return false;
}

/* Update all RTT estimations for QUIC packets */
void update_quic_rtt_estimate(vlib_main_t * vm, quic_observer_t * session,
            f64 now, u16 src_port, u16 init_src_port, u8 measurement,
            u32 packet_number, u32 pkt_count) {

  bool spin = measurement & ONE_BIT_SPIN;
  u8 status_bits = (measurement & STATUS_MASK) >> STATUS_SHIFT;
  bool basic = basic_latency_estimate(vm, &(session->basic_spin_observer),
            now, src_port, init_src_port, spin);
  
  // TODO: will fail if packet number is 0
  bool pn = false;
  if (packet_number) {
    pn = pn_latency_estimate(vm, &(session->pn_spin_observer),
            now, src_port, init_src_port, spin, packet_number);
  }
  /* VEC estimator */
  bool status = status_estimate(vm, &(session->status_spin_observer),
            now, src_port, init_src_port, spin, status_bits);
  bool dyna = heuristic_estimate(vm, &(session->dyna_heur_spin_observer),
            now, src_port, init_src_port, spin);
  
  /* Now it is time to print the rtt estimates to a file */
  /* If this is the first time we run, print CSV file header */
  if (pkt_count == 1){
    latency_printf(0, "%s,%s,%s", "time", "pn", "host");
    latency_printf(0, ",%s,%s", "spin_data", "spin_new");
    latency_printf(0, ",%s,%s", "pn_spin_data", "pn_spin_new");
    latency_printf(0, ",%s,%s", "vec_data", "vec_new");
    latency_printf(0, ",%s,%s", "heur_data", "heur_new");
    latency_printf(0, "\n");
  }

  /* If at least one update */
  if (basic || pn || status || dyna) {
    /* Now print the actual data */
    if (src_port == init_src_port) {
      latency_printf(0, "%.*lf,%u,%s", TIME_PRECISION, now,
                     packet_number, "server");
      latency_printf(0, ",%.*lf", RTT_PRECISION, session->basic_spin_observer.rtt_server);
      latency_printf(0, ",%d", session->basic_spin_observer.new_server);
      latency_printf(0, ",%.*lf", RTT_PRECISION, session->pn_spin_observer.rtt_server);
      latency_printf(0, ",%d", session->pn_spin_observer.new_server);
      latency_printf(0, ",%.*lf", RTT_PRECISION, session->status_spin_observer.rtt_server);
      latency_printf(0, ",%d", session->status_spin_observer.new_server);
      latency_printf(0, ",%.*lf", RTT_PRECISION,
             session->dyna_heur_spin_observer.rtt_server[session->dyna_heur_spin_observer.index_server]);
      latency_printf(0, ",%d", session->dyna_heur_spin_observer.new_server);
      latency_printf(1, "\n");

      session->basic_spin_observer.new_server = false;
      session->pn_spin_observer.new_server = false;
      session->status_spin_observer.new_server = false;
      session->dyna_heur_spin_observer.new_server = false;

    } else {
      latency_printf(0, "%.*lf,%u,%s", TIME_PRECISION, now,
                     packet_number, "client");
      latency_printf(0, ",%.*lf", RTT_PRECISION, session->basic_spin_observer.rtt_client);
      latency_printf(0, ",%d", session->basic_spin_observer.new_client);
      latency_printf(0, ",%.*lf", RTT_PRECISION, session->pn_spin_observer.rtt_client);
      latency_printf(0, ",%d", session->pn_spin_observer.new_client);
      latency_printf(0, ",%.*lf", RTT_PRECISION, session->status_spin_observer.rtt_client);
      latency_printf(0, ",%d", session->status_spin_observer.new_client);
      latency_printf(0, ",%.*lf", RTT_PRECISION,
            session->dyna_heur_spin_observer.rtt_client[session->dyna_heur_spin_observer.index_client]);
      latency_printf(0, ",%d", session->dyna_heur_spin_observer.new_client);
      latency_printf(1, "\n");

      session->basic_spin_observer.new_client = false;
      session->pn_spin_observer.new_client = false;
      session->status_spin_observer.new_client = false;
      session->dyna_heur_spin_observer.new_client = false;
    }
  }
}

/**
 * BASIC latency estimator
 */
bool basic_latency_estimate(vlib_main_t * vm, basic_spin_observer_t *observer,
        f64 now, u16 src_port, u16 init_src_port, bool spin) {
  /* if this is a packet from the SERVER */
  if (src_port != init_src_port) {
    if (observer->spin_server != spin) {
      observer->spin_server = spin;
      observer->rtt_server = now - observer->time_last_spin_server;
      observer->new_server = true;
      observer->time_last_spin_server = now;
      return true;
    }
  /* if this is a packet from the CLIENT */
  } else {
    if (observer->spin_client != spin) {
      observer->spin_client = spin;
      observer->rtt_client = now - observer->time_last_spin_client;
      observer->new_client = true;
      observer->time_last_spin_client = now;
      return true;
    }
  }
  return false;
}

/*
 * (PN) observer
 */
//TODO this does not handle PN wrap around yet
bool pn_latency_estimate(vlib_main_t * vm, pn_spin_observer_t *observer,
    f64 now, u16 src_port, u16 init_src_port, bool spin, u32 packet_number) {
  /* if this is a packet from the SERVER */
  if (src_port != init_src_port) {
    /* check if arrived in order and has different spin */
    if (packet_number > observer->pn_server && observer->spin_server != spin) {
      observer->spin_server = spin;
      observer->pn_server = packet_number;
      observer->rtt_server = now - observer->time_last_spin_server;
      observer->new_server = true;
      observer->time_last_spin_server = now;
      return true;
    }
  /* if this is a packet from the CLIENT */
  } else {
    /* check if arrived in order and has different spin */
    if (packet_number > observer->pn_client && observer->spin_client != spin) {
      observer->spin_client = spin;
      observer->pn_client = packet_number;
      observer->rtt_client = now - observer->time_last_spin_client;
      observer->new_client = true;
      observer->time_last_spin_client = now;
      return true;
    }
  }
  return false;
}

/*
 * VEC observer
 */
bool status_estimate(vlib_main_t * vm, status_spin_observer_t *observer,
      f64 now, u16 src_port, u16 init_src_port, bool spin, u8 status) {
  bool update = false;
  /* if this is a packet from the SERVER */
  if (src_port != init_src_port) {
    /* check if arrived in order and has different spin */
    if (observer->spin_server != spin) {
      observer->spin_server = spin;
      /* only report and store RTT if it was valid over the entire round trip */
      if (status == STATUS_VALID){
        observer->rtt_server = now - observer->time_last_spin_server;
        observer->new_server = true;
        update = true;
      }
    }
    if (status != STATUS_INVALID) observer->time_last_spin_server = now;
  
  /* if this is a packet from the CLIENT */
  } else {
    /* check if arrived in order and has different spin */
    if (observer->spin_client != spin) {
      observer->spin_client = spin;
      /* only report and store RTT if it was valid over the entire round trip */
      if (status == STATUS_VALID){
        observer->rtt_client = now - observer->time_last_spin_client;
        observer->new_client = true;
        update = true;
      }
    }
    if (status != STATUS_INVALID) observer->time_last_spin_client = now;
  }
  return update;
}

/*
 * VEC ne zero estimate
 */
bool vec_ne_zero_estimate(vlib_main_t * vm, status_spin_observer_t *observer,
      f64 now, u16 src_port, u16 init_src_port, bool spin, u8 status) {
  bool update = false;
  /* if this is a packet from the SERVER */
  if (src_port != init_src_port) {
    /* check if arrived in order and has different spin */
    if (observer->spin_server != spin) {
      observer->spin_server = spin;
      /* only report and store RTT if it was valid over the entire round trip */
      if (status != STATUS_INVALID){
        observer->rtt_server = now - observer->time_last_spin_server;
        observer->new_server = true;
        update = true;
      }
    }
    if (status != STATUS_INVALID) observer->time_last_spin_server = now;
  
  /* if this is a packet from the CLIENT */
  } else {
    /* check if arrived in order and has different spin */
    if (observer->spin_client != spin) {
      observer->spin_client = spin;
      /* only report and store RTT if it was valid over the entire round trip */
      if (status != STATUS_INVALID){
        observer->rtt_client = now - observer->time_last_spin_client;
        observer->new_client = true;
        update = true;
      }
    }
    if (status != STATUS_INVALID) observer->time_last_spin_client = now;
  }
  return update;
}

/*
 * Dynamic heuristic observer
 */
bool heuristic_estimate(vlib_main_t * vm, dyna_heur_spin_observer_t *observer,
          f64 now, u16 src_port, u16 init_src_port, bool spin) {
  bool update = false;
  /* if this is a packet from the SERVER */
  if (src_port != init_src_port) {
    if (observer->spin_server != spin) {
      observer->spin_server = spin;
      f64 rtt_candidate = now - observer->time_last_spin_server;

      /* calculate the acceptance threshold */
      f64 acceptance_threshold = observer->rtt_server[0];
      for(int i = 1; i < DYNA_HEUR_HISTORY_SIZE; i++){
        if (observer->rtt_server[i] < acceptance_threshold){
          acceptance_threshold = observer->rtt_server[i];
        }
      }
      acceptance_threshold *= DYNA_HEUR_THRESHOLD;

      if (rtt_candidate > acceptance_threshold ||
          observer->rejected_server >= DYNA_HEUR_MAX_REJECT){
        observer->rejected_server = 0;
        observer->index_server =
          (observer->index_server + 1) % DYNA_HEUR_HISTORY_SIZE;
        observer->rtt_server[observer->index_server] = rtt_candidate;
        observer->new_server = true;
        update = true;
        /* The assumption is that a packet has been held back long enough to arrive
         * after the valid spin edge, therefore, we completely ignore this false spin edge
         * and do not report the time at which we saw this packet */
        observer->time_last_spin_server = now;

      /* if the rtt_candidate is rejected */
      } else {
        observer->rejected_server++;
      }
    }
  
  /* if this is a packet from the CLIENT */
  } else {
    if (observer->spin_client != spin){
      observer->spin_client = spin;
      f64 rtt_candidate = now - observer->time_last_spin_client;

      /* calculate the acceptance threshold */
      f64 acceptance_threshold = observer->rtt_client[0];
      for(int i = 1; i < DYNA_HEUR_HISTORY_SIZE; i++){
        if (observer->rtt_client[i] < acceptance_threshold){
          acceptance_threshold = observer->rtt_client[i];
        }
      }
      acceptance_threshold *= DYNA_HEUR_THRESHOLD;

      if (rtt_candidate > acceptance_threshold ||
          observer->rejected_client >= DYNA_HEUR_MAX_REJECT){
        observer->rejected_client = 0;
        observer->index_client =
          (observer->index_client + 1) % DYNA_HEUR_HISTORY_SIZE;
        observer->rtt_client[observer->index_client] = rtt_candidate;
        observer->new_client = true;
        update = true;
        /* see comment for packets from server */
        observer->time_last_spin_client = now;
      } else {
        observer->rejected_client++;
      }
    }
  }
  return update;
}

/* Update all RTT estimations for TCP packets */
void update_tcp_rtt_estimate(vlib_main_t * vm, tcp_observer_t * session,
                f64 now, u16 src_port, u16 init_src_port, u8 measurement,
                u32 tsval, u32 tsecr, u32 pkt_count, u32 seq_num) {

  bool spin = measurement & TCP_SPIN;
  u8 status_bits = (measurement & TCP_VEC_MASK) >> TCP_VEC_SHIFT;
  bool status = status_estimate(vm, &(session->status_spin_observer),
                now, src_port, init_src_port, spin, status_bits);
  bool vec_status = vec_ne_zero_estimate(vm, &(session->vec_ne_zero),
                now, src_port, init_src_port, spin, status_bits);
  bool single = ts_single_estimate(vm, &(session->ts_one_RTT_observer),
                now, src_port, init_src_port, tsval, tsecr);
  bool all = ts_all_estimate(vm, &(session->ts_all_RTT_observer),
                now, src_port, init_src_port, tsval, tsecr);
  
  if (pkt_count == 1){
    tcp_printf(0, "%s,%s,%s", "time", "host", "seq_num");
    tcp_printf(0, ",%s,%s", "vec_data", "vec_new");
    tcp_printf(0, ",%s,%s", "single_ts_rtt_data", "single_ts_rtt_new");
    tcp_printf(0, ",%s,%s", "all_ts_rtt_data", "all_ts_rtt_new");
    tcp_printf(0, ",%s,%s", "vec_ne_zero_data", "vec_ne_zero_new");
    tcp_printf(0, "\n");
  }
  
  /* If we have at least one update */
  if (status || single || all || vec_status) {
    /* Now print the actual data */
    if (src_port != init_src_port) {
      tcp_printf(0, "%.*lf,%s,%u", TIME_PRECISION, now, "server", seq_num);
      tcp_printf(0, ",%.*lf", RTT_PRECISION, session->status_spin_observer.rtt_server);
      tcp_printf(0, ",%d", session->status_spin_observer.new_server);
      tcp_printf(0, ",%.*lf", RTT_PRECISION, session->ts_one_RTT_observer.rtt_server);
      tcp_printf(0, ",%d", session->ts_one_RTT_observer.new_server);
      tcp_printf(0, ",%.*lf", RTT_PRECISION, session->ts_all_RTT_observer.rtt_server);
      tcp_printf(0, ",%d", session->ts_all_RTT_observer.new_server);
      tcp_printf(0, ",%.*lf", RTT_PRECISION, session->vec_ne_zero.rtt_server);
      tcp_printf(0, ",%d", session->vec_ne_zero.new_server);
    
      tcp_printf(1, "\n");

      session->status_spin_observer.new_server = false;
      session->vec_ne_zero.new_server = false;
      session->ts_one_RTT_observer.new_server = false;
      session->ts_all_RTT_observer.new_server = false;

    } else {
      tcp_printf(0, "%.*lf,%s,%u", TIME_PRECISION, now, "client", seq_num);
      tcp_printf(0, ",%.*lf", RTT_PRECISION, session->status_spin_observer.rtt_client);
      tcp_printf(0, ",%d", session->status_spin_observer.new_client);
      tcp_printf(0, ",%.*lf", RTT_PRECISION,  session->ts_one_RTT_observer.rtt_client);
      tcp_printf(0, ",%d", session->ts_one_RTT_observer.new_client);
      tcp_printf(0, ",%.*lf", RTT_PRECISION, session->ts_all_RTT_observer.rtt_client);
      tcp_printf(0, ",%d", session->ts_all_RTT_observer.new_client);
      tcp_printf(0, ",%.*lf", RTT_PRECISION, session->vec_ne_zero.rtt_client);
      tcp_printf(0, ",%d", session->vec_ne_zero.new_client);
      
      tcp_printf(1, "\n");

      session->status_spin_observer.new_client = false;
      session->vec_ne_zero.new_client = false;
      session->ts_one_RTT_observer.new_client = false;
      session->ts_all_RTT_observer.new_client = false;

    }
  }
}

/* One RTT estimation per RTT */
bool ts_single_estimate(vlib_main_t * vm,
          timestamp_observer_single_RTT_t * observer,
          f64 now, u16 src_port, u16 init_src_port, u32 tsval, u32 tsecr) {
  bool update = false;
  if (src_port == init_src_port) {
    if (!observer->ts_init_client) {
      observer->ts_init_client = tsval;
      observer->time_init_client = now;
    } else {  
      if (tsecr && observer->ts_ack_client &&
          tsecr >= observer->ts_ack_client) {
        observer->rtt_client = now - observer->time_init_client;
        observer->ts_init_client = tsval;
        observer->ts_ack_client = 0;
        observer->time_init_client = now;
        observer->new_client = true;
        update = true;
      }
    }
    if (tsecr && !observer->ts_ack_server &&
        tsecr >= observer->ts_init_server) { 
      observer->ts_ack_server = tsval;
    }
  }
  else {
    if (!observer->ts_init_server) {
      observer->ts_init_server = tsval;
      observer->time_init_server = now;
    }
    else {
      if (tsecr && observer->ts_ack_server &&
          tsecr >= observer->ts_ack_server) {
        observer->rtt_server = now - observer->time_init_server;
        observer->ts_init_server = tsval;
        observer->ts_ack_server = 0;
        observer->time_init_server = now;
        observer->new_server = true;
        update = true;
      }
    }
    if (tsecr && !observer->ts_ack_client &&
        tsecr >= observer->ts_init_client) {
      observer->ts_ack_client = tsval;
    } 
  }
  return update;
}

/* RTT estimation for every possible timestamp value */
bool ts_all_estimate(vlib_main_t * vm, timestamp_observer_all_RTT_t * observer,
          f64 now, u16 src_port, u16 init_src_port, u32 tsval, u32 tsecr) {
  bool update = false;

  // TODO state will explode in case of large reordering
  if (src_port == init_src_port) {
    uword* init_t = hash_get(observer->hash_init_client, tsval);
    uword* ack_t = hash_get(observer->hash_ack_client, tsecr);
    uword* init_t_server = hash_get(observer->hash_init_server, tsecr);
    if (!init_t) {
      time_test_t* temp;
      vec_alloc(temp, 1);
      memset(temp, 0, sizeof (time_test_t));
      temp->time = now;
      hash_set(observer->hash_init_client, tsval, temp);
    } 
    if (tsecr && ack_t) {
      time_test_t* ack_time = (time_test_t *) ack_t[0];
      observer->rtt_client = now - ack_time->time;
      vec_free(ack_time);
      hash_unset(observer->hash_ack_client, tsecr);
      observer->new_client = true;
      update = true;
    }
    if (tsecr && init_t_server) {
      hash_set(observer->hash_ack_server, tsval, (time_test_t*) init_t_server[0]);
      hash_unset(observer->hash_init_server, tsecr);
    }
  }
  else {
    uword* init_t = hash_get(observer->hash_init_server, tsval);
    uword* ack_t = hash_get(observer->hash_ack_server, tsecr);
    uword* init_t_client = hash_get(observer->hash_init_client, tsecr);
    if (!init_t) {
      time_test_t* temp;
      vec_alloc(temp, 1);
      memset(temp, 0, sizeof (time_test_t));
      temp->time = now;
      hash_set(observer->hash_init_server, tsval, temp);
    } 
    if (tsecr && ack_t) {
      time_test_t* ack_time = (time_test_t *) ack_t[0];
      observer->rtt_server = now - ack_time->time;
      vec_free(ack_time);
      hash_unset(observer->hash_ack_server, tsecr);
      observer->new_server = true;
      update = true;
    }
    if (tsecr && init_t_client) { 
      hash_set(observer->hash_ack_client, tsval, (time_test_t*) init_t_client[0]);
      hash_unset(observer->hash_init_client, tsecr);
    }
  }
  // TODO: check all hash sizes and clear if too big
  // perhaps also based on amount of observed packets, e.g. every 5000 packets
  // E.g. if sum(4 hashes) > 500 -> clear all hashes,
  // set both times to 0 and update to true
  return update;
}

void update_plus_rtt_estimate(vlib_main_t * vm, plus_observer_t * session,
        f64 now, u16 src_port, u16 init_src_port, u32 psn,
        u32 pse, u64 cat, u32 pkt_count) {
  
  bool new_rtt = psn_single_estimate(vm, &(session->plus_single_observer),
                 src_port, init_src_port, psn, pse, now);
  
  if (pkt_count == 1){
    /* TODO: add CAT */
    plus_printf(0, "%s,%s,%s,%s,%s,%s", "time", "host", "#pkt", "psn", "pse", "cat");
    plus_printf(0, ",%s,%s", "psn_pse_data", "psn_pse_new");
    plus_printf(0, "\n");
  }

  /* If we have at least one update */
  if (new_rtt) {
    /* Now print the actual data */
    if (src_port != init_src_port) {
      plus_printf(0, "%.*lf,%s,%u,%u,%u,%llu", TIME_PRECISION, now, "server", pkt_count, psn, pse, cat);
      
      plus_printf(0, ",%.*lf", RTT_PRECISION, session->plus_single_observer.rtt_dst);
      plus_printf(0, ",%d", session->plus_single_observer.new_server);
    
      plus_printf(1, "\n");

      session->plus_single_observer.new_server = false;
    } else {
      plus_printf(0, "%.*lf,%s,%u,%u,%u,%llu", TIME_PRECISION, now, "client", pkt_count, psn, pse, cat);
      
      plus_printf(0, ",%.*lf", RTT_PRECISION, session->plus_single_observer.rtt_src);
      plus_printf(0, ",%d", session->plus_single_observer.new_client);
      
      plus_printf(1, "\n");

      session->plus_single_observer.new_client = false;
    }
  }
}

bool psn_single_estimate(vlib_main_t * vm, plus_single_observer_t * session,
        u16 src_port, u16 init_src_port, u32 psn, u32 pse, f64 now) {
    /* Decide direction */
  if (src_port == init_src_port) {
    /* Is the RTT estimation for the last packet completed?  */ 
    if (session->time_src == 0) {
      session->psn_src = psn;
      session->time_src = now;
    }
    if (session->time_dst && comes_after_u32(pse, session->psn_dst)) {
      session->rtt_src = now - session->time_dst;
      session->time_dst = 0;
      session->new_client = true;
      return true;
    }
  } else {
    if (session->time_dst == 0) {
      session->psn_dst = psn;
      session->time_dst = now;
    }
    if (session->time_src && comes_after_u32(pse, session->psn_src)) {
      session->rtt_dst = now - session->time_src;
      session->time_src = 0;
      session->new_server = true;
      return true;
    }
  }
  return false;
}

/**
 * @brief update the state of the session with the given key
 */
void update_state(latency_key_t * kv_in, uword new_state)
{
  BVT(clib_bihash_kv) kv;
  latency_main_t *pm = &latency_main;
  BVT(clib_bihash) *bi_table;
  bi_table = &pm->latency_table;
  kv.key = kv_in->as_u64;
  kv.value = new_state;
  BV(clib_bihash_add_del) (bi_table, &kv, 1 /* is_add */);
}

/**
 * @brief create a new session for a new flow
 */
u32 create_session(sup_protocols_t p_type) {
  latency_session_t * session;
  latency_main_t * pm = &latency_main;
  pm->active_flows ++;
  pm->total_flows ++;
  pool_get (pm->session_pool, session);
  memset(session, 0, sizeof (*session));
  /* Correct session index */
  session->index = session - pm->session_pool;
  session->state = 0;
  
  switch (p_type) {
    case P_TCP:
      session->p_type = P_TCP;
      vec_alloc(session->tcp, 1);
      memset(session->tcp, 0, sizeof (tcp_observer_t));
      session->tcp->status_spin_observer.spin_client = SPIN_NOT_KNOWN;
      session->tcp->status_spin_observer.spin_server = SPIN_NOT_KNOWN;
      session->tcp->vec_ne_zero.spin_client = SPIN_NOT_KNOWN;
      session->tcp->vec_ne_zero.spin_server = SPIN_NOT_KNOWN;
      session->tcp->ts_all_RTT_observer.hash_init_client =
        hash_create(0, sizeof(time_test_t*));
      session->tcp->ts_all_RTT_observer.hash_init_server =
        hash_create(0, sizeof(time_test_t*));
      session->tcp->ts_all_RTT_observer.hash_ack_client =
        hash_create(0, sizeof(time_test_t*));
      session->tcp->ts_all_RTT_observer.hash_ack_server =
        hash_create(0, sizeof(time_test_t*));
      break;

    case P_QUIC:
      session->p_type = P_QUIC;
      vec_alloc(session->quic, 1);
      memset(session->quic, 0, sizeof (quic_observer_t));
      session->quic->basic_spin_observer.spin_client = SPIN_NOT_KNOWN;
      session->quic->basic_spin_observer.spin_server = SPIN_NOT_KNOWN;
      session->quic->pn_spin_observer.spin_client = SPIN_NOT_KNOWN;
      session->quic->pn_spin_observer.spin_server = SPIN_NOT_KNOWN;
      session->quic->status_spin_observer.spin_client = SPIN_NOT_KNOWN;
      session->quic->status_spin_observer.spin_server = SPIN_NOT_KNOWN;
      session->quic->dyna_heur_spin_observer.spin_client = SPIN_NOT_KNOWN;
      session->quic->dyna_heur_spin_observer.spin_server = SPIN_NOT_KNOWN;
    break;

    case P_PLUS:
      session->p_type = P_PLUS;
      vec_alloc(session->plus, 1);
      memset(session->plus, 0, sizeof (plus_observer_t));
    break;
    
    case P_UNKNOWN:
    default:
       session->p_type = P_UNKNOWN;
    break; 
  }
  
  return session->index;
}

/**
 * @brief clean session after timeout
 */
void clean_session(u32 index)
{
  latency_main_t * pm = &latency_main;
  latency_session_t * session = get_latency_session(index);
  
  /* If main loop (in node.c) is executed sparsely, it can happen that
   * the timer wheel triggers multiple times for the same session.
   * We remove/clean the session only the first time. */
  if (session == 0) {
    return;
  }
  pm->active_flows --;
 
  switch (session->p_type) {
    case P_TCP:
      // TODO: fix potential memory leak
      // Iterate over all remaining key, value pairs and free value pointers
      hash_free(session->tcp->ts_all_RTT_observer.hash_init_client);
      hash_free(session->tcp->ts_all_RTT_observer.hash_init_server);
      hash_free(session->tcp->ts_all_RTT_observer.hash_ack_client);
      hash_free(session->tcp->ts_all_RTT_observer.hash_ack_server);
      vec_free(session->tcp);
    break;

    case P_QUIC:
      vec_free(session->quic);
    break;

    case P_PLUS:
      vec_free(session->plus);
    break;

    default:
      break;
  }

  BVT(clib_bihash_kv) kv;
  BVT(clib_bihash) * bi_table;
  bi_table = &pm->latency_table;
  
  /* Clear hash and pool entry
   * First for the key in reverse direction */
  kv.key = session->key_reverse;
  BV(clib_bihash_add_del) (bi_table, &kv, 0 /* is_add */);
  kv.key = session->key;
  BV(clib_bihash_add_del) (bi_table, &kv, 0 /* is_add */);
  pool_put (pm->session_pool, session);
}

/**
 * @brief callback function for expired timer
 */
static void timer_expired_callback(u32 * expired_timers) {
  int i;
  u32 index, timer_id;
  
  /* Iterate over all expired timers */
  for (i = 0; i < vec_len(expired_timers); i = i+1) {
    /* Extract index and timer wheel id */
    index = expired_timers[i] & 0x7FFFFFFF;
    timer_id = expired_timers[i] >> 31;
    
    /* Only use timer with ID 0 at the moment */
    ASSERT (timer_id == 0);

    clean_session(index);
  }
}

/**
 * @brief parse TCP headers (from tcp_input.c)
 */
int
tcp_options_parse_mod (tcp_header_t * th, u32 * tsval, u32 * tsecr) {
  const u8 *data;
  u8 opt_len, opts_len, kind;

  opts_len = (tcp_doff (th) << 2) - sizeof (tcp_header_t);
  data = (const u8 *) (th + 1);

  for (; opts_len > 0; opts_len -= opt_len, data += opt_len) {
      kind = data[0];

    /* Get options length */
    if (kind == TCP_OPTION_EOL)
      break;
    else if (kind == TCP_OPTION_NOOP) {
      opt_len = 1;
      continue;
    }
    else {
      /* broken options */
      if (opts_len < 2)
        return -1;
      
      opt_len = data[1];

      /* weird option length */
      if (opt_len < 2 || opt_len > opts_len)
        return -1;
    }

    /* Parse options */
    switch (kind) {
      case TCP_OPTION_MSS:
        break;
      case TCP_OPTION_WINDOW_SCALE:
        break;
      case TCP_OPTION_TIMESTAMP:
        if (opt_len == TCP_OPTION_LEN_TIMESTAMP) {
          *tsval = clib_net_to_host_u32 (*(u32 *) (data + 2));
          *tsecr = clib_net_to_host_u32 (*(u32 *) (data + 6));
        }
        break;
      case TCP_OPTION_SACK_PERMITTED:
        break;
      case TCP_OPTION_SACK_BLOCK:
        /* If too short or not correctly formatted, break */
        if (opt_len < 10 || ((opt_len - 2) % TCP_OPTION_LEN_SACK_BLOCK))
          break;
        break;
      default:
        continue;
    }
  }
  return 0;
}    

/* Output to CLI / stdout, this is a modified copy of `vlib_cli_output` */
void latency_printf (int flush, char *fmt, ...) {
  va_list va;
  u8 *s;

  static FILE *output_file_spin = NULL;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  if (output_file_spin == NULL){
    output_file_spin = fopen("/tmp/latency_quic_printf.out", "w");
  }
  fprintf(output_file_spin, "%s", s);

  if (flush){
    fflush(output_file_spin);
  }

  vec_free (s);
}

/* Output to CLI / stdout, this is a modified copy of `vlib_cli_output` */
void tcp_printf (int flush, char *fmt, ...) {
  va_list va;
  u8 *s;

  static FILE *output_file_tcp = NULL;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  if (output_file_tcp == NULL){
    output_file_tcp = fopen("/tmp/latency_tcp_printf.out", "w");
  }
  fprintf(output_file_tcp, "%s", s);

  if (flush){
    fflush(output_file_tcp);
  }

  vec_free (s);
}

/* Output to CLI / stdout, this is a modified copy of `vlib_cli_output` */
void plus_printf (int flush, char *fmt, ...) {
  va_list va;
  u8 *s;

  static FILE *output_file_plus = NULL;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  if (output_file_plus == NULL){
    output_file_plus = fopen("/tmp/latency_plus_printf.out", "w");
  }
  fprintf(output_file_plus, "%s", s);

  if (flush){
    fflush(output_file_plus);
  }

  vec_free (s);
}

/**
 * @brief Initialize the latency plugin.
 */
static clib_error_t * latency_init (vlib_main_t * vm)
{

  // TODO: set mb_IP to good default value!!!

  latency_main_t * pm = &latency_main;
  clib_error_t * error = 0;
  u8 * name;

  pm->vnet_main =  vnet_get_main ();
  name = format (0, "latency_%08x%c", api_version, 0);
  
  /* Ask for a correctly-sized block of API message decode slots */
  pm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);
  
  error = latency_plugin_api_hookup (vm);
  
  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (pm, &api_main);
 
  /* Create hashes */
  pm->hash_quic_ports = hash_create(0, sizeof(u16));
  // add ports with swapped bytes!
  hash_set(pm->hash_quic_ports, 20753, 1); // 4433
  // additional ports

  pm->hash_server_ports_to_ips = hash_create(0, sizeof(u32));

  /* Init bihash */
  BV (clib_bihash_init) (&pm->latency_table, "latency", 2048, 512<<20);

  /* Timer wheel has 2048 slots, so we predefine pool with
   * 2048 entries as well */ 
  pool_init_fixed(pm->session_pool, 2048);

  /* Init timer wheel with 100ms resolution */
  tw_timer_wheel_init_2t_1w_2048sl (&pm->tw,
          timer_expired_callback, 100e-3, ~0);
  pm->tw.last_run_time = vlib_time_now (vm);
  
  /* Set counters to zero*/
  pm->total_flows = 0;
  pm->active_flows = 0;

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (latency_init);

/**
 * @brief Hook the LATENCY plugin into the VPP graph hierarchy.
 */
VNET_FEATURE_INIT (latency, static) = 
{
  /* It runs in the device-input arc before the ip4-lookup node */  
  .arc_name = "ip4-unicast",
  .node_name = "latency",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
