#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <arpa/inet.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <mule.h>
#include <mulefile.h>
#include <mulesrc.h>
#include <muleses.h>
#include <muleqpkt.h>
#include <mulehlp.h>
#include <tag.h>
#include <ticks.h>
#include <random.h>
#include <mem.h>
#include <log.h>

bool
mule_proto_hello(
                 MULE_SESSION* ms,
                 MULE_SOURCE* msc,
                 bool answer,
                 uint8_t* pkt,
                 uint32_t pkt_len
                )
{
  bool result = false;
  uint32_t rem_len = 0;
  uint32_t tag_count = 0;
  uint32_t tag_id = 0;
  TAG* tag = NULL;
  uint32_t tag_len = 0;
  bool parse_error = false;
  uint64_t int_val = 0;
  bool is_emule = false;
  uint8_t* p = NULL; 

  do {

    if (!ms || !msc) break;

    p = pkt;

    rem_len = pkt_len;

    // User hash len

    if (!answer){

      if (*p++ != MULE_SOURCE_USER_HASH_LEN) break;

      rem_len -= 1;

    }

    // User hash
    
    memcpy(msc->info.user_hash, p, sizeof(msc->info.user_hash));

    p += sizeof(msc->info.user_hash);

    // User id
    
    msc->info.user_id = *(uint32_t*)p;

    p += sizeof(uint32_t);

    rem_len -= sizeof(uint32_t);

    // Tcp port
    
    msc->info.tcp_port = *(uint16_t*)p;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // Tag count
    
    tag_count = *(uint32_t*)p;

    p += sizeof(uint32_t);

    rem_len -= sizeof(uint32_t);

    while (tag_count--) {

      if (!tag_read(p, rem_len, true, &tag, &p, &tag_len)){

        LOG_ERROR("Failed to read tag.");

        parse_error = true;

        break;

      }

      rem_len -= tag_len;

      if (!tag_get_id(tag, &tag_id)){

        LOG_ERROR("Failed to get tag id.");

        parse_error = true;

        break;

      }

      int_val = 0;

      switch (tag_id){

        case CT_NAME:

          tag_string_get_data(tag, (uint8_t*)msc->info.user_name, sizeof(msc->info.user_name));

          LOG_DEBUG("CT_NAME: %s", msc->info.user_name);

        break;

        case CT_VERSION:

          tag_get_integer(tag, &int_val);

          msc->info.donkey_ver = (uint32_t)int_val;

          LOG_DEBUG("CT_VERSION: %d", msc->info.donkey_ver);

        break;

        case CT_EMULE_UDPPORTS:

          tag_get_integer(tag, &int_val);

          LOG_DEBUG("CT_EMULE_UDP_PORTS: %.8x", (uint32_t)int_val);

          msc->udp_port_no = htons((uint16_t)((int_val >> 16) & 0xffff));

          msc->info.udp_port = (uint16_t)int_val;

        break;

        // [IMPLEMENT] buddy tags parsing
        
        case CT_EMULE_MISCOPTIONS1:

          tag_get_integer(tag, &int_val);

          LOG_DEBUG("CT_EMULE_MISCOPTIONS1: %.8x", (uint32_t)int_val);

          msc->info.misc_opts_1.AICH_ver = (int_val >> (4 * 7 + 1)) & 0x07;

          msc->info.misc_opts_1.unicode_support = (int_val >> (4 * 7)) & 0x01;

          msc->info.misc_opts_1.udp_ver = (int_val >> (4 * 6)) & 0x0f;

          msc->info.misc_opts_1.data_comp_ver = (int_val >> (4 * 5)) & 0x0f;

          msc->info.misc_opts_1.support_sec_ident = (int_val >> (4 * 4)) & 0x0f;

          msc->info.misc_opts_1.source_exchange_ver = (int_val >> (4 * 3)) & 0x0f;

          msc->info.misc_opts_1.extended_requests_ver = (int_val >> (4 * 2)) & 0x0f;

          msc->info.misc_opts_1.accept_comment_ver = (int_val >> (4 * 1)) & 0x0f;

          msc->info.misc_opts_1.no_view_shared_files = (int_val >> (1 * 2)) & 0x01;

          msc->info.misc_opts_1.multi_packet = (int_val >> (1 * 1)) & 0x01;

          msc->info.misc_opts_1.support_preview = (int_val >> 1 * 0) & 0x01;

        break;

        case CT_EMULE_MISCOPTIONS2:

          tag_get_integer(tag, &int_val);

          LOG_DEBUG("CT_EMULE_MISCOPTIONS2: %.8x", int_val);

          msc->info.misc_opts_2.direct_udp_callback = (int_val >> 12) & 0x01;

          msc->info.misc_opts_2.supports_source_ex2 = (int_val >> 10) & 0x01;

          msc->info.misc_opts_2.requires_crypt_layer = (int_val >> 9) & 0x01;

          msc->info.misc_opts_2.requests_crypt_layer = (int_val >> 8) & 0x01;

          msc->info.misc_opts_2.supports_crypt_layer = (int_val >> 7) & 0x01;

          msc->info.misc_opts_2.ext_multi_packet = (int_val >> 5) & 0x01;

          msc->info.misc_opts_2.support_large_files = (int_val >> 4) & 0x01;

          msc->info.misc_opts_2.kad_version = int_val & 0x0f;

          msc->info.misc_opts_2.requests_crypt_layer &= msc->info.misc_opts_2.supports_crypt_layer;

          msc->info.misc_opts_2.requires_crypt_layer &= msc->info.misc_opts_2.requests_crypt_layer;

        break;

        case CT_EMULECOMPAT_OPTIONS:

          tag_get_integer(tag, &int_val);

          LOG_DEBUG("CT_EMULECOMPAT_OPTIONS: %.8x", (uint32_t)int_val);

          msc->info.compat_opts.value_based_type_tags = (int_val >> (1 * 1)) & 0x01;

          msc->info.compat_opts.os_info_support = (int_val >> (1 * 0)) & 0x01;

        break;

        case CT_EMULE_VERSION:

          tag_get_integer(tag, &int_val);

          LOG_DEBUG("CT_EMULE_VERSION: %.8x", (uint32_t)int_val);

          msc->info.compatible_client = (uint32_t)(int_val >> 24);

          msc->info.client_version = int_val & 0xffffff;

          msc->info.emule_version = 0x99; // [WHY]

          msc->info.shared_dirs = 1;

          is_emule = true;

        break;

      }

      tag_destroy(tag);

    }

    // Not needing server ip:port hence skip them.
    
    p += 6;

    rem_len -= 6;

    LOG_DEBUG("rem_len %.8x", rem_len);

    msc->info.info_packets_received |= IP_EDONKEYPROTPACK;

    if (is_emule) msc->info.info_packets_received |= IP_EMULEPROTPACK;

    result = true;

  } while (false);

  return result;
}

bool
mule_proto_udp_fw_check_req(
                            MULE_SESSION* ms,
                            MULE_SOURCE* msc,
                            uint8_t* pkt,
                            uint32_t pkt_len
                           )
{
  bool result = false;
  uint16_t int_port = 0;
  uint16_t ext_port = 0;
  uint32_t key = 0;
  uint32_t rem_len = 0;
  uint8_t* p = NULL;
  bool already_known = false; // [IMPLEMENT] For now always false
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  bool queued = false;

  do {

    if (!ms) break;

    p = pkt;

    rem_len = pkt_len;

    // Internal kad udp port
    
    int_port = *(uint16_t*)p;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // External kad udp port

    ext_port = *(uint16_t*)p;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // Sender udp key
    
    key = *(uint32_t*)p;

    p += sizeof(uint32_t);

    rem_len -= sizeof(uint32_t);

    if (int_port == 0){

      LOG_ERROR("Internal udp port is set to 0, no kad packet will be send.");

      break;

    }

    // Two packets will be send, one for internal and one for external kad udp ports.

    if (ms->kad_session && ms->kcbs.kad_send_fw_check_udp){

      ms->kcbs.kad_send_fw_check_udp(
                                     ms->kad_session,
                                     int_port,
                                     key,
                                     msc->ip4_no
                                    );

      ms->kcbs.kad_send_fw_check_udp(
                                     ms->kad_session,
                                     ext_port,
                                     key,
                                     msc->ip4_no
                                    );
    }

    result = true;

  } while (false);

  return result;
}

bool
mule_proto_file_name_answer(
                            MULE_SOURCE* msc,
                            uint8_t buffer,
                            uint32_t len,
                            uint32_t* parsed_len_out
                           )
{
  bool result = false;

  do {

    if (!msc || !buffer) break;

    result = true;

  } while (false);

  return result;
}

bool
mule_proto_file_status(
                       MULE_SOURCE* msc,
                       uint8_t buffer,
                       uint32_t len,
                       uint32_t* parsed_len_out
                      )
{
  bool result = false;

  do {

  result = true;

  } while (false);

  return result;
}

bool
mule_proto_handle_donkey_packet(
                                MULE_SESSION* ms,
                                MULE_SOURCE* msc,
                                uint8_t* raw_pkt,
                                uint32_t raw_pkt_len
                               )
{
  bool result = false;
  uint8_t* pkt = NULL;
  uint32_t pkt_len = 0;
  uint8_t op = 0;
  bool answer = true;

  do {

    if (!ms) break;

    op = raw_pkt[5];

    pkt = raw_pkt + 6;

    pkt_len = *((uint32_t*)(raw_pkt + 1)) - 1; // minus one because encoded packet length include opcode byte

    if (!msc && op != OP_HELLO){

      LOG_WARN("Packet for unknown source, not handling it.");

      break;

    }

    switch (op) {

      case OP_HELLO:

        answer = false;

      case OP_HELLOANSWER:

        LOG_DEBUG("%s", answer?"OP_HELLOANSWER":"OP_HELLO");

        if (!mule_proto_hello(ms, msc, answer, pkt, pkt_len)) break;

        if (msc->udp_port_no && ms->kcbs.kad_bootstrap_from_node){

          ms->kcbs.kad_bootstrap_from_node(ms->kad_session, msc->ip4_no, msc->udp_port_no);

        }

        msc->state = MULE_SOURCE_STATE_HELLO_RECEIVED;

        msc->done = true;

      break;

      case OP_REQFILENAMEANSWER:

        

      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
mule_proto_handle_ext_packet(
                             MULE_SESSION* ms,
                             MULE_SOURCE* msc,
                             uint8_t* raw_pkt,
                             uint32_t raw_pkt_len
                            )
{
  bool result = false;
  uint8_t op = 0;
  uint8_t* pkt = NULL;
  uint32_t pkt_len = 0;


  do {

    if (!ms || !msc || !raw_pkt || !raw_pkt_len) break;

    op = raw_pkt[5];

    pkt_len = *((uint32_t*)(raw_pkt + 1)) - 1; // minus one because encoded packet length includes opcode byte.

    pkt = raw_pkt + 6;

    switch (op){

      case OP_FWCHECKUDPREQ:

        result = mule_proto_udp_fw_check_req(ms, msc, pkt, pkt_len);

      break;

      case OP_KAD_FWTCPCHECK_ACK:

        if (ms->kad_session && ms->kcbs.kad_fw_check_response) ms->kcbs.kad_fw_check_response(ms->kad_session);

        msc->state = MULE_SOURCE_STATE_ACTION_DONE;

        msc->done = true;
        
      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
mule_proto_handle_packet(
                         MULE_SESSION* ms,
                         MULE_SOURCE* msc,
                         uint8_t* raw_pkt,
                         uint32_t raw_pkt_len
                        )
{
  bool result = false;
  uint8_t proto = 0;

  do {

    proto = raw_pkt[0];

    switch (proto) {

      case OP_EDONKEYPROT:

        result = mule_proto_handle_donkey_packet(ms, msc, raw_pkt, raw_pkt_len);

      break;

      case OP_EMULEPROT:

        result = mule_proto_handle_ext_packet(ms, msc, raw_pkt, raw_pkt_len);

      break;

    }

    result = true;

  } while (false);

  return result;
}
