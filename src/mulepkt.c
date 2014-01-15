#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <arpa/inet.h>
#include <uint128.h>
#include <mule.h>
#include <packet.h>
#include <list.h>
#include <queue.h>
#include <tag.h>
#include <taglst.h>
#include <mulesrc.h>
#include <muleses.h>
#include <muleqpkt.h>
#include <mem.h>
#include <log.h>

bool
mulepkt_create_emit(
                    uint8_t proto,
                    uint8_t op,
                    uint8_t* pkt_data,
                    uint32_t pkt_data_len,
                    void** raw_pkt_out,
                    uint32_t* raw_pkt_len_out
                   )
{
  bool result = false;
  KAD_PACKET* kpkt = NULL;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint32_t bytes_emited = 0;

  do {

    if (!raw_pkt_out) break;

    if (!pkt_create(pkt_data, pkt_data_len, proto, op, &kpkt)){

      LOG_ERROR("pkt_create failed.");

      break;

    }

    raw_pkt_len = pkt_length_with_header_emule(kpkt);

    raw_pkt = mem_alloc(raw_pkt_len);

    if (!raw_pkt){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    if (!pkt_emit_emule(kpkt, (uint8_t*)raw_pkt, raw_pkt_len, &bytes_emited)){

      LOG_ERROR("Failed to emit packet to buffer.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    if (raw_pkt_len_out) *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (!result && raw_pkt) mem_free(raw_pkt);

  if (kpkt) pkt_destroy(kpkt);

  return result;
}

bool
mulepkt_create_hello(
                     MULE_SESSION* ms,
                     uint8_t opcode,
                     uint32_t kad_version,
                     uint16_t kad_udp_port,
                     bool kad_fw,
                     bool kad_fw_udp,
                     uint32_t kad_pub_ip4_no,
                     void** raw_pkt_out,
                     uint32_t* raw_pkt_len_out
                    )
{
  bool result = false;
  uint8_t* pkt_data = NULL;
  uint32_t pkt_data_len = 0;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint8_t t_cnt = 0;
  LIST* tl = NULL;
  TAG* t = NULL;
  uint16_t udp_port = 0;
  MULE_MISC_OPTS_1* mmo1 = NULL;   
  MULE_MISC_OPTS_2* mmo2 = NULL;
  uint64_t opts;
  uint32_t t_buf_len = 0;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  uint32_t bytes_emited = 0;

  do {

    if (!ms || !raw_pkt_out || !raw_pkt_len_out) break;

    t_cnt = 7; // Base tag count.

    pkt_data_len = ((opcode == OP_HELLO)?sizeof(uint8_t):0) + // User hash len len
                   sizeof(UINT128) + // User hash len
                   sizeof(uint32_t) + // App id
                   sizeof(uint16_t) + // Tcp port
                   sizeof(uint32_t) + // Server ip
                   sizeof(uint16_t); // Server port

    // Nick

    LOG_DEBUG("CT_NAME: %s", ms->nick); 

    if (!tag_create(TAGTYPE_STRING, CT_NAME, NULL, (uint64_t)ms->nick, &t)){

      LOG_ERROR("Failed to create CT_NAME tag.");

      break;

    }

    tag_list_add(&tl, t);

    // [IMPLEMENT] GetVBTTags ??
    
    // Version
    
    LOG_DEBUG("CT_VERSION: %d", EDONKEYVERSION);

    if (!tag_create(TAGTYPE_UINT8, CT_VERSION, NULL, (uint64_t)EDONKEYVERSION, &t)){

      LOG_ERROR("Failed to create CT_VERSION tag.");

      break;

    }

    tag_list_add(&tl, t);

    // Udp ports, kad and emule.
  
    udp_port = kad_udp_port;

    LOG_DEBUG("CT_EMULE_UDPPORTS: %.8x", (uint32_t)((udp_port << 16) | (udp_port)));
    
    if (!tag_create(TAGTYPE_UINT32, CT_EMULE_UDPPORTS, NULL, (uint32_t)((udp_port << 16) | udp_port), &t)){

      LOG_ERROR("Failed to create CT_EMULE_UDPPORTS tag.");

      break;

    }

    tag_list_add(&tl, t);

    // Emule version
    
    LOG_DEBUG("CT_EMULE_VERSION: %.8x", (SO_AMULE << 24) | MAKE_FULL_ED2K_VERSION(VERSION_MJR, VERSION_MIN, VERSION_UPDATE));

    if (!tag_create(
                    TAGTYPE_UINT32, 
                    CT_EMULE_VERSION, 
                    NULL, 
                    (SO_AMULE << 24) | MAKE_FULL_ED2K_VERSION(VERSION_MJR, VERSION_MIN, VERSION_UPDATE),
                    &t
                    )
                    
    ){

      LOG_ERROR("Failed to create CT_EMULE_VERSION tag.");

      break;

    }

    tag_list_add(&tl, t);

    // Misc opts #1.

    mmo1 = (MULE_MISC_OPTS_1*)mem_alloc(sizeof(MULE_MISC_OPTS_1));

    if (!mmo1){

      LOG_ERROR("Failed to allocate memory for mule misc opts #1.");

      break;

    }

    mmo1->udp_ver = 4;

    mmo1->data_comp_ver = 1;

    mmo1->support_sec_ident = 0; // [IMPLEMENT] identification

    mmo1->source_exchange_ver = 3;

    mmo1->extended_requests_ver = 2;

    mmo1->accept_comment_ver = 1;

    mmo1->no_view_shared_files = 1; // Set to no as negative flag

    mmo1->multi_packet = 1;

    mmo1->support_preview = 0;

    mmo1->peer_cache = 0;

    mmo1->unicode_support = 1;

    mmo1->AICH_ver = 1;

    opts = (mmo1->AICH_ver            << ((4 * 7) + 1)) |
           (mmo1->unicode_support     <<  (4 * 7)) |
           (mmo1->udp_ver             << 4 * 6) |
           (mmo1->data_comp_ver        << 4 * 5) |
           (mmo1->support_sec_ident    << 4 * 4) |
           (mmo1->source_exchange_ver  << 4 * 3) |
           (mmo1->extended_requests_ver << 4 * 2) |
           (mmo1->accept_comment_ver   << 4 * 1) |
           (mmo1->peer_cache          << 1 * 3) |
           (mmo1->no_view_shared_files  << 1 * 2) |
           (mmo1->multi_packet        << 1 * 1) |
           (mmo1->support_preview     << 1 * 0);

    LOG_DEBUG("CT_EMULE_MISCOPTIONS1: %.8x", opts);

    if (!tag_create(TAGTYPE_UINT64, CT_EMULE_MISCOPTIONS1, NULL, opts, &t)){

      LOG_ERROR("Failed to create CT_EMULE_MISCOPTIONS1 tag.");

      break;

    }

    tag_list_add(&tl, t);

    mmo2 = (MULE_MISC_OPTS_2*)mem_alloc(sizeof(MULE_MISC_OPTS_2));

    if (!mmo2){

      LOG_ERROR("Failed to allocate memory for emule misc options #2.");

      break;

    }

    mmo2->kad_version = kad_version;

    mmo2->support_large_files = 1;

    mmo2->ext_multi_packet = 1;

    mmo2->reserved = 0;

    mmo2->supports_crypt_layer = 0; // [IMPLEMENT]: encryption

    mmo2->requests_crypt_layer = 0;

    mmo2->requires_crypt_layer = 0;

    mmo2->supports_source_ex2 = 1;

    mmo2->direct_udp_callback = (kad_fw && !kad_fw_udp)?1:0;

    opts = (mmo2->direct_udp_callback << 12) |
           (mmo2->supports_source_ex2 << 10) |
           (mmo2->requires_crypt_layer << 9) |
           (mmo2->requests_crypt_layer << 8) |
           (mmo2->supports_crypt_layer << 7) |
           (mmo2->reserved  << 6) |
           (mmo2->ext_multi_packet << 5) |
           (mmo2->support_large_files << 4) |
           (mmo2->kad_version << 0);

    LOG_DEBUG("CT_EMULE_MISCOPTIONS2: %.8x", opts);

    if (!tag_create(TAGTYPE_UINT64, CT_EMULE_MISCOPTIONS2, NULL, opts, &t)){

      LOG_ERROR("Failed to create CT_EMULE_MISCOPTIONS2 tag.");

      break;

    }

    tag_list_add(&tl, t);

    LOG_DEBUG("CT_EMULECOMPAT_OPTIONS: %.8x", 1);

    if (!tag_create(TAGTYPE_UINT64, CT_EMULECOMPAT_OPTIONS, 0, 1, &t)){ // OSInfo support is set.

      LOG_ERROR("Failed to create CT_EMULECOMPAT_OPTIONS tag.");

      break;

    }

    tag_list_add(&tl, t);

    if (!tag_list_calc_buffer_length(tl, true, &t_buf_len)){

      LOG_ERROR("Failed to calculate buffer length for tag list.");

      break;

    }

    LOG_DEBUG("Tag list buffer len %.8x", t_buf_len);

    pkt_data_len += t_buf_len;

    rem_len = pkt_data_len;

    p = pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for packet data.");

    }

    LOG_DEBUG("rem_len %.8x", rem_len);

    // Start emiting data to packet.
    
    if (opcode == OP_HELLO){

      *p++ = sizeof(UINT128); // User hash len.

      rem_len -= 1;

    }

    uint128_emit(&ms->user_hash, p, rem_len);

    p += sizeof(UINT128);

    rem_len -= sizeof(UINT128);

    // If kad is firewalled id is 1 else id is ip in network bytes order
    
    *(uint32_t*)p = kad_fw?1:kad_pub_ip4_no;

    p += sizeof(uint32_t);

    rem_len -= sizeof(uint32_t);

    // Tcp port.
    
    *(uint16_t*)p = ms->tcp_port;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // Tags
    
    if (tag_list_emit(tl, p, rem_len, true, &p, &rem_len)){

      LOG_ERROR("Failed to emit tag list.");

      break;

    }

    LOG_DEBUG("rem_len = %.8x", rem_len);

    // Server ip.

    *(uint32_t*)p = 0; // In our case always null.

    p += sizeof(uint32_t);

    rem_len -= sizeof(uint32_t);

    // Server port
    
    *(uint16_t*)p = 0; // Same.

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    LOG_DEBUG("rem_len %.8x", rem_len);

    if (!mulepkt_create_emit(OP_EDONKEYPROT, opcode, pkt_data, pkt_data_len, &raw_pkt, &raw_pkt_len)){

      LOG_ERROR("Failed to emit hello packet.");

      break;

    }

    *raw_pkt_out = raw_pkt; 

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  if (mmo1) mem_free(mmo1);

  if (mmo2) mem_free(mmo2);

  if (tl) list_destroy(tl, true);

  if (pkt_data) mem_free(pkt_data);

  return result;
}

bool
mulepkt_create_udp_fw_check_req_pkt(
                                    MULE_SESSION* ms,
                                    uint16_t int_kad_port,
                                    uint16_t ext_kad_port,
                                    uint32_t verify_key,
                                    void** raw_pkt_out,
                                    uint32_t* raw_pkt_len_out
                                   )
{
  bool result = false;
  uint8_t* pkt_data = NULL;
  uint32_t pkt_data_len = 0;
  void* raw_pkt = NULL;
  uint32_t raw_pkt_len = 0;
  uint32_t rem_len = 0;
  uint8_t* p = NULL;

  do {

    if (!ms || !raw_pkt || !raw_pkt_len) break;

    rem_len  = pkt_data_len = sizeof(uint16_t) + // Internal kad port
                              sizeof(uint16_t) + // External kad port
                              sizeof(uint32_t); // Udp verify key

    p = pkt_data = (uint8_t*)mem_alloc(pkt_data_len);

    if (!pkt_data){

      LOG_ERROR("Failed to allocate memory for packet data.");

      break;

    }

    // Internal kad port
    
    *(uint16_t*)p = int_kad_port;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    // External kad port
    
    *(uint16_t*)p = ext_kad_port;

    p += sizeof(uint16_t);

    rem_len = sizeof(uint16_t);

    // Udp verify key
    
    *(uint32_t*)p = verify_key;

    p += sizeof(uint32_t);

    rem_len -= sizeof(uint32_t);

    if (!mulepkt_create_emit(OP_EMULEPROT, OP_FWCHECKUDPREQ, pkt_data, pkt_data_len, &raw_pkt, &raw_pkt_len)){

      LOG_ERROR("Failed to emit udp firewall check request packet.");

      break;

    }

    *raw_pkt_out = raw_pkt;

    *raw_pkt_len_out = raw_pkt_len;

    result = true;

  } while (false);

  return result;
}
