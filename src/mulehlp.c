#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <list.h>
#include <queue.h>
#include <uint128.h>
#include <mule.h>
#include <mulefile.h>
#include <mulesrc.h>
#include <muleses.h>
#include <muleqpkt.h>
#include <mulepkt.h>
#include <mem.h>
#include <log.h>

bool
mulehlp_get_kad_info(
                     MULE_SESSION* ms,
                     KAD_STATUS* kss
                    )
{
  bool result = false;

  do {

    if (!ms || !kss) break;

    if (!ms->kad_session || !ms->kcbs.kad_get_status) break;

    result = ms->kcbs.kad_get_status(ms->kad_session, kss);

  } while (false);

  return result;
}

bool
mulehlp_calc_udp_verify_key(
                            MULE_SESSION* ms,
                            uint32_t ip4_no,
                            uint32_t* verify_key_out 
                           )
{
  bool result = false;

  do {

    if (!ms || !verify_key_out) break;

    if (!ms->kad_session || !ms->kcbs.kad_calc_verify_key) break;

    result = ms->kcbs.kad_calc_verify_key(ms->kad_session, ip4_no, verify_key_out);

  } while (false);

  return result;
}

bool
mulehlp_destroy_in_pkt_queue(
                             MULE_SESSION* ms
                            )
{
  bool result = false;
  MULE_QUEUED_PACKET* qpkt = NULL;

  do {

    if (!ms) break;

    do {

      qpkt = NULL;

      DEQ_IN_PKT(ms, (void**)&qpkt);

      if (!qpkt) break;

      muleqpkt_destroy(qpkt, true);

    } while (true);

    queue_destroy(ms->queue_in_pkt);

    result = true;

  } while (false);

  return result;
}

bool
mulehlp_destroy_out_pkt_queue(
                              MULE_SESSION* ms
                             )
{
  bool result = false;
  MULE_QUEUED_PACKET* qpkt = NULL;

  do {

    if (!ms) break;

    do {

      qpkt = NULL;

      DEQ_OUT_PKT(ms, (void**)&qpkt);

      if (!qpkt) break;

      muleqpkt_destroy(qpkt, true);

    } while (true);

    queue_destroy(ms->queue_out_pkt);

    result = true;

  } while (false);

  return result;
}

bool
mulehlp_destroy_sources_list(
                             MULE_SESSION* ms
                            )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;

  do {

    if (!ms) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->sources, e, msc);

      if (msc->fd) ms->ncbs.disconnect(msc->fd);

      mule_source_destroy(msc);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    list_destroy(ms->sources, false);

    result = true;

  } while (false);

  return result;
}

bool
mulehlp_destroy_pub_files_list(
                               MULE_SESSION* ms
                              )
{
  bool result = false;
  MULE_FILE* mf = NULL;

  do {

    if (!ms) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->pub_files, e, mf);

      mule_file_destroy(mf);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    list_destroy(ms->pub_files, false);

    result = true;

  } while (false);

  return result;
}

bool
mulehlp_queue_hello_pkt(
                        MULE_SESSION* ms,
                        MULE_SOURCE* msc,
                        bool answer
                       )
{
  bool result = false;
  KAD_STATUS kss;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ms || !msc) break;

    memset(&kss, 0, sizeof(kss));

    if (ms->kad_session && ms->kcbs.kad_get_status){

      ms->kcbs.kad_get_status(ms->kad_session, &kss);

    }

    if (!mulepkt_create_hello(
                              ms,
                              answer?OP_HELLOANSWER:OP_HELLO,
                              kss.version,
                              kss.udp_port,
                              kss.fw,
                              kss.fw_udp,
                              kss.pub_ip4_no,
                              &pkt,
                              &pkt_len
                             )
    ){

      LOG_ERROR("Failed to create hello packet.");

      break;

    }

    result = mule_session_create_queue_out_pkt(
                                               ms,
                                               PACKET_ACTION_SEND_DATA,
                                               msc->ip4_no,
                                               msc->tcp_port_no,
                                               msc->fd,
                                               pkt,
                                               pkt_len
                                              );

  } while (false);

  return result;
}

bool
mulehlp_queue_udp_fw_chk_pkt(
                             MULE_SESSION* ms,
                             MULE_SOURCE* msc
                            )
{
  bool result = false;
  KAD_STATUS kss;
  uint32_t udp_verify_key = 0;
  void* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ms || !msc) break;

    memset(&kss, 0, sizeof(kss));

    mulehlp_get_kad_info(ms, &kss);

    mulehlp_calc_udp_verify_key(ms, msc->ip4_no, &udp_verify_key);

    LOG_DEBUG("int_port %d, ext_port %d, verify_key %.8x", kss.udp_port, kss.ext_udp_port, udp_verify_key);

    if (!mulepkt_create_udp_fw_check_req_pkt(ms, kss.udp_port, kss.ext_udp_port, udp_verify_key, &pkt, &pkt_len)){

      LOG_ERROR("Failed to create udp firewall check request packet.");

      break;

    }
    
    result = mule_session_create_queue_out_pkt(
                                               ms,
                                               PACKET_ACTION_SEND_DATA,
                                               msc->ip4_no,
                                               msc->tcp_port_no,
                                               msc->fd,
                                               pkt,
                                               pkt_len
                                              );

  } while (false);

  return result;
}

bool
mulehlp_queue_file_request_pkt(
                               MULE_SESSION* ms,
                               MULE_SOURCE* msc,
                               MULE_FILE* mf,
                               uint32_t* sent_flags_out
                              )
{
  bool result = false;
  void* pkt = NULL;
  uint32_t pkt_len = 0;
  uint32_t sent_flags = 0;

  do {

    if (msc->info.misc_opts_1.multi_packet){

      if (!mulepkt_create_mp_file_request(msc, mf, &pkt, &pkt_len, &sent_flags)){

        LOG_ERROR("Failed to create multi packet file request.");

        break;

      }

      result = mule_session_create_queue_out_pkt(
                                                 ms,
                                                 PACKET_ACTION_SEND_DATA,
                                                 msc->ip4_no,
                                                 msc->tcp_port_no,
                                                 msc->fd,
                                                 pkt,
                                                 pkt_len
                                                );
    } else {

      // OP_REQUESTFILENAME

      if (!mulepkt_create_file_name_request(msc, mf, &pkt, &pkt_len)){

        LOG_ERROR("Failed to create request file name packet.");

        break;

      }

      if (!mule_session_create_queue_out_pkt(
                                             ms,
                                             PACKET_ACTION_SEND_DATA,
                                             msc->ip4_no,
                                             msc->tcp_port_no,
                                             msc->fd,
                                             pkt,
                                             pkt_len
                                            )
      ){

        LOG_ERROR("Failed to queue tcp packet.");

        break;

      }

      sent_flags |= MULE_SOURCE_FLAG_FILE_NAME;

      if (mf->part_count > 1){

        // OP_SETREQFILEID
      
        if (!mulepkt_create_file_hash_set_request(msc, mf, &pkt, &pkt_len)){

          LOG_ERROR("Failed to create file hash set request packet.");

          break;

        }

        if (!mule_session_create_queue_out_pkt(
                                               ms,
                                               PACKET_ACTION_SEND_DATA,
                                               msc->ip4_no,
                                               msc->tcp_port_no,
                                               msc->fd,
                                               pkt,
                                               pkt_len
                                              )
        ){

          LOG_ERROR("Failed to queue tcp packet.");

          break;

        }

        sent_flags |= MULE_SOURCE_FLAG_FILE_STATUS;

      }

      if (msc->info.misc_opts_1.AICH_ver & 1){

        // OP_AICHFILEHASHREQ
        
        if (!mule_pkt_create_AICH_request(msc, mf, &pkt, &pkt_len)){

          LOG_ERROR("Failed to create file AICH request packet.");

          break;

        }

        if (!mule_session_create_queue_out_pkt(
                                               ms,
                                               PACKET_ACTION_SEND_DATA,
                                               msc->ip4_no,
                                               msc->tcp_port_no,
                                               msc->fd,
                                               pkt,
                                               pkt_len
                                              )
        ){

          LOG_ERROR("Failed to queue tcp packet.");

          break;

        }

        sent_flags |= MULE_SOURCE_FLAG_AICH_HASH;

      }

    }

    *sent_flags_out = sent_flags;

    result = true;

  } while (false);

  return result;
}

bool
mulehlp_pub_file_by_id(
                       MULE_SESSION* ms,
                       UINT128* id,
                       MULE_FILE** mf_out
                      )
{
  bool result = false;
  MULE_FILE* mf = NULL;
  bool found = false;

  do {

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->pub_files, e, mf);

      if (0 == uint128_compare(id, &mf->id)){

        if (mf_out) *mf_out = mf;

        found = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!found) break;

    result = true;

  } while (false);

  return result;
}
