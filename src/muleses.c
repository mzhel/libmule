#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#ifdef CONFIG_VERBOSE
#include <arpa/inet.h>
#endif
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <mule.h>
#include <mulesrc.h>
#include <muleses.h>
#include <mulehlp.h>
#include <muleqpkt.h>
#include <muleproto.h>
#include <pktasm.h>
#include <ticks.h>
#include <random.h>
#include <muledbg.h>
#include <mem.h>
#include <log.h>

bool
mule_session_init(
                  uint16_t tcp_port,
                  MULE_SESSION** ms_out
                 )
{
  bool result = false;
  MULE_SESSION* ms = NULL;

  do {

    if (!ms_out) break;

    ms = (MULE_SESSION*)mem_alloc(sizeof(MULE_SESSION));

    if (!ms){

      LOG_ERROR("Failed to allocate memory for mule session.");

      break;

    }

    strcpy(ms->nick, "muleuser");

    random_init(ticks_now_ms());

    ms->tcp_port = tcp_port;

    for (uint32_t i = 0; i < sizeof(ms->user_hash); i++){

      ms->user_hash.data.byteData[i] = random_uint8();

    }

    ms->user_hash.data.byteData[5] = 14;

    ms->user_hash.data.byteData[14] = 111;

    queue_create(PACKET_QUEUE_LENGTH, &ms->queue_in_pkt);

    queue_create(PACKET_QUEUE_LENGTH, &ms->queue_out_pkt);

    *ms_out = ms;

    result = true;

  } while (false);

  return result;
}


bool
mule_session_uninit(
                    MULE_SESSION* ms
                   )
{
  bool result = false;

  do {

    if (!ms) break;

    mulehlp_destroy_in_pkt_queue(ms);

    mulehlp_destroy_out_pkt_queue(ms);

    mulehlp_destroy_sources_list(ms);

    mem_free(ms);

    result = true;

  } while (false);

  return result;
}

bool
mule_session_set_kad_callbacks(
                               MULE_SESSION* ms,
                               void* kad_session,
                               KAD_CALLBACKS* kcbs
                               )
{
  bool result = false;

  do {

    if (!ms || !kad_session || !kcbs) break;

    ms->kad_session = kad_session;

    memcpy(&ms->kcbs, kcbs, sizeof(KAD_CALLBACKS));

    result = true;

  } while (false);

  return result;
}

bool
mule_session_set_network_callbacks(
                                   MULE_SESSION* ms,
                                   void* net_handle,
                                   MULE_NETWORK_CALLBACKS* ncbs
                                  )
{
  bool result = false;

  do {

    if (!ms || !ncbs) break;

    ms->net_handle = net_handle;

    memcpy(&ms->ncbs, ncbs, sizeof(MULE_NETWORK_CALLBACKS));

    result = true;

  } while (false);

  return result;
}

bool
mule_session_set_cipher_callbacks(
                                  MULE_SESSION* ms,
                                  CIPHER_CALLBACKS* ccbs
                                 )
{
  bool result = false;

  do {

    if (!ms || !ccbs) break;

    memcpy(&ms->ncbs, ccbs, sizeof(CIPHER_CALLBACKS));

    result = true;

  } while (false);

  return result;
}

bool
mule_session_global_source_by_ip_port(
                                      MULE_SESSION* ms,
                                      uint32_t ip4_no,
                                      uint16_t port_no,
                                      MULE_SOURCE** msc_out
                                     )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;
  bool found = true;

  do {

    if (!ms || !msc_out) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->sources, e, msc);

      if (ip4_no == msc->ip4_no && port_no == msc->tcp_port_no){

        found = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!found) break;

    *msc_out = msc;

    result = true;

  } while (false);

  return result;
}

bool
mule_session_global_source_by_fd(
                                 MULE_SESSION* ms,
                                 void* fd,
                                 MULE_SOURCE** msc_out
                                 )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;
  bool found = false;

  do {

    if (!ms || !msc_out) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->sources, e, msc);

      if (fd == msc->fd){

        found = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!found) break;

    *msc_out = msc;

    result = true;

  } while (false);

  return result;
}

bool
mule_session_global_source_by_ip_and_direction(
                                               MULE_SESSION* ms,
                                               uint32_t ip4_no,
                                               uint8_t direction,
                                               MULE_SOURCE** msc_out
                                              )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;
  bool found = true;

  do {

    if (!ms || !msc_out) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->sources, e, msc);

      if (ip4_no == msc->ip4_no && direction == msc->direction){

        found = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!found) break;

    *msc_out = msc;

    result = true;

  } while (false);

  return result;
}


bool
mule_session_add_global_source(
                               MULE_SESSION* ms,
                               MULE_SOURCE* msc
                              )
{
  bool result = false;

  do {

    if (!ms || !msc) break;

    LOG_DEBUG("Adding global source %s:%d", msc->ip4_str, ntohs(msc->tcp_port_no));

    if (!list_add_entry(&ms->sources, msc)){

      LOG_ERROR("Failed to add global source to list.");

      break;

    }

    mule_source_add_type(msc, MULE_SOURCE_FLAG_GLOBAL);

    result = true;

  } while (false);

  return result;
}

bool
mule_session_free_global_sources(
                                 MULE_SESSION* ms
                                )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;

  do {

    if (!ms) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->sources, e, msc);

      mule_source_destroy(msc);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    list_destroy(ms->sources, false);

    ms->sources = NULL;

    result = true;

  } while (false);

  return result;
}

bool
mule_session_create_queue_out_pkt(
                                  MULE_SESSION* ms,
                                  uint8_t action,
                                  uint32_t ip4_no,
                                  uint16_t port_no,
                                  void* fd,
                                  uint8_t* pkt,
                                  uint32_t pkt_len
                                  )
{
  bool result = false;
  MULE_QUEUED_PACKET* qp = NULL;

  do {

    if (!ms) break;

    if (!muleqpkt_alloc(action, ip4_no, port_no, pkt, pkt_len, &qp)){

      LOG_ERROR("Failed to allocate queued packet.");

      break;

    }

    qp->ts = ticks_now_ms();

    qp->fd = fd;

    QUEUE_OUT_PKT(ms, qp); 

    result = true;

  } while (false);

  return result;
}

bool
mule_session_create_queue_in_pkt(
                                 MULE_SESSION* ms,
                                 uint8_t action,
                                 uint32_t ip4_no,
                                 uint16_t port_no,
                                 uint8_t* pkt,
                                 uint32_t pkt_len
                                )
{
  bool result = false;
  MULE_QUEUED_PACKET* qp = NULL;

  do {

    if (!ms) break;

    if (!muleqpkt_alloc(action, ip4_no, port_no, pkt, pkt_len, &qp)){

      LOG_ERROR("Failed to allocate queued packet.");

      break;

    }

    qp->ts = ticks_now_ms();

    QUEUE_IN_PKT(ms, qp); 

    result = true;

  } while (false);

  return result;
}

bool
mule_session_disconnect_inactive_sources(
                                         MULE_SESSION* ms
                                        )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;
  uint32_t now = ticks_now_ms();

  do {

    if (!ms) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->sources, e, msc);

      if (now - msc->last_action_time > MULE_SOURCE_INACTIVITY_TIMEOUT_MS){

        if (msc->state == MULE_SOURCE_STATE_NEW || msc->state == MULE_SOURCE_STATE_CONNECT_QUEUED){

          msc->state = MULE_SOURCE_STATE_CONNECT_FAILED;

          msc->done = true;
                    
        } else if (msc->fd){

          LOG_DEBUG("Queueing disconnect for %s:%d", msc->ip4_str, ntohs(msc->tcp_port_no));

          if (!mule_session_create_queue_out_pkt(
                                                 ms,
                                                 PACKET_ACTION_DISCONNECT,
                                                 msc->ip4_no,
                                                 msc->tcp_port_no,
                                                 msc->fd,
                                                 NULL,
                                                 0
                                                )
          ){

            LOG_ERROR("Failed to queue packet.");

            break;

          }

          msc->state = MULE_SOURCE_STATE_DISCONNECT_QUEUED;

        }

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    result = true;

  } while (false);

  return result;
}

bool
mule_session_remove_disconnected_sources(
                                         MULE_SESSION* ms
                                        )
{
  bool result = false;
  uint8_t action = 0;
  void* arg = NULL;
  MULE_SOURCE* msc = NULL;
  LIST* to_rem_lst = NULL;
  bool remove = false;

  do {

    if (!ms) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->sources, e, msc);

      remove = false;

      if (msc->done){

        if (msc->state == MULE_SOURCE_STATE_DISCONNECTED){

          LOG_DEBUG("Removing disconnected source %s:%d", msc->ip4_str, ntohs(msc->tcp_port_no));

          remove = true;

        } else if (msc->state == MULE_SOURCE_STATE_CONNECT_FAILED){

          LOG_DEBUG("Removing source failed to connect %s", msc->ip4_str);

          remove = true;

        }

        if (remove) list_add_entry(&to_rem_lst, msc);

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(to_rem_lst, e, msc);

      if (list_remove_entry_by_data(&ms->sources, (void*)msc, false)){

          mule_source_dequeue_action(msc, &action, &arg);

          if (msc->last_action == MULE_SOURCE_ACTION_FW_CHECK || action == MULE_SOURCE_ACTION_FW_CHECK){

            if (ms->kad_session && ms->kcbs.kad_fw_dec_checks_running){

                ms->kcbs.kad_fw_dec_checks_running(ms->kad_session);

            }

          } else if (msc->last_action == MULE_SOURCE_ACTION_UDP_FW_CHECK || action == MULE_SOURCE_ACTION_UDP_FW_CHECK){

            if (ms->kad_session && ms->kcbs.kad_fw_dec_checks_running_udp){

              ms->kcbs.kad_fw_dec_checks_running_udp(ms->kad_session);

            }

          }

        mule_source_destroy(msc);

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    result = true;

  } while (false);

  if (to_rem_lst) list_destroy(to_rem_lst, false);

  return result;
}

bool
mule_session_do_source_scheduled_action(
                                        MULE_SESSION* ms,
                                        MULE_SOURCE* msc,
                                        bool* action_done_out,
                                        bool* wait_io_completion_out,
                                        uint32_t* timeout_out,
                                        bool* end_flag_out
                                       )
{
  bool result = false;
  uint8_t action = 0;
  void* arg = NULL;
  bool no_more_actions = true;
  uint32_t timeout = 0;
  uint32_t now = ticks_now_ms();
  bool action_done = false;
  bool wait_io_completion = false;

  do {

    if (!ms || !msc) break;

    if (!mule_source_dequeue_action(msc, &action, &arg)) break; 

    msc->last_action = action;

    no_more_actions = false;

    switch (action) {

      case MULE_SOURCE_ACTION_UDP_FW_CHECK:

       if (!mulehlp_queue_udp_fw_chk_pkt(ms, msc)){

         LOG_ERROR("Failed to queue udp firewall check request packet.");

         break;

       }

       wait_io_completion = true;

       action_done = true;

       timeout = now + SEC2MS(10);

      break;

      case MULE_SOURCE_ACTION_FW_CHECK:

        wait_io_completion = true;

        action_done = true;

        timeout = now + SEC2MS(10);

      break;

    }

    if (action_done_out) *action_done_out = action_done;

    if (wait_io_completion_out) *wait_io_completion_out = wait_io_completion;

    if (timeout_out) *timeout_out = timeout;

    result = true;

  } while (false);

  if (end_flag_out) *end_flag_out = no_more_actions;

  return result;
}

bool
mule_session_manage_sources(
                            MULE_SESSION* ms 
                           )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;
  bool action_queued = false;
  bool all_actions_done = false;
  bool current_action_done = false;
  uint32_t now = ticks_now_ms();
  bool wait_io_completion = false;
  uint32_t  timeout_before_done = false;

  do {

    if (!ms) break;

    LOG_DEBUG("Active sources list:\n");

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(ms->sources, e, msc);

      LOG_DEBUG(
                "Source state for %s:%d (%s) - %s, done = %s, last_action_time = %.8x", 
                msc->ip4_str, 
                ntohs(msc->tcp_port_no), 
                (msc->direction == MULE_SOURCE_DIRECTION_IN?"IN":"OUT"), 
                muledbg_source_state_by_name(msc->state),
                (msc->done == true?"true":"false"),
                msc->last_action_time
               );

      action_queued = false;

      switch (msc->state){

        case MULE_SOURCE_STATE_NEW:

          if (msc->direction == MULE_SOURCE_DIRECTION_OUT){

            LOG_DEBUG(
                      "Queueing connect for %s:%d (%s)", 
                       msc->ip4_str, 
                       ntohs(msc->tcp_port_no), 
                       (msc->direction == MULE_SOURCE_DIRECTION_IN?"IN":"OUT") 
                     );

            if (!mule_session_create_queue_out_pkt(ms, PACKET_ACTION_CONNECT, msc->ip4_no, msc->tcp_port_no, msc->fd, NULL, 0)){

              LOG_ERROR("Failed to queue packet.");

              break;

            }

            msc->state = MULE_SOURCE_STATE_CONNECT_QUEUED;

            action_queued = true;

          }

        break;

        case MULE_SOURCE_STATE_CONNECTED:

          if (msc->direction == MULE_SOURCE_DIRECTION_OUT){

            if (mulehlp_queue_hello_pkt(ms, msc, false)){

              msc->state = MULE_SOURCE_STATE_HELLO_SENT;

              msc->wait_io_completion = true;

            }

            action_queued = true;

          }

        break;

        case MULE_SOURCE_STATE_HELLO_RECEIVED:

          if (msc->direction == MULE_SOURCE_DIRECTION_IN){

            if (mulehlp_queue_hello_pkt(ms, msc, true)){

              msc->state = MULE_SOURCE_STATE_HANDSHAKE_COMPLETED;

              msc->wait_io_completion = true;

              action_queued = true;

            }

          } else if (msc->direction == MULE_SOURCE_DIRECTION_OUT){

            msc->state = MULE_SOURCE_STATE_HANDSHAKE_COMPLETED;

            msc->wait_io_completion = false;

            action_queued = false;

          }

        break;

        case MULE_SOURCE_STATE_HANDSHAKE_COMPLETED:

          if (msc->direction == MULE_SOURCE_DIRECTION_IN){

            msc->wait_io_completion = true;

            action_queued = false;

          } else {

            all_actions_done = false;

            current_action_done = false;

            wait_io_completion = false;

            mule_session_do_source_scheduled_action(
                                                    ms, 
                                                    msc, 
                                                    &current_action_done, 
                                                    &wait_io_completion, 
                                                    &timeout_before_done, 
                                                    &all_actions_done
                                                   );

            if (all_actions_done){

              msc->state = MULE_SOURCE_STATE_ACTION_DONE;

              msc->done = true;

              msc->last_action_time = now;

              break;

            }

            if (current_action_done){

              if (timeout_before_done){

                msc->timeout = timeout_before_done;

                msc->state = MULE_SOURCE_STATE_TIMEOUT_BEFORE_DONE;

              } else {

                msc->state = MULE_SOURCE_STATE_HANDSHAKE_COMPLETED;

              }

            }

            if (wait_io_completion){

              msc->wait_io_completion = true;

              action_queued = true;

            } else {

              msc->done = true;

              msc->last_action_time = now;

            }

          }

        break;

        case MULE_SOURCE_STATE_TIMEOUT_BEFORE_DONE:

          msc->last_action_time = now;

          msc->done = true;

          if (msc->timeout < now){

            msc->timeout = 0;

            msc->state = MULE_SOURCE_STATE_HANDSHAKE_COMPLETED;

          }

        break;

        case MULE_SOURCE_STATE_ACTION_DONE:

          LOG_DEBUG("Queueing disconnect for %s:%d", msc->ip4_str, ntohs(msc->tcp_port_no));

          if (!mule_session_create_queue_out_pkt(
                                                 ms,
                                                 PACKET_ACTION_DISCONNECT,
                                                 msc->ip4_no,
                                                 msc->tcp_port_no,
                                                 msc->fd,
                                                 NULL,
                                                 0
                                                 )
          ){

            LOG_ERROR("Failed to queue packet.");

            break;

          }

          msc->state = MULE_SOURCE_STATE_DISCONNECT_QUEUED;

          action_queued = true;

        break;

      }

      if (action_queued){

        msc->last_action_time = now;

        msc->done = false;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    result = true;

  } while (false);

  return result;
}

bool
mule_session_deq_and_handle_in_qpkt(
                                    MULE_SESSION* ms
                                   )
{
  bool result = false;
  MULE_QUEUED_PACKET* qpkt = NULL;
  MULE_SOURCE* msc = NULL;
  void* pkt_to_free = NULL;
  uint8_t* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ms) break;

    DEQ_IN_PKT(ms, (void**)&qpkt);

    if (!qpkt) break;

    mule_session_global_source_by_ip_port(ms, qpkt->ip4_no, qpkt->port_no, &msc);

    if (!msc) break;

    switch (qpkt->action){

      case PACKET_ACTION_PARSE_DATA:

        pktasm_raw_data((PKT_ASM*)msc->pkt_asm, qpkt->pkt, qpkt->pkt_len);

        while (pktasm_full_packet((PKT_ASM*)msc->pkt_asm, &pkt_to_free, &pkt, &pkt_len)){

          mule_proto_handle_packet(ms, msc, pkt, pkt_len);

          if (msc->wait_io_completion){

            msc->wait_io_completion = false;

            msc->done = true;

          }

          if (pkt_to_free){

            mem_free(pkt_to_free);

            pkt_to_free = NULL;

          }

        }

      break;

    }

    result = true;

  } while (false);

  if (qpkt) muleqpkt_destroy(qpkt, true);

  return result;
}

bool
mule_session_deq_and_handle_out_qpkt(
                                     MULE_SESSION* ms
                                    )
{
  bool result = false;
  MULE_QUEUED_PACKET* qpkt = NULL;  
  MULE_SOURCE* msc = NULL;

  do {

    if (!ms) break;

    DEQ_OUT_PKT(ms, (void**)&qpkt);

    if (!qpkt) break;

    mule_session_global_source_by_ip_port(ms, qpkt->ip4_no, qpkt->port_no, &msc);

    if (!msc) break;

    switch (qpkt->action){

      case PACKET_ACTION_CONNECT:

        if (ms->net_handle && ms->ncbs.connect){

          ms->ncbs.connect(ms->net_handle, qpkt->ip4_no, qpkt->port_no, ms);

        }

      break;

      case PACKET_ACTION_SEND_DATA:

        LOG_DEBUG("Sending packet, handle = %.8x, length = %.8x.", msc->fd, qpkt->pkt_len);

        ms->ncbs.send(msc->fd, qpkt->pkt, qpkt->pkt_len); 

      break;

      case PACKET_ACTION_DISCONNECT:

        LOG_DEBUG("Disconnecting %s:%d, handle = %.8x", msc->ip4_str, ntohs(msc->tcp_port_no), msc->fd);

        ms->ncbs.disconnect(msc->fd);

        mule_session_peer_disconnected(ms, msc->fd);

      break;

    }

    result = true;

  } while (false);

  if (qpkt) muleqpkt_destroy(qpkt, true);

  return result;
}

bool
mule_session_update(
                    MULE_SESSION* ms
                   )
{
  bool result = false;
  uint32_t now = ticks_now_ms();

  do {

    if (!ms) break;

    if (ms->timers.manage_sources <= now){

      mule_session_manage_sources(ms);

      ms->timers.manage_sources = now + SEC2MS(1);

    }

    if (ms->timers.manage_inactive_sources <= now){

      mule_session_disconnect_inactive_sources(ms);

      ms->timers.manage_inactive_sources = now + SEC2MS(5);

    }

    if (ms->timers.remove_disconnected_sources <= now){

      mule_session_remove_disconnected_sources(ms);

      ms->timers.remove_disconnected_sources = now + SEC2MS(5);

    }

    if (ms->timers.handle_in_packets <= now){

      mule_session_deq_and_handle_in_qpkt(ms);

      ms->timers.handle_in_packets = now + 500;

    }

    if (ms->timers.handle_out_packets <= now){

      mule_session_deq_and_handle_out_qpkt(ms);

      ms->timers.handle_out_packets = now + 500;

    }

    result = true;

  } while (false);

  return result;
}

bool
mule_session_new_connection(
                            MULE_SESSION* ms,
                            uint32_t ip4_no,
                            uint16_t port_no,
                            void* fd
                           )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;
  bool source_not_found = false;

  do {
       
    mule_session_global_source_by_ip_and_direction(ms, ip4_no, MULE_SOURCE_DIRECTION_IN, &msc);

    // This situation shouldn't happen, sources for incomming
    // connections always should be added before actual
    // incomming connection hapenning, and if source will be created
    // here port will be set to incomming connection port
    // instead of source listen port which is wrong.
    
    if (!msc){

      source_not_found = true;
    
      mule_source_create(1, NULL, ip4_no, port_no, 0, 0, &msc);

      if (!msc){

        LOG_ERROR("Failed to create source.");

        break;

      }

    }

    msc->state = MULE_SOURCE_STATE_CONNECTED;

    msc->fd = fd;

    msc->done = true;

    if (source_not_found){

      mule_source_set_direction(msc, MULE_SOURCE_DIRECTION_IN);

      if (!mule_session_add_global_source(ms, msc)){

        LOG_ERROR("Failed to add source to global sources list.");

        break;

      }

    }

    result = true;

  } while (false);

  if (!result && source_not_found && msc) mule_source_destroy(msc);

  return result;
}

bool
mule_session_connected_to_peer(
                               MULE_SESSION* ms,
                               uint32_t ip4_no,
                               uint16_t port_no,
                               void* fd
                              )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;

  do {

    if (!ms) break;

    if (!mule_session_global_source_by_ip_port(ms, ip4_no, port_no, &msc)){

      LOG_ERROR("Failed to find source for connection.");

      break;

    }

    msc->state = MULE_SOURCE_STATE_CONNECTED;

    msc->fd = fd;

    msc->done = true;

    result = true;

  } while (false);

  return result;
}

bool
mule_session_peer_disconnected(
                               MULE_SESSION* ms,
                               void* fd
                              )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;

  do {

    if (!ms) break;

    if (!mule_session_global_source_by_fd(ms, fd, &msc)){

      LOG_ERROR("Disconnected source not found in global sources list.");

      break;

    }

    msc->last_action_time = 0;

    msc->state = MULE_SOURCE_STATE_DISCONNECTED;

    msc->done = true;

    msc->fd = NULL;

    result = true;

  } while (false);

  return result;
}

bool
mule_session_data_received(
                           MULE_SESSION* ms,
                           void* fd,
                           uint8_t* data,
                           uint32_t data_len
                          )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;
  uint8_t* pkt = NULL;
  uint32_t pkt_len = 0;

  do {

    if (!ms) break;

    if (!mule_session_global_source_by_fd(ms, fd, &msc)){

      LOG_ERROR("Source not found.");

      break;

    }

    pkt_len = data_len;

    pkt = (uint8_t*)mem_alloc(pkt_len);

    if (!pkt){

      LOG_ERROR("Failed to allocate memory for packet.");

      break;

    }

    memcpy(pkt, data, data_len);

    if (!mule_session_create_queue_in_pkt(
                                          ms,
                                          PACKET_ACTION_PARSE_DATA, 
                                          msc->ip4_no, 
                                          msc->tcp_port_no, 
                                          pkt,
                                          pkt_len
                                         )
    ){

      LOG_ERROR("Failed to queue received data to handle.");

      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
mule_session_add_source_for_udp_fw_check(
                                         MULE_SESSION* ms,
                                         UINT128* id,
                                         uint32_t ip4_no,
                                         uint16_t tcp_port_no,
                                         uint16_t udp_port_no
                                        )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;

  do {

    if (!ms) break;

    if (!mule_source_create(
                            1,
                            id,
                            ip4_no,
                            tcp_port_no,
                            udp_port_no,
                            0,
                            &msc
                           )
    ){

      LOG_ERROR("Failed to create mule source.");

      break;

    }

    mule_source_queue_action(msc, MULE_SOURCE_ACTION_UDP_FW_CHECK, NULL);

    mule_source_set_direction(msc, MULE_SOURCE_DIRECTION_OUT);

    msc->done = true;

    if (!mule_session_add_global_source(ms, msc)){

      LOG_ERROR("Failed to add source to global sources list.");

      break;

    }

    result = true;

  } while (false);

  if (!result && msc) mule_source_destroy(msc);

  return result;
}

bool
mule_session_add_source_for_tcp_fw_check(
                                         MULE_SESSION* ms,
                                         UINT128* id,
                                         uint32_t ip4_no,
                                         uint16_t tcp_port_no,
                                         uint16_t udp_port_no
                                        )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;

  do {

    if (!ms) break;

    if (!mule_source_create(
                            1,
                            id,
                            ip4_no,
                            tcp_port_no,
                            udp_port_no,
                            0,
                            &msc
                           )
    ){

      LOG_ERROR("Failed to create mule source.");

      break;

    }

    mule_source_queue_action(msc, MULE_SOURCE_ACTION_FW_CHECK, NULL);

    mule_source_set_direction(msc, MULE_SOURCE_DIRECTION_IN);

    msc->done = true;

    if (!mule_session_add_global_source(ms, msc)){

      LOG_ERROR("Failed to add source to global sources list.");

      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
mule_session_timer(
                   MULE_SESSION* ms
                  )
{
  bool result = false;

  do {

    result = mule_session_update(ms);

  } while (false);

  return result;
}
