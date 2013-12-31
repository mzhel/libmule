#include <stdint.h>
#include <stdbool.h>
#include <random.h>
#include <ticks.h>
#include <pktasm.h>
#include <mulesrc.h>
#include <mem.h>
#include <list.h>
#include <queue.h>
#include <log.h>

bool
mule_source_create(
                   uint8_t access,
                   UINT128* id,
                   uint32_t ip4_no,
                   uint16_t tcp_port_no,
                   uint16_t udp_port_no,
                   uint8_t cipher_opts,
                   MULE_SOURCE** msc_out
                  )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;

  do {

    if (!msc_out) break;

    msc = mem_alloc(MULE_SOURCE*)mem_alloc(sizeof(MULE_SOURCE));

    if (!msc){

      LOG_ERROR("Failed to allocate memory for mule source.");

      break;

    }

    msc->access = access;

    msc->state = MULE_SOURCE_STATE_NEW;

    msc->done = true;

    queue_create(0, &msc->actions);

    msc->last_action_time = ticks_now_ms();

    if (id) uint128_copy(id, &msc->id);

    msc->ip4_no = ip4_no;

    msc->tcp_port_no = tcp_port_no;

    msc->udp_port_no = udp_port_no;

    msc->cipher_opts = cipher_opts;

    pktasm_create((PKT_ASM**)&msc->pkt_asm);

    *msc_out = msc;

    result = true;

  } while (false);

  if (!result && msc) mule_source_destroy(msc);

  return result;
}

bool
mule_source_destroy(
                    MULE_SOURCE* msc
                   )
{
  bool result = false;

  do {

    if (!msc) break;

    queue_destroy(msc->actions);

    if (msc->dl_info.parts_status) mem_free(ks->dl_info.parts_status);

    if (msc->dl_info.parts_hash) mem_free(ks->dl_info.parts_hash);

    list_destroy(msc->dl_info.req_blocks, true);

    pktasm_destroy((PKT_ASM*)msc->pkt_asm);

    mem_free(msc);

    result = true;

  } while (false);

  return result;
}

bool
mule_source_set_direction(
                          MULE_SOURCE* msc,
                          uint8_t direction
                         )
{
  bool result = false;

  do {

    if (!msc) break;

    msc->direction = direction;

    result = true;

  } while (false);

  return result;
}

bool
mule_source_add_type(
                     MULE_SOURCE* msc,
                     uint8_t type
                    )
{
  bool result = false;

  do {

    if (!msc) break;

    msc->type |= type;

    result = true;

  } while (false);

  return result;
}

bool
mule_source_remove_type(
                        MULE_SOURCE* msc,
                        uint8_t type
                       )
{
  bool result = false;

  do {

    if (!msc) break;

    msc->type &= ~type;

    result = true;

  } while (false);

  return result;
}

bool
mule_source_type_set(
                     MULE_SOURCE* msc,
                     uint8_t type
                    )
{
  bool result = false;

  do {

    if (!msc || !(msc->type & flag)) break;

    result = true;

  } while (false);

  return result;
}

bool
mule_source_copy(
                 MULE_SOURCE* msc_src,
                 MULE_SOURCE** msc_dst_out
                )
{
  bool result = false;
  MULE_SOURCE* msc_dst = NULL;

  do {

    if (!msc_src || !msc_dst_out) break;

    if (!mule_source_create(
                            msc_src->access,
                            &msc_src->id,
                            msc_src->ip4_no,
                            msc_src->tcp_port_no,
                            msc_src->udp_port_no,
                            msc_src->cipher_opts,
                            &msc_dst
                           )
    ){

      LOG_ERROR("Failed to create kad source.");

      break;

    }

    *msc_dst_out = msc_dst;

    result = true;

  } while (false);

  return result;
}

bool
mule_source_new_download(
                         MULE_SOURCE* msc,
                         MULE_FILE* mf
                        )
{
  bool result = false;

  do {

    if (!msc || !mf) break;

    if (msc->dl_info.parts_status) mem_free(msc->dl_info.parts_status);

    if (msc->dl_info.parts_hash) mem_free(msc->dl_info.parts_hash);

    memset(&msc->dl_info, 0, sizeof(msc->dl_info));

    msc->dl_info.sent_part.state = MULE_PART_STATE_WAIT_HEAD;

    msc->dl_info.file = mf;

    msc->dl_info.state = MULE_SOURCE_DL_STATE_INFO_EXCHANGE;

    // If whole file length is lesser than size of one part
    // we assume there is at least one part available on the source.
    
    if (mf->size < mf->part_size){

      msc->dl_info.parts_status = (uint8_t*)mem_alloc(sizeof(uint8_t));

      if (!msc->dl_info.parts_status){

        LOG_ERROR("Failed to allocate memory parts status.");

        break;

      }

      *msc->dl_info.parts_status = 1;

      msc->dl_info.parts_status_bytes = 1;

    }

    result = true;

  } while (false);

  return result;
}

bool
mule_source_set_up_down_parts_info(
                                   MULE_SOURCE* msc,
                                   bool all_parts,
                                   uint8_t* parts,
                                   uint32_t parts_len,
                                   uint16_t parts_count
                                  )
{
  bool result = false;
  uint32_t copy_len = 0;

  do {

    if (!msc) break;

    msc->dl_info.parts_count = parts_count;

    if (all_parts){

      msc->dl_info.all_parts = all_parts;

      if (msc->dl_info.parts_status) mem_free(msc->dl_info.parts_status);

      msc->dl_info.parts_status_bytes = 0;

    } else {

      if (!parts) break;

      if (!msc->dl_info.parts_status){

        msc->dl_info.parts_status = (uint8_t*)mem_alloc(parts_len);

        if (!msc->dl_info.parts_status){

          LOG_ERROR("Failed to allocate memory for parts status.");

          break;

        }

        msc->dl_info.parts_status_bytes = parts_len;

      }

      copy_len = parts_len > ksc->dl_info.parts_status_bytes?ksc->dl_info.parts_status_bytes:parts_len;

      memcpy(ksc->dl_info.parts_status, parts, copy_len);

    }

    result = true;

  } while (false);

  return result;
}

bool
mule_source_get_part_to_download(
                                 MULE_SOURCE* msc,
                                 MULE_FILE* mf,
                                 uint64_t* part_start_out,
                                 uint64_t* part_len_out
                                )
{
  bool result = false;

  do {

    if (!msc || !mf) break;



    result = true;

  } while (false);

  return result;
}

bool
mule_source_set_cipher(
                       MULE_SOURCE* msc
                      )
{
  bool result = false;
  uint8_t hash_byte_str[16] = {0};
  uint32_t rand_part = 0;
  uint8_t key_data[21] = {0};
  uint8_t* p = NULL;
  uint8_t md5_dgst[16] = {0};

  do {

    if (!msc) break;

    uint128_emit_be(&msc->id, hash_byte_str, sizeof(hash_byte_str));

    rand_part = random_uint32();

    memcpy(key_data, hash_byte_str, sizeof(hash_byte_str));

    p = key_data + 17;

    *(uint32_t*)p = rand_part;

    // Calculate send key.
    
    key_data[16] = MAGIC_VALUE_REQUESTER;

    md5(key_data, sizeof(key_data), md5_dgst);

    memcpy(msc->send_buf_key, key_data, sizeof(msc->send_buf_key));

    // Calculate receive key.
    
    key_data[16] = MAGIC_VALUE_SERVER;

    md5(key_data, sizeof(key_data), md5_dgst);

    memcpy(msc->recv_buf_key, key_data, sizeof(msc->recv_buf_key));

    result = true;

  } while (false);

  return result;
}

bool
mule_source_queue_action(
                         MULE_SOURCE* msc,
                         uint8_t type,
                         void* arg
                        )
{
  bool result = false;
  MULE_SOURCE_ACTION* msca = NULL;

  do {

    if (!msc) break;

    msca = (MULE_SOURCE_ACTION*)mem_alloc(sizeof(MULE_SOURCE_ACTION));

    if (!msca){

      LOG_ERROR("Failed to allocate memory for source action.");

      break;

    }

    msca->type = type;

    msca->arg = arg;

    MULE_SOURCE_ACTIONS_LOCK(msc);

    queue_enq(msc->actions, (void*)msca);

    MULE_SOURCE_ACTIONS_UNLOCK(msc);

    result = true;

  } while (false);

  if (!result && msca) mem_free(msca);

  return result;
}

bool
mule_source_dequeue_action(
                           MULE_SOURCE* msc,
                           uint8_t* action_out,
                           void** arg_out
                          )
{
  bool result = false;
  MULE_SOURCE_ACTION* msca = NULL;

  do {

    if (!msc) break;

    MULE_SOURCE_ACTIONS_LOCK(msc);

    queue_deq(msc->actions, (void**)&msca);

    if (!msca) break;

    if (action_out) *action_out = msca->type;

    if (arg_out) *arg_out = msca->arg;

    mem_free(msca);

    result = true;

  } while (false);

  if (msc) MULE_SOURCE_ACTIONS_UNLOCK(msc);

  return result;
}
