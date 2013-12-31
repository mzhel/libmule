#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <list.h>
#include <queue.h>
#include <mem.h>
#include <pktasm.h>
#include <log.h>

bool
pktasm_create(
               PKT_ASM** pa_out
              )
{
  bool result = false;
  PKT_ASM* pa = NULL;

  do {
    
    if (!pa_out) break;

    pa = (PKT_ASM*)mem_alloc(sizeof(PKT_ASM));

    if (!pa){

      LOG_ERROR("Failed to allocate memory for packet assembler.");

      break;

    }

    if (!queue_create(0, &pa->pkts)){

      LOG_ERROR("Failed to create queue.");

      break;

    }

    pa->last_pkt_state = PKT_ASM_STATE_WAIT_HEAD;

    *pa_out = pa;

    result = true;

  } while (false);

  if (!result && pa) pktasm_destroy(pa);

  return result;
}

bool
pktasm_destroy(
                PKT_ASM* pa
               )
{
  bool result = false;
  void* pkt = NULL;

  do {

    if (!pa) break;

    if (pa->pkts){

      while (queue_deq(pa->pkts, &pkt)){

        if (pkt) mem_free(pkt);

      }

      queue_destroy(pa->pkts); // All queued packets will be freed.

    }

    mem_free(pa);

    result = true;

  } while (false);

  return result;
}

bool
pktasm_tail_data(
                 PKT_ASM* pa,
                 uint8_t* data,
                 uint32_t len,
                 uint32_t* copied_out
                )
{
  bool result = false;
  uint32_t copied = 0;
  uint32_t bytes_to_rcv = 0;

  do {

    if (!pa || !data || !copied_out) break;

    if (pa->last_pkt_state == PKT_ASM_STATE_WAIT_TAIL){

      bytes_to_rcv = pa->pkt_bytes_to_rcv - pa->pkt_bytes_rcvd;

      copied = bytes_to_rcv > len?len:bytes_to_rcv;

      memcpy(pa->last_pkt + pa->last_pkt_offset, data, copied);

      pa->last_pkt_offset += copied;

      pa->pkt_bytes_rcvd += copied;

      if (pa->pkt_bytes_to_rcv == pa->pkt_bytes_rcvd){

        queue_enq(pa->pkts, (void*)pa->last_pkt);

        pa->last_pkt_state = PKT_ASM_STATE_WAIT_HEAD;

        pa->head_bytes_rcvd = 0;

        pa->last_pkt = NULL;

        pa->last_pkt_offset = 0;

        pa->pkt_bytes_to_rcv = 0;

        pa->pkt_bytes_rcvd = 0;

      }

    }

    *copied_out = copied;

    result = true;

  } while (false);

  return result;
}

bool
pktasm_raw_data(
                PKT_ASM* pa,
                uint8_t* data,
                uint32_t len
               )
{
  bool result = false;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  uint32_t copy_len = 0;
  uint32_t pkt_len = 0;
  uint32_t copied = 0;

  do {

    if (!pa || !data || !len) break;

    p = data;

    rem_len = len;

    while (rem_len) {

      switch(pa->last_pkt_state) {

        case PKT_ASM_STATE_WAIT_HEAD:

          copy_len = (rem_len > (sizeof(pa->last_pkt_head) - pa->head_bytes_rcvd))?
                     (sizeof(pa->last_pkt_head) - pa->head_bytes_rcvd):
                     rem_len;

          memcpy(pa->last_pkt_head + pa->head_bytes_rcvd, p, copy_len);

          pa->head_bytes_rcvd += copy_len;

          p += copy_len;

          rem_len -= copy_len;

          if (pa->head_bytes_rcvd == sizeof(pa->last_pkt_head)){

            pa->last_pkt_state = PKT_ASM_STATE_WAIT_TAIL;

            pkt_len = *((uint32_t*)(pa->last_pkt_head + 1));

            pa->pkt_bytes_to_rcv = pkt_len - 1;

            pa->pkt_bytes_rcvd = 0;

            pa->last_pkt_offset = 0;

            pa->last_pkt = (uint8_t*)mem_alloc(sizeof(uint32_t) + sizeof(pa->last_pkt_head) + pkt_len - 1);

            // Disposition:
            //
            // raw_pkt_len - 4 bytes.
            //
            // header - 6 bytes;
            //
            // pkt_data - header.length
            //

            if (!pa->last_pkt){

              LOG_ERROR("Failed to allocate memory for packet.");

              break;

            }

            *((uint32_t*)pa->last_pkt) = sizeof(pa->last_pkt_head) + pkt_len - 1;

            pa->last_pkt_offset += sizeof(uint32_t);

            memcpy(pa->last_pkt + pa->last_pkt_offset, pa->last_pkt_head, sizeof(pa->last_pkt_head));

            pa->last_pkt_offset += sizeof(pa->last_pkt_head);

            if (!pa->pkt_bytes_to_rcv){

              // Packet length is zero, so we go to the tail data straight,
              // because there will not be further iterations.
              
              pktasm_tail_data(pa, p, rem_len, &copied);

              p += copied;

              rem_len -= copied;

            }

          }

        break;

        case PKT_ASM_STATE_WAIT_TAIL:

          pktasm_tail_data(pa, p, rem_len, &copied);

          p += copied;

          rem_len -= copied;

        break;

      }

    }

    result = true;

  } while (false);

  return result;
}

bool
pktasm_full_packet(
                   PKT_ASM* pa,
                   void** pkt_to_free_out,
                   uint8_t** raw_pkt_out,
                   uint32_t* raw_pkt_len_out
                  )
{
  bool result = false;
  void* pkt_to_free = NULL;

  do {

    if (!pa || !pkt_to_free_out) break;

    if (!queue_deq(pa->pkts, &pkt_to_free)) break;

    *pkt_to_free_out = pkt_to_free;

    if (raw_pkt_out) *raw_pkt_out = ((uint8_t*)pkt_to_free) + sizeof(uint32_t);

    if (raw_pkt_len_out) *raw_pkt_len_out = *((uint32_t*)pkt_to_free);

    result = true;

  } while (false);


  return result;
}
