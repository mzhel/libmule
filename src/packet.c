#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <packet.h>
#include <mem.h>
#include <log.h>

bool
pkt_create(
           uint8_t* data,
           uint32_t data_size,
           uint8_t proto,
           uint8_t opcode,
           KAD_PACKET** pkt_out
           )
{
  bool result = false;
  KAD_PACKET* pkt = NULL;

  do {

    if (data_size && !data) break;

    pkt = (KAD_PACKET*)mem_alloc(data_size + (sizeof(KAD_PACKET) - 1));

    if (!pkt){

      LOG_ERROR("Failed to allocate memory for kad packet.");

      break;

    }

    pkt->proto = proto;

    pkt->opcode = opcode;

    pkt->data_size = data_size;

    memcpy(pkt->data, data, data_size);

    *pkt_out = pkt;

    result = true;

  } while (false);

  return result;
}

bool
pkt_destroy(
            KAD_PACKET* pkt
            )
{
  bool result = false;

  do {

    if (!pkt) break;

    mem_free(pkt);

    result = true;

  } while (false);

  return result;

}

bool
pkt_emit_internal(
                  uint8_t emit_type,
                  KAD_PACKET* kp,
                  uint8_t* buf,
                  uint32_t buf_len,
                  uint32_t* bytes_copied_out
                 )
{
  bool result = false;
  uint8_t* p = NULL;

  do {

    if (!kp || !buf || !buf_len) break;

    if (pkt_length_with_header_internal(emit_type, kp) > buf_len) {

      LOG_ERROR("Insufficient size of buffer");

      break;

    }

    p = buf;

    *p++ = kp->proto;

    if (emit_type == PACKET_EMIT_TYPE_TCP){

      *((uint32_t*)p) = kp->data_size + 1;

      p += sizeof(uint32_t);

    }

    *p++ = kp->opcode;

    memcpy(p, kp->data, kp->data_size);

    if (bytes_copied_out) *bytes_copied_out = ((emit_type == PACKET_EMIT_TYPE_UDP)?2:6) + kp->data_size;

    result = true;

  } while (false);

  return result;
}
