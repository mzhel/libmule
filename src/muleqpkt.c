#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <mule.h>
#include <mulesrc.h>
#include <muleses.h>
#include <muleqpkt.h>
#include <mem.h>
#include <log.h>

bool
muleqpkt_alloc(
               uint8_t action,
               uint32_t ip4_no,
               uint16_t port_no,
               uint8_t* pkt,
               uint32_t pkt_len,
               MULE_QUEUED_PACKET** qp_out
              )
{
  bool result = false;
  MULE_QUEUED_PACKET* qp = NULL;

  do {

    if (!qp_out) break;

    qp = (MULE_QUEUED_PACKET*)mem_alloc(sizeof(MULE_QUEUED_PACKET));

    if (!qp){

      LOG_ERROR("Failed to allocate memory for queued packet.");

      break;

    }

    qp->action = action;

    qp->ip4_no = ip4_no;

    qp->port_no = port_no;

    qp->pkt = pkt;

    qp->pkt_len = pkt_len;

    *qp_out = qp;

    result = true;

  } while (false);

  return result;
}

bool
muleqpkt_destroy(
                 MULE_QUEUED_PACKET* qp,
                 bool free_data
                )
{
  bool result = false;

  do {

    if (!qp) break;

    if (free_data && qp->pkt) mem_free(qp->pkt);

    mem_free(qp);

    result = true;

  } while (false);

  return result;
}

