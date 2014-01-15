#ifndef _MULEQPKT_H_
#define _MULEQPKT_H_

typedef struct _mule_queued_packet {
  void* fd;
  uint8_t action;
  uint32_t ip4_no;
  uint16_t port_no;
  uint8_t* pkt;
  uint32_t pkt_len;
  uint32_t ts;
} MULE_QUEUED_PACKET;

bool
muleqpkt_alloc(
               uint8_t action,
               uint32_t ip4_no,
               uint16_t port_no,
               uint8_t* pkt,
               uint32_t pkt_len,
               MULE_QUEUED_PACKET** qp_out
              );

bool
muleqpkt_destroy(
                 MULE_QUEUED_PACKET* qp,
                 bool free_data
                );

#endif // _MULEQPKT_H_
