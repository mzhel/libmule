#ifndef _PKTASM_H_
#define _PKTASM_H_

#define PKT_ASM_STATE_IDLE      0
#define PKT_ASM_STATE_WAIT_HEAD 1
#define PKT_ASM_STATE_WAIT_TAIL 2

typedef struct {
  uint8_t last_pkt_state;
  uint8_t last_pkt_head[6];
  uint8_t head_bytes_rcvd;
  uint8_t* last_pkt;
  uint32_t last_pkt_offset;
  uint32_t pkt_bytes_to_rcv;
  uint32_t pkt_bytes_rcvd;
  QUEUE* pkts;
} PKT_ASM;

bool
pktasm_create(
              PKT_ASM** pa_out
              );

bool
pktasm_destroy(
               PKT_ASM* pa
              );

bool
pktasm_raw_data(
                PKT_ASM* pa,
                uint8_t* data,
                uint32_t len
               );

bool
pktasm_full_packet(
                   PKT_ASM* pa,
                   void** pkt_to_free_out,
                   uint8_t** raw_pkt_out,
                   uint32_t* raw_pkt_len_out
                  );

#endif //_ PKTASM_H_
