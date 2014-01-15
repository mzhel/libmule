#ifndef _PACKET_H_
#define _PACKET_H_

// opcodes

#define KADEMLIA_BOOTSTRAP_REQ      0x00
#define KADEMLIA_BOOTSTRAP_RES      0x08
#define KADEMLIA_HELLO_REQ          0x10
#define KADEMLIA_HELLO_RES          0x18
#define KADEMLIA_REQ                0x20
#define KADEMLIA_RES                0x28
#define KADEMLIA_SEARCH_REQ         0x30
#define KADEMLIA_SEARCH_NOTES_REQ   0x32
#define KADEMLIA_SEARCH_RES         0x38
#define KADEMLIA_SEARCH_NOTES_RES   0x3a
#define KADEMLIA_PUBLISH_REQ        0x40
#define KADEMLIA_PUBLISH_NOTES_REQ  0x42
#define KADEMLIA_PUBLISH_RES        0x48
#define KADEMLIA_PUBLISH_NOTES_RES  0x4a
#define KADEMLIA_FIREWALLED_REQ     0x50
#define KADEMLIA_FINDBUDDY_REQ      0x51
#define KADEMLIA_CALLBACK_REQ       0x52
#define KADEMLIA_FIREWALLED_RES     0x58
#define KADEMLIA_FIREWALLED_ACK_RES 0x59
#define KADEMLIA_FINDBUDDY_RES      0x5a

// kad v2

#define KADEMLIA2_BOOTSTRAP_REQ     0x01
#define KADEMLIA2_BOOTSTRAP_RES     0x09
#define KADEMLIA2_HELLO_REQ         0x11
#define KADEMLIA2_HELLO_RES         0x19
#define KADEMLIA2_REQ               0x21
#define KADEMLIA2_HELLO_RES_ACK     0x22
#define KADEMLIA2_RES               0x29
#define KADEMLIA2_SEARCH_KEY_REQ    0x33
#define KADEMLIA2_SEARCH_SOURCE_REQ 0x34
#define KADEMLIA2_SEARCH_NOTES_REQ  0x35
#define KADEMLIA2_SEARCH_RES        0x3b
#define KADEMLIA2_PUBLISH_KEY_REQ   0x43
#define KADEMLIA2_PUBLISH_SOURCE_REQ 0x44
#define KADEMLIA2_PUBLISH_NOTES_REQ 0x45
#define KADEMLIA2_PUBLISH_RES       0x4b
#define KADEMLIA2_PUBLISH_RES_ACK   0x4c
#define KADEMLIA2_FIREWALLED_REQ    0x53
#define KADEMLIA2_PING              0x60
#define KADEMLIA2_PONG              0x61
#define KADEMLIA2_FIREWALLUDP       0x62

#define PACKET_EMIT_TYPE_UDP        1
#define PACKET_EMIT_TYPE_TCP        2

typedef struct _kad_packet {
  uint8_t proto;
  uint8_t opcode;
  uint32_t  data_size;
  uint8_t data[1];
} KAD_PACKET;

bool
pkt_create(
           uint8_t* data,
           uint32_t data_size,
           uint8_t proto,
           uint8_t opcode,
           KAD_PACKET** pkt_out
          );

bool
pkt_destroy(
            KAD_PACKET* pkt
            );
bool
pkt_emit_internal(
                  uint8_t emit_type,
                  KAD_PACKET* kp,
                  uint8_t* buf,
                  uint32_t buf_len,
                  uint32_t* bytes_copied_out
                 );

#define pkt_emit(kp, buf, buf_len, bytes_copied_out) pkt_emit_internal(PACKET_EMIT_TYPE_UDP, kp, buf, buf_len, bytes_copied_out)


#define pkt_emit_emule(kp, buf, buf_len, bytes_copied_out) pkt_emit_internal(PACKET_EMIT_TYPE_TCP, kp, buf, buf_len, bytes_copied_out)

#define pkt_length_with_header_internal(emit_type, pkt) ((emit_type == PACKET_EMIT_TYPE_UDP)?2:6) + pkt->data_size
#define pkt_length_with_header(pkt) pkt_length_with_header_internal(PACKET_EMIT_TYPE_UDP, pkt)
#define pkt_length_with_header_emule(pkt) pkt_length_with_header_internal(PACKET_EMIT_TYPE_TCP, pkt)

#endif // _PACKET_H_
