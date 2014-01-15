#ifndef _MULEPROTO_H_
#define _MULEPROTO_H_

bool
mule_proto_handle_packet(
                         MULE_SESSION* ms,
                         MULE_SOURCE* msc,
                         uint8_t* raw_pkt,
                         uint32_t raw_pkt_len
                        );

#endif // _MULEPROTO_H_
