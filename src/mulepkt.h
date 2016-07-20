#ifndef _MULEPKT_H_
#define _MULEPKT_H_

bool
mulepkt_create_emit(
                    uint8_t proto,
                    uint8_t op,
                    uint8_t* pkt_data,
                    uint32_t pkt_data_len,
                    void** raw_pkt_out,
                    uint32_t* raw_pkt_len_out
                   );

bool
mulepkt_create_hello(
                     MULE_SESSION* ms,
                     uint8_t opcode,
                     uint32_t kad_version,
                     uint16_t kad_udp_port,
                     bool kad_fw,
                     bool kad_fw_udp,
                     uint32_t kad_pub_ip4_no,
                     void** raw_pkt_out,
                     uint32_t* raw_pkt_len_out
                    );

bool
mulepkt_create_udp_fw_check_req_pkt(
                                    MULE_SESSION* ms,
                                    uint16_t int_kad_port,
                                    uint16_t ext_kad_port,
                                    uint32_t verify_key,
                                    void** raw_pkt_out,
                                    uint32_t* raw_pkt_len_out
                                   );

bool
mulepkt_create_mp_file_request(
                               MULE_SOURCE* msc,
                               MULE_FILE* mf,
                               void** raw_pkt_out,
                               uint32_t* raw_pkt_len_out,
                               uint32_t* sent_flags_out
                              );

bool
mulepkt_create_file_name_request(
                                 MULE_SOURCE* msc,
                                 MULE_FILE* mf,
                                 void** raw_pkt_out,
                                 uint32_t* raw_pkt_len_out
                                );

bool
mulepkt_create_file_hash_set_request(
                                     MULE_SOURCE* msc,
                                     MULE_FILE* mf,
                                     void** raw_pkt_out,
                                     uint32_t* raw_pkt_len_out
                                    );

bool
mule_pkt_create_AICH_request(
                             MULE_SOURCE* msc,
                             MULE_FILE* mf,
                             void** raw_pkt_out,
                             uint32_t* raw_pkt_len_out
                            );



#endif // _MULEPKT_H_
