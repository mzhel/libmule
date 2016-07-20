#ifndef _MULEHLP_H_
#define _MULEHLP_H_

bool
mulehlp_destroy_in_pkt_queue(
                             MULE_SESSION* ms
                            );

bool
mulehlp_destroy_out_pkt_queue(
                              MULE_SESSION* ms
                             );

bool
mulehlp_destroy_sources_list(
                             MULE_SESSION* ms
                            );

bool
mulehlp_destroy_pub_files_list(
                               MULE_SESSION* ms
                              );

bool
mulehlp_queue_hello_pkt(
                        MULE_SESSION* ms,
                        MULE_SOURCE* msc,
                        bool answer
                       );

bool
mulehlp_queue_udp_fw_chk_pkt(
                             MULE_SESSION* ms,
                             MULE_SOURCE* msc
                            );

bool
mulehlp_pub_file_by_id(
                       MULE_SESSION* ms,
                       UINT128* id,
                       MULE_FILE** mf_out
                      );
bool
mulehlp_queue_file_request_pkt(
                               MULE_SESSION* ms,
                               MULE_SOURCE* msc,
                               MULE_FILE* mf,
                               uint32_t* sent_flags_out
                              );

#endif // _MULEHLP_H_
