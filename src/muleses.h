#ifndef _MULESES_H_
#define _MULESES_H_

#define MAX_NICK_LEN 15

#define PACKET_QUEUE_LENGTH 64

#define PACKET_ACTION_CONNECT    1
#define PACKET_ACTION_SEND_DATA  2
#define PACKET_ACTION_PARSE_DATA 3
#define PACKET_ACTION_DISCONNECT 4

typedef struct _kad_status {
  uint8_t version;
  uint16_t udp_port;
  uint16_t ext_udp_port;
  bool fw;
  bool fw_udp;
  uint32_t pub_ip4_no;
} KAD_STATUS;

// Kad callbacks prototypes.

typedef bool (*KAD_GET_STATUS)(void* ks, KAD_STATUS* kss);

typedef bool (*KAD_CALC_VERIFY_KEY)(void* ks, uint32_t ip4_no, uint32_t* key_out);

typedef bool (*KAD_BOOTSTRAP_FROM_NODE)(void* ks, uint32_t ip4_no, uint16_t port_no);

typedef bool (*KAD_SEND_FW_CHECK_UDP)(void* ks, uint16_t check_port, uint32_t key, uint32_t ip4_no);

typedef bool (*KAD_FW_CHECK_RESPONSE)(void* ks);

typedef bool (*KAD_FW_DEC_CHECKS_RUNNING)(void* ks);

typedef bool (*KAD_FW_DEC_CHECKS_RUNNING_UDP)(void* ks);

// Network callbacks prototypes.

typedef bool (*CONNECT)(void* handle, uint32_t ip4_no, uint16_t port_no, void* arg);

typedef bool (*SEND)(void* conn_handle, uint8_t* data, uint32_t data_len);

typedef bool (*DISCONNECT)(void* conn_handle);

typedef struct mule_network_callbacks {
  CONNECT connect;
  SEND send;
  DISCONNECT disconnect;
} MULE_NETWORK_CALLBACKS;

typedef struct _mule_sesssion_timers {
  uint32_t manage_sources;
  uint32_t manage_inactive_sources;
  uint32_t remove_disconnected_sources;
  uint32_t handle_in_packets;
  uint32_t handle_out_packets;
} MULE_SESSION_TIMERS;

typedef struct _kad_callbacks {
  KAD_GET_STATUS kad_get_status;
  KAD_CALC_VERIFY_KEY kad_calc_verify_key;
  KAD_BOOTSTRAP_FROM_NODE kad_bootstrap_from_node;
  KAD_SEND_FW_CHECK_UDP kad_send_fw_check_udp;
  KAD_FW_CHECK_RESPONSE kad_fw_check_response;
  KAD_FW_DEC_CHECKS_RUNNING kad_fw_dec_checks_running;
  KAD_FW_DEC_CHECKS_RUNNING_UDP kad_fw_dec_checks_running_udp;
} KAD_CALLBACKS;

typedef struct _mule_session {
  uint16_t tcp_port;
  char nick[MAX_NICK_LEN + 1];
  LIST* sources;
  UINT128 user_hash;
  QUEUE* queue_in_pkt;
  QUEUE* queue_out_pkt;
  void* kad_session;
  KAD_CALLBACKS kcbs;
  void* net_handle;
  MULE_NETWORK_CALLBACKS ncbs;
  MULE_SESSION_TIMERS timers;
} MULE_SESSION;

bool
mule_session_init(
                  uint16_t tcp_port,
                  MULE_SESSION** ms_out
                 );

bool
mule_session_uninit(
                    MULE_SESSION* ms
                   );

bool
mule_session_set_kad_callbacks(
                               MULE_SESSION* ms,
                               void* kad_session,
                               KAD_CALLBACKS* kcbs
                               );

bool
mule_session_set_network_callbacks(
                                   MULE_SESSION* ms,
                                   void* net_handle,
                                   MULE_NETWORK_CALLBACKS* ncbs
                                  );

bool
mule_session_create_queue_out_pkt(
                                  MULE_SESSION* ms,
                                  uint8_t action,
                                  uint32_t ip4_no,
                                  uint16_t port_no,
                                  void* fd,
                                  uint8_t* pkt,
                                  uint32_t pkt_len
                                  );

bool
mule_session_global_source_by_ip_port(
                                      MULE_SESSION* ms,
                                      uint32_t ip4_no,
                                      uint16_t port_no,
                                      MULE_SOURCE** msc_out
                                     );

bool
mule_session_global_source_by_fd(
                                 MULE_SESSION* ms,
                                 void* fd,
                                 MULE_SOURCE** msc_out
                                 );

bool
mule_session_global_source_by_ip_and_direction(
                                               MULE_SESSION* ms,
                                               uint32_t ip4_no,
                                               uint8_t direction,
                                               MULE_SOURCE** msc_out
                                              );

bool
mule_session_add_global_source(
                               MULE_SESSION* ms,
                               MULE_SOURCE* msc
                              );

bool
mule_session_new_connection(
                            MULE_SESSION* ms,
                            uint32_t ip4_no,
                            uint16_t port_no,
                            void* fd
                           );

bool
mule_session_connected_to_peer(
                               MULE_SESSION* ms,
                               uint32_t ip4_no,
                               uint16_t port_no,
                               void* fd
                              );

bool
mule_session_peer_disconnected(
                               MULE_SESSION* ms,
                               void* fd
                              );

bool
mule_session_data_received(
                           MULE_SESSION* ms,
                           void* fd,
                           uint8_t* pkt,
                           uint32_t pkt_len
                          );

bool
mule_session_timer(
                   MULE_SESSION* ms
                  );

#define QUEUE_IN_PKT(ms, p) queue_enq(ms->queue_in_pkt, p)

#define DEQ_IN_PKT(ms, pp) queue_deq(ms->queue_in_pkt, pp)

#define QUEUE_OUT_PKT(ms, p) queue_enq(ms->queue_out_pkt, p)

#define DEQ_OUT_PKT(ms, pp) queue_deq(ms->queue_out_pkt, pp)

#endif // _MULESES_H_
