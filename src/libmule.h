#ifndef _LIBMULE_H_
#define _LIBMULE_H_

#ifndef KAD_SESSION_STATUS_DEFINED
#define KAD_SESSION_STATUS_DEFINED

typedef struct _kad_session_status {
  uint8_t version;
  uint16_t udp_port;
  uint16_t ext_udp_port;
  bool fw;
  bool fw_udp;
  uint32_t pub_ip4_no;
} KAD_SESSION_STATUS;

#endif

typedef struct _mule_session MULE_SESSION;

// Kad callbacks prototypes.

typedef bool (*KAD_GET_STATUS)(void* ks, KAD_SESSION_STATUS* kss);

typedef bool (*KAD_CALC_VERIFY_KEY)(void* ks, uint32_t ip4_no, uint32_t* key_out);

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

typedef struct _kad_callbacks {
  KAD_GET_STATUS kad_get_status;
  KAD_CALC_VERIFY_KEY kad_calc_verify_key;
  KAD_SEND_FW_CHECK_UDP kad_send_fw_check_udp;
  KAD_FW_CHECK_RESPONSE kad_fw_check_response;
  KAD_FW_DEC_CHECKS_RUNNING kad_fw_dec_checks_running;
  KAD_FW_DEC_CHECKS_RUNNING_UDP kad_fw_dec_checks_running_udp;
} KAD_CALLBACKS;

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
mule_session_new_connection(
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
mule_session_connected_to_peer(
                               MULE_SESSION* ms,
                               uint32_t ip4_no,
                               uint16_t port_no,
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

bool
mule_session_add_source_for_udp_fw_check(
                                         MULE_SESSION* ms,
                                         void* id,
                                         uint32_t ip4_no,
                                         uint16_t tcp_port_no,
                                         uint16_t udp_port_no
                                        );

#endif // _LIBMULE_H_
