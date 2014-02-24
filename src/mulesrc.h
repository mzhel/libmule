#ifndef _MULESRC_H_
#define _MULESRC_H_

#define MULE_SOURCE_FLAG_FILE_BOUND       1
#define MULE_SOURCE_FLAG_GLOBAL           2
#define MULE_SOURCE_FLAG_COPIED_TO_GLOBAL 3

#define MULE_SOURCE_STATE_NEW                       1
#define MULE_SOURCE_STATE_CONNECT_QUEUED            2
#define MULE_SOURCE_STATE_CONNECTED                 3
#define MULE_SOURCE_STATE_CONNECT_FAILED            4
#define MULE_SOURCE_STATE_HELLO_SENT                5
#define MULE_SOURCE_STATE_HELLO_RECEIVED            6
#define MULE_SOURCE_STATE_HANDSHAKE_COMPLETED       7
#define MULE_SOURCE_STATE_FILE_INFO_REQUEST_SENT    8
#define MULE_SOURCE_STATE_FILE_INFO_ANSWER_RECEIVED 9
#define MULE_SOURCE_STATE_DOWNLOADING               10
#define MULE_SOURCE_STATE_TIMEOUT_BEFORE_DONE       11
#define MULE_SOURCE_STATE_ACTION_DONE               12
#define MULE_SOURCE_STATE_DISCONNECT_QUEUED         13
#define MULE_SOURCE_STATE_DISCONNECTED              14

#define MULE_SOURCE_ACTION_IDLE         0
#define MULE_SOURCE_ACTION_UDP_FW_CHECK 1
#define MULE_SOURCE_ACTION_FW_CHECK     2
#define MULE_SOURCE_ACTION_DOWNLOAD     3
#define MULE_SOURCE_ACTION_DISCONNECT   4

#define MULE_SOURCE_DIRECTION_IN        1
#define MULE_SOURCE_DIRECTION_OUT       2

#define MULE_SOURCE_CRYPT_LAYER_SUPPORT_MASK  0x01
#define MULE_SOURCE_CRYPT_LAYER_REQUEST_MASK  0x02
#define MULE_SOURCE_CRYPT_LAYER_REQUIRES_MASK 0x04
#define MULE_SOURCE_UDP_CALLBACK_MASK         0x08

#define MULE_SOURCE_CIPHER_STATE_NONE         0x00
#define MULE_SOURCE_CIPHER_STATE_PENDING      0x01

#define MAGIC_VALUE_REQUESTER 34
#define MAGIC_VALUE_SERVER    203

#define MULE_SOURCE_USER_HASH_LEN     16
#define MULE_SOURCE_MAX_USER_NICK_LEN 31
#define MULE_SOURCE_MAX_FILE_NAME_LEN 255

#define MULE_SOURCE_INACTIVITY_TIMEOUT_MS 25000

#define MULE_SOURCE_FLAG_FILE_NAME    1
#define MULE_SOURCE_FLAG_FILE_STATUS  2
#define MULE_SOURCE_FLAG_AICH_HASH    4

#define MULE_SOURCE_DL_STATE_INFO_EXCHANGE        1
#define MULE_SOURCE_DL_STATE_PARTS_HASHES_REQ     2
#define MULE_SOURCE_DL_STATE_WAITING_PART_HASHES  3
#define MULE_SOURCE_DL_STATE_UPLOAD_REQUEST       4
#define MULE_SOURCE_DL_STATE_WAITING_UPLOAD_RESP  5
#define MULE_SOURCE_DL_STATE_PARTS_REQUEST        6
#define MULE_SOURCE_DL_STATE_PARTS_WAIT           7
#define MULE_SOURCE_DL_STATE_PART_RECEIVED        8
#define MULE_SOURCE_DL_STATE_NO_PARTS_NEEDED      9

#define MULE_PART_STATE_WAIT_HEAD 1
#define MULE_PART_STATE_WAIT_TAIL 2

#define MULE_SOURCE_ACTIONS_LOCK(msc)
#define MULE_SOURCE_ACTIONS_UNLOCK(msc)

typedef struct _kad_file MULE_FILE;

typedef struct _sent_part {
  uint8_t state;
  uint8_t* data;
  uint32_t rcvd;
  uint32_t to_recv;
} SENT_PART;

typedef struct _mule_source_download_info {
  uint32_t send_flags;
  uint32_t recv_flags;
  uint32_t blocks_to_recv;
  uint32_t state;
  MULE_FILE* file;
  char file_name[MULE_SOURCE_MAX_FILE_NAME_LEN + 1];
  bool all_parts;
  uint16_t parts_count;
  uint32_t parts_status_bytes;
  uint8_t* parts_status; // Bitmap describing parts status.
  UINT128* parts_hash; // Array of hashes for each part.
  SENT_PART sent_part;
  LIST* req_blocks;
} MULE_SOURCE_DOWNLOAD_INFO;

typedef struct _mule_source_action {
  uint8_t type;
  void* arg;
} MULE_SOURCE_ACTION;

typedef struct _mule_source_info {
  uint8_t user_hash[MULE_SOURCE_USER_HASH_LEN];
  uint32_t user_id;
  uint16_t tcp_port;
  char user_name[MULE_SOURCE_MAX_USER_NICK_LEN + 1];
  uint32_t donkey_ver;
  uint16_t udp_port;
  MULE_MISC_OPTS_1 misc_opts_1;
  MULE_MISC_OPTS_2 misc_opts_2;
  MULE_COMPAT_OPTS compat_opts;
  uint32_t compatible_client;
  uint32_t client_version;
  uint32_t emule_version;
  uint8_t shared_dirs;
  uint8_t info_packets_received;
} MULE_SOURCE_INFO;

typedef struct _mule_source {
  uint8_t type; // Source type flags;
  uint8_t state;
  QUEUE* actions;
  uint8_t last_action;
  uint8_t direction;
  uint8_t access; // firewalled, callback possible etc.
  UINT128 id;
  uint32_t ip4_no;
  uint16_t tcp_port_no;
  uint16_t udp_port_no;
  uint8_t cipher_opts;
  uint8_t cipher_state;
  uint8_t send_buf_key[16];
  uint8_t recv_buf_key[16];
  bool wait_io_completion;
  bool done;
  uint32_t last_action_time;
  uint32_t timeout;
  MULE_SOURCE_INFO info;
  void* pkt_asm;
  MULE_SOURCE_DOWNLOAD_INFO dl_info;
  void* fd;
#ifdef CONFIG_VERBOSE
  char ip4_str[32];
#endif
} MULE_SOURCE;

bool
mule_source_create(
                   uint8_t access,
                   UINT128* id,
                   uint32_t ip4_no,
                   uint16_t tcp_port_no,
                   uint16_t udp_port_no,
                   uint8_t cipher_opts,
                   MULE_SOURCE** msc_out
                  );

bool
mule_source_destroy(
                    MULE_SOURCE* msc
                   );

bool
mule_source_set_direction(
                          MULE_SOURCE* msc,
                          uint8_t direction
                         );

bool
mule_source_add_type(
                     MULE_SOURCE* msc,
                     uint8_t type
                    );

bool
mule_source_remove_type(
                        MULE_SOURCE* msc,
                        uint8_t type
                       );

bool
mule_source_type_set(
                     MULE_SOURCE* msc,
                     uint8_t type
                    );

bool
mule_source_copy(
                 MULE_SOURCE* msc_src,
                 MULE_SOURCE** msc_dst_out
                );

bool
mule_source_queue_action(
                         MULE_SOURCE* msc,
                         uint8_t type,
                         void* arg
                        );

bool
mule_source_dequeue_action(
                           MULE_SOURCE* msc,
                           uint8_t* action_out,
                           void** arg_out
                          );

#endif // _MULESRC_H_
