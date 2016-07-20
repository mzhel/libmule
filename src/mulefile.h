#ifndef _MULEFILE_H_
#define _MULEFILE_H_

#define MULE_FILE_PART_SIZE (9500 * 1024)

#define MULE_FILE_HASH_SIZE 16
#define MULE_FILE_AICH_HASH_SIZE 20 // AICH is really SHA1

#define MULE_FILE_PART_STATUS_DOWNLOADING   1
#define MULE_FILE_PART_STATUS_BAD_HASH      2
#define MULE_FILE_PART_STATUS_FULL          3
#define MULE_FILE_PART_STATUS_FULL_VERIFIED 4
#define MULE_FILE_PART_STATUS_ON_DISK       5
#define MULE_FILE_PART_STATUS_CACHE         6

#define MULE_FILE_BLOCK_STATE_NEW           1
#define MULE_FILE_BLOCK_STATE_ALLOCATED     2
#define MULE_FILE_BLOCK_STATE_DOWNLOADING   3
#define MULE_FILE_BLOCK_STATE_DOWNLOADED    4
#define MULE_FILE_BLOCK_STATE_SAVED_TO_DISK 5
#define MULE_FILE_BLOCK_STATE_CACHE         6

#define MULE_FILE_CACHED_BLOCK_TIMEOUT 10000 // 10 sec

#define MULE_FILE_PART_LOCK(p)
#define MULE_FILE_PART_UNLOCK(p)

typedef struct _mule_file_part_block {
  uint8_t state;
  uint32_t last_read_time;
  uint32_t recvd;
  uint32_t len;
  uint8_t data[1];
} MULE_FILE_PART_BLOCK;

typedef struct _mule_file_part {
  uint8_t status;
  uint16_t idx;
  uint64_t start;
  uint64_t length;
  LIST* blocks; // List of MULE_FILE_PART_BLOCK structures, representing
                // file blocks currently downloading.
} MULE_FILE_PART;

typedef struct _mule_file {
  // FILE* f;
  uint64_t length;
  bool queued_for_deletion;
  bool del_from_disk;
  UINT128 id; // When initialized from disk id is md4 hash in big-endian byte order.
  char* name;
  char* path;
  bool full; // flag is set when file is loaded from disk or all it's parts are downloaded.
  bool part_hashes_needed; // set if need to request part hashes from source
  bool published;
  bool publish_initiated;
  uint32_t publish_timeout;
  uint32_t sources_count;
  uint16_t complete_sources_count;
  uint32_t part_size;
  uint32_t part_count;
  uint32_t e2k_part_count;
  uint32_t e2k_part_hash_count;
  uint8_t aich_hash[MULE_FILE_AICH_HASH_SIZE];
  UINT128* parts_hashes;
  LIST* sources; // List of MULE_SOURCE structures, this sources are local to file they bound to
                 // and may overlap with sources in other files and global sources list.
  LIST* keywords; // List of KAD_KEYWORD structures linked to this file.
  LIST* parts; // List of MULE_FILE_PART structures, containing actual file data.
  uint8_t buf[1]; // Buffer for all pointers in the structure.
} MULE_FILE;

#define mule_file_calc_part_info_size(mf) (sizeof(uint16_t) + (mf->e2k_part_count / 8) + ((mf->e2k_part_count %8)?1:0))


bool
mule_file_create(
                UINT128* id,
                char* name,
                char* path,
                uint8_t* data,
                uint64_t size,
                void* /*CIPHER_CALLBACKS*/ ccbs,
                MULE_FILE** mf_out
               );

bool
mule_file_destroy(
                 MULE_FILE* mf
                );

bool
mule_file_add_source(
                    MULE_FILE* mf,
                    uint8_t type,
                    UINT128* id,
                    uint32_t ip4_no,
                    uint16_t tcp_port_no,
                    uint16_t udp_port_no,
                    uint8_t cipher_opts
                   );

bool
mule_file_emit_parts_info(
                          MULE_FILE* mf,
                          uint8_t* buffer,
                          uint32_t buffer_length,
                          uint32_t* emited_len_out
                         );

#endif // _MULEFILE_H_
