#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <mule.h>
#include <mulefile.h>
#include <mulesrc.h>
#include <muleses.h>
#include <mem.h>
#include <log.h>

bool
mule_file_init_parts(
                     MULE_FILE* kf,
                     uint64_t size,
                     bool full
                    )
{
  bool result = false;
  MULE_FILE_PART* part = NULL;
  uint32_t rem_file_size = 0;

  do {

    kf->part_size = MULE_FILE_PART_SIZE;

    // Real parts count
    
    kf->part_count = (uint32_t) ((size + MULE_FILE_PART_SIZE - 1) / MULE_FILE_PART_SIZE);

    kf->part_hashes_needed = kf->part_count > 1;

    // Parts for OP_FILESTATUS
    
    kf->e2k_part_count = (uint32_t)(size / MULE_FILE_PART_SIZE + 1);

    // Parts for OP_HASHSETANSWER;

    kf->e2k_part_hash_count = (uint32_t)(size / MULE_FILE_PART_SIZE);

    if (kf->e2k_part_hash_count) kf->e2k_part_hash_count++;

    LOG_DEBUG("size = %.8x%.8x, parts_size = %.8x, part_count = %.8x, e2k_part_count = %.8x, e2k_part_hash_count = %.8x",
              (uint32_t)(size >> 32),
              (uint32_t)size,
              kf->part_size,
              kf->part_count,
              kf->e2k_part_count,
              kf->e2k_part_hash_count
              );

    rem_file_size = (uint32_t)size;

    for (uint32_t i = 0; i < kf->part_count; i++){

      part = (MULE_FILE_PART*)mem_alloc(sizeof(MULE_FILE_PART) - 1 + kf->part_size);

      if (!part) {

        LOG_ERROR("Failed to allocate memory or part structure.");

        break;

      }

      // Initialize part entry
      
      part->status = full?MULE_FILE_PART_STATUS_ON_DISK:MULE_FILE_PART_STATUS_DOWNLOADING;

      // [LOCK] part lock initialization
      
      part->start = i * kf->part_size;

      part->idx = (uint16_t)i;

      part->length = (rem_file_size > kf->part_size)?kf->part_size:rem_file_size;

      list_add_entry(&kf->parts, (void*)part);

      rem_file_size -= (rem_file_size > kf->part_size)?kf->part_size:rem_file_size;

    }

    result = true;

  } while (false);

  if (!result) list_destroy(kf->parts, true);

  return result;
}

bool
mule_file_create_hashes(
                       MULE_FILE* kf,
                       uint8_t* data,
                       uint64_t data_len,
                       CIPHER_CALLBACKS* ccbs
                      )
{
  bool result = false;
  uint32_t rem_len = 0;
  uint8_t* p = NULL;
  uint32_t part_data_len = 0;
  uint8_t part_hash[16] = {0};

  do {

    if (!kf || !data || !data_len || !ccbs || ccbs->md4) break;

    rem_len = (uint32_t)data_len;

    p = data;

    // Calculate and store hash for each part.
    
    for (uint32_t i = 0; i < kf->part_count; i++){

      if (!rem_len) break;

      part_data_len = (rem_len < MULE_FILE_PART_SIZE)?rem_len:MULE_FILE_PART_SIZE;

      memset(part_hash, 0, sizeof(part_hash));

      ccbs->md4((uint8_t*)p, part_data_len, part_hash);

      // Copying data in raw byte order to calculate file hash.
      
      uint128_from_buffer(&kf->parts_hashes[i], part_hash, sizeof(part_hash), false);

      p += part_data_len;

      rem_len -= part_data_len;

    }

    memset(part_hash, 0, sizeof(part_hash));

    if (kf->part_count > 1){

      ccbs->md4((uint8_t*)kf->parts_hashes, sizeof(UINT128) * kf->part_count, part_hash);

      uint128_from_buffer(&kf->id, (uint8_t*)&kf->parts_hashes[0], sizeof(UINT128),true);

    } else {

      uint128_from_buffer(&kf->id, (uint8_t*)&kf->parts_hashes[0], sizeof(UINT128), true);

    }

    // After file hash calculation part hashes need to be set in big endian byte order

    for (uint32_t i = 0; i < kf->part_count; i++){

      memcpy(part_hash, (uint8_t*)(&kf->parts_hashes[i]), sizeof(UINT128) );

      uint128_from_buffer(&kf->parts_hashes[i], part_hash, sizeof(part_hash), true);

      LOG_DEBUG_UINT128("part_hash", ((UINT128*)&kf->parts_hashes[i]));


    }

    LOG_DEBUG_UINT128("fileId", ((UINT128*)&kf->id));

    result = true;

  } while (false);

  return result;
}

bool
mule_file_destroy_sources(
                         MULE_FILE* mf
                        )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;

  do {

    if (!mf) break;

   
    LIST_EACH_ENTRY_WITH_DATA_BEGIN(mf->sources, e, msc);
    
      mule_source_destroy(msc);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    list_destroy(mf->sources, false);

    result = true;

  } while (false);

  return result;
}

bool
mule_file_destroy(
                 MULE_FILE* mf
                )
{
  bool result = false;
  MULE_FILE_PART* mfp = NULL;

  do {

    if (!mf) break;

    if (mf->sources) mule_file_destroy_sources(mf);

    // [TODO] This list must be local to a file,
    // all published keywords need to be
    // copied to global keywords list.
    //
    // Destroy list but spare keyword structures
    // they stil linked to global list.

    if (mf->keywords) list_destroy(mf->keywords, false);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(mf->parts, e, mfp);

      list_destroy(mfp->blocks, true);

      mem_free(mfp);

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    list_destroy(mf->parts, false);

    mem_free(mf);

    result = true;

  } while (false);

  return result;
}

bool
mule_file_create(
                UINT128* id,
                char* name,
                char* path,
                uint8_t* data,
                uint64_t size,
                void* /*CIPHER_CALLBACKS*/ ccbs,
                MULE_FILE** mf_out
               )
{
  bool result = false;
  MULE_FILE* mf = NULL;
  uint32_t name_len = 0;
  uint32_t path_len = 0;
  char* p = NULL;
  uint32_t part_count = 0;

  do {

    if (!name) break;

    name_len = strlen(name) + 1;

    if (path){

      path_len = strlen(path) + 1;

    }

    part_count = (uint32_t)((size + MULE_FILE_PART_SIZE - 1) / MULE_FILE_PART_SIZE);

    mf = (MULE_FILE*)mem_alloc(
                              sizeof(MULE_FILE) - 1 + 
                              name_len + 
                              path_len + 
                              part_count * sizeof(UINT128)
                             );

    if (!mf){

      LOG_ERROR("Failed to allocate memory for kad file.");

      break;

    }

    mule_file_init_parts(mf, size, data?true:false);

    // Point p to start of the buffer.
    
    p = (char*)mf + sizeof(MULE_FILE) - 1;

    if (id) uint128_copy(id, &mf->id);

    mf->name = p;

    strcpy(p, name);

    p += name_len;

    if (path){

      mf->path = p;

      strcpy(p, path);

      p += path_len;

    }

    // Hash for each of possible parts.

    mf->parts_hashes = (UINT128*)p;

    mf->length = size;

    if (data){

      mf->full = true;

      mule_file_create_hashes(mf, data, size, ccbs);

    }

    *mf_out = mf;

    result = true;

  } while (false);

  if (!result && mf) mule_file_destroy(mf);

  return result;
}

bool
mule_file_add_source(
                    MULE_FILE* mf,
                    uint8_t type,
                    UINT128* id,
                    uint32_t ip4_no,
                    uint16_t tcp_port_no,
                    uint16_t udp_port_no,
                    uint8_t cipher_opts
                   )
{
  bool result = false;
  MULE_SOURCE* msc = NULL;

  do {

    // [TODO] one file source can be attached to multiple kad files.

    if (!mf) break;

    if (!mule_source_create(type, id, ip4_no, tcp_port_no, udp_port_no, cipher_opts, &msc)){

      LOG_ERROR("Failed to create mule source.");

      break;

    }

    mule_source_add_type(msc, MULE_SOURCE_FLAG_FILE_BOUND);

    if(!list_add_entry(&mf->sources, (void*)msc)){

      LOG_ERROR("Failed to add source to sources list.");

      break;

    }

    result = true;

  } while (false);

  if (!result && msc) mule_source_destroy(msc);

  return result;
}

bool
mule_file_part_is_blocks_complete(
                                  MULE_FILE_PART* mfp
                                 )
{
  bool result = false;
  uint64_t part_start = 0;
  uint64_t part_len = 0;
  uint64_t blocks_len = 0;
  MULE_FILE_PART_BLOCK* mfbp = 0;

  do {

    part_start = mfp->start;

    part_len = mfp->length;

    LOG_DEBUG("Part to check: %.8x:%.8x", (uint32_t)part_start, (uint32_t)part_len);

    // Blocks allocated in consequintal order without gaps between them
    // so they all represent continuous space.

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(mfp->blocks, e, mfbp);

      if (
          mfbp->state == MULE_FILE_BLOCK_STATE_DOWNLOADED ||
          mfbp->state == MULE_FILE_BLOCK_STATE_SAVED_TO_DISK
          ){

        // Block downloaded.
        
        blocks_len += mfbp->len;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    LOG_DEBUG("blocks_len %.8x, part_len = %.8x", (uint32_t)blocks_len, (uint32_t)part_len);

    if (!blocks_len != part_len) break;

    result = true;

  } while (false);

  return result;
}

bool
mule_file_is_part_complete(
                          MULE_FILE* mf,
                          uint64_t start,
                          uint64_t end
                         )
{
  bool result = false;
  MULE_FILE_PART* mfp = NULL;
  bool complete = false;
  do {

    if (!mf) break;

    LOG_DEBUG("Part to check: start = %.8x, end = %.8x", (uint32_t)start, (uint32_t)end);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(mf->parts, e, mfp);
    
      LOG_DEBUG("Part to check: start = &.8x, end = %.8x", (uint32_t)mfp->start, (uint32_t)(mfp->start + mfp->length));  
      if (
          mfp->start == start &&
          mfp->start + mfp->length == end &&
          (mfp->status == MULE_FILE_PART_STATUS_FULL || mule_file_part_is_blocks_complete(mfp))
         ) {

          complete = true;
      }

      if (complete) break;

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!complete) break;

    result = true;

  } while (false);

  return result;
}

bool
mule_file_parse_part_info(
                         uint8_t* buffer,
                         uint32_t len,
                         bool* all_parts_out,
                         uint8_t** parts_out,
                         uint32_t* parts_len_out,
                         uint16_t* parts_count_out,
                         uint32_t* parsed_len_out
                        )
{
  bool result = false;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  uint8_t* parts = NULL;
  uint32_t parts_len = 0;
  uint16_t parts_count = 0;
  uint32_t parsed_len = 0;
  bool all_parts = false;


  do {

    p = buffer;

    rem_len = len;

    parts_count = *((uint16_t*)p);

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    parsed_len += sizeof(uint16_t);

    if (!parts_count) {

      all_parts = true;

    } else {

      parts_len = (parts_count / 8) + ((parts_count % 8)?1:0);

      parts = (uint8_t*)mem_alloc(parts_len);

      if (!parts) {

        LOG_ERROR("Failed to allocate memory for parts.");

        break;

      }

      memcpy(parts, buffer, len < parts_len?len:parts_len);

      parsed_len += len < parts_len?len:parts_len;

    }

    *all_parts_out = all_parts;

    *parts_out = parts;

    *parts_len_out = parts_len;

    *parts_count_out  = parts_count;

    *parsed_len_out = parsed_len;

    result = true;

  } while (false);

  return result;
}

bool
mule_file_emit_parts_info(
                          MULE_FILE* mf,
                          uint8_t* buffer,
                          uint32_t buffer_length,
                          uint32_t* emited_len_out
                         )
{
  bool result = false;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  uint64_t rem_file_len = 0;
  uint32_t part_size = 0;
  uint16_t total_parts = 0;
  uint16_t j = 0;
  uint16_t x = 0;

  do {

    if (!mf || !buffer) break;

    if (buffer_length < mule_file_calc_part_info_size(mf)){

      LOG_ERROR("Not enough spacec in buffer.");

      break;

    }

    p = buffer;

    rem_file_len = mf->length;

    rem_len = buffer_length;

    total_parts = (uint16_t)mf->e2k_part_count;

    // Parts count
    
    *((uint16_t*)p) = total_parts;

    p += sizeof(uint16_t);

    rem_len -= sizeof(uint16_t);

    for (uint32_t i = 0; i < total_parts; i++){

      part_size = (rem_file_len > MULE_FILE_PART_SIZE?MULE_FILE_PART_SIZE:rem_file_len);

      LOG_DEBUG("Checking part start %.8x, end %.8x.", 
                (uint32_t)(i * MULE_FILE_PART_SIZE),
                (uint32_t)(i * MULE_FILE_PART_SIZE + part_size)
               );

      x |= mule_file_is_part_complete(mf, i * MULE_FILE_PART_SIZE, (uint32_t)(i * MULE_FILE_PART_SIZE + part_size)) << j++;

      LOG_DEBUG("Complete heck result %.2x", x);

      if (j == 8){

        j = 0;

        *p++ = x;

        rem_len--;

        x = 0;

      }

      rem_file_len -= part_size;

      if (!rem_file_len) break;

    }

    // [FIXFIX] Ugly, need to be rewritten.

    if (j){

      *p++ = x;

      rem_len--;

    }

    if (emited_len_out) *emited_len_out = buffer_length - rem_len;

    result = true;

  } while (false);

  return result;
}

bool
mule_file_part_get_block_to_download(
                                     MULE_FILE_PART* mfp,
                                     uint32_t pref_blk_len,
                                     uint64_t* block_start_out,
                                     uint64_t* block_len_out
                                    )
{
  bool result = false;
  MULE_FILE_PART_BLOCK* mfpb = NULL;
  uint64_t offset_from_start = 0;
  uint64_t part_start = 0;
  uint64_t block_start = 0;
  uint64_t block_len = 0;
  bool found = false;

  do {

    if (!mfp || !block_start_out || !block_len_out) break;

    part_start = mfp->start;

    LOG_DEBUG("part_start = %.8x", (uint32_t)part_start);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(mfp->blocks, e, mfpb);

      LOG_DEBUG("block_start = %.8x, block_len = %.8x, block_recvd = %.8x, block_state = %.8x",
                (uint32_t)(part_start + offset_from_start),
                (uint32_t)mfpb->len,
                (uint32_t)mfpb->recvd,
                (uint32_t)mfpb->state
               );

      if (mfpb->state == MULE_FILE_BLOCK_STATE_ALLOCATED){

        // Block state remain allocated in case of this part being not available on remote source.
        // Can also be allocated when download was canceled and block was not fully downloaded.
        
        block_start = part_start + offset_from_start;

        block_len = mfpb->len;

        mfpb->state = MULE_FILE_BLOCK_STATE_DOWNLOADING;

        LOG_DEBUG("Already allocated block %.8x:%.8x", (uint32_t)block_start, (uint32_t)block_len);

        found = true;

        break;

      }

      offset_from_start += mfpb->len;

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!found){

      LOG_DEBUG("offset_from_start = %.8x", offset_from_start);

      block_start = part_start + offset_from_start;

      block_len = ((mfp->length - offset_from_start) < pref_blk_len)?(mfp->length - offset_from_start):pref_blk_len;

      LOG_DEBUG("Next allocated block: %.8x:%.8x", (uint32_t)block_start, (uint32_t)block_len);

      if (!block_len) break; // In original source DebugBreak() used instead of break, probably for catching errors.

      mfpb = (MULE_FILE_PART_BLOCK*)mem_alloc(sizeof(MULE_FILE_PART_BLOCK) - 1 + (uint32_t)block_len);

      if (!mfpb){

        LOG_ERROR("Failed to allocate memory for kad file part block.");

        break;

      }

      mfpb->state = MULE_FILE_BLOCK_STATE_DOWNLOADING;

      mfpb->len = (uint32_t) block_len;

      list_add_entry(&mfp->blocks, (void*)mfpb);

    }

    *block_start_out = block_start;

    *block_len_out = block_len;

    result = true;

  } while (false);

  return result;
}

bool
mule_file_get_block_to_download(
                                MULE_FILE* mf,
                                uint64_t part_start,
                                uint64_t pref_block_len,
                                uint64_t* start_out,
                                uint64_t* length_out
                               )
{
  bool result = false;
  MULE_FILE_PART* mfp = NULL;
  bool found = false;

  do {

    if (!mf || !start_out || !length_out) break;

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(mf->parts, e, mfp);

      if (
          mfp->start == part_start && 
          !(mfp->status >= MULE_FILE_PART_STATUS_FULL || mule_file_part_is_blocks_complete(mfp))
         ){

        if (mule_file_part_get_block_to_download(mfp, (uint32_t)pref_block_len, start_out, length_out)){

          found = true;

          break;

        }

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!found) break;

    result = true;

  } while (false);

  return result;
}

bool
mule_file_is_block_downloading(
                               MULE_FILE* mf,
                               bool check_len,
                               uint64_t start,
                               uint64_t len
                              )
{
  bool result = false;
  MULE_FILE_PART* mfp = NULL;
  MULE_FILE_PART_BLOCK* mfpb= NULL;
  uint64_t part_start = 0;
  bool found = false;

  do {

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(mf->parts, e, mfp);

      if (mfp->start <= start && mfp->length > len) {

        part_start = mfp->start;

        LIST_EACH_ENTRY_WITH_DATA_BEGIN(mfp->blocks, e2, mfpb);

          if (part_start <= start && mfpb->state == MULE_FILE_BLOCK_STATE_DOWNLOADING){

            if (!(check_len && (mfpb->len - mfpb->recvd) < len)){

              found = true;

              break;

            }

          }

          part_start += mfpb->len;

        LIST_EACH_ENTRY_WITH_DATA_END(e);

      }

      if (found) break;

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (!found) break;

    result = true;

  } while (false);

  return result;
}
