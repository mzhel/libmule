#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <tag.h>
#include <list.h>
#include <mem.h>
#include <log.h>

bool
tag_list_emit(
              LIST* tl,
              uint8_t* buf,
              uint32_t buf_len,
              bool count_u32,
              uint8_t** buf_after_out,
              uint32_t* rem_len_out
             )
{
  bool result = false;
  uint8_t* p = NULL;
  uint32_t rem_len = 0;
  TAG* t = NULL;
  uint32_t t_len = 0;
  bool failed = false;
  uint32_t t_cnt = 0;

  do {

    if (!tl || !buf || !buf_len) break;

    p = buf;

    rem_len = buf_len;

    list_entries_count(tl, &t_cnt);

    if (count_u32){

      *(uint32_t*)p = t_cnt;

      p += sizeof(uint32_t);

      rem_len -= sizeof(uint32_t);

    } else {

      *p++ = (uint32_t)t_cnt;

      rem_len--;

    }

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(tl, e, t);

      tag_calc_buf_size(t, &t_len);

      if (rem_len < t_len){

        failed = true;

        break;

      }

      if (!tag_emit(t, p, rem_len, &p, &rem_len)){

        LOG_ERROR("Failed to emit tag from list.");

        failed = true;

        break;

      }

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (buf_after_out) *buf_after_out = p;

    if (rem_len_out) *rem_len_out = rem_len;

    if (failed) break;

    result = true;

  } while (false);

  return result;
}

bool
tag_list_add(
            LIST** tl_ptr,
            TAG* t
           )
{
  bool result = false;

  do {

    if (!tl_ptr || !t) break;

    list_add_entry(tl_ptr, t);

    result = true;

  } while (false);

  return result;
}

bool
tag_list_calc_buffer_length(
                            LIST* tl,
                            bool count_u32,
                            uint32_t* len_out
                           )
{
  bool result = false;
  uint32_t t_len = 0;
  uint32_t len = 0;
  TAG* t = NULL;
  bool failed = false;

  do {

    if (!tl || !len_out) break;

    len = count_u32?sizeof(uint32_t):sizeof(uint8_t);

    LIST_EACH_ENTRY_WITH_DATA_BEGIN(tl, e, t);

      if (!tag_calc_buf_size(t, &t_len)){

        LOG_ERROR("Failed to calculate buffer size for tag.");

        failed = true;

        break;

      }

      len += t_len;

    LIST_EACH_ENTRY_WITH_DATA_END(e);

    if (failed) break;

    *len_out = len;

    result = true;

  } while (false);

  return result;
}
