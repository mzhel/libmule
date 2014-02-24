#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <wchar.h>
#include <str.h>
#include <tag.h>
#include <mem.h>
#include <log.h>

/*
 *    Emited tag:
 *
 *    [0] - Type. 1byte.
 *    [1] - Name.Length 2bytes.
 *    [3] - Name.Data. Name.Length bytes.
 *    [3 + Name.Length] Data.
 *
 *    When TAG_NAME_ID_FLAG is set.
 *
 *    [0] - Type. 1byte.
 *    [1] - NameId. 1byte.
 *    [2] - Data.
 *
 */

bool
tag_var_int_create(
                   uint8_t name_id,
                   wchar_t* name,
                   uint64_t val,
                   TAG** tag_out
                  )
{
  bool result = false;
  TAG* tag = NULL;
  uint32_t name_len = 0;
  uint8_t* pout = NULL;

  do {

    if ((!name_id && !name) || !tag_out) break;

    if (!name_id) name_len = str_wide_len(name);

    tag = (TAG*) mem_alloc(sizeof(TAG) + (name_len * 2));

    if (!tag) {

      LOG_ERROR("Failed to allocate memory for tag.");

      break;

    }

    tag->name_id = name_id;

    tag->name_len = name_len;

    if (!name_id){

      memcpy(tag->name, name, name_len * 2);

    }

    tag->data_offset = tag->name_len?(10 + (tag->name_len - 1) * 2):10;

    pout = (uint8_t*)tag + tag->data_offset;

    if (val < 0xff){

      tag->type = TAGTYPE_UINT8;

      *pout = (uint8_t)val;

    } else if (val < 0xffff){

      tag->type = TAGTYPE_UINT16;

      *((uint16_t*)pout) = (uint16_t)val;

    } else if (val < 0xffffffff){

      tag->type = TAGTYPE_UINT32;

      *((uint32_t*)pout) = (uint32_t)val;

    } else {

      tag->type = TAGTYPE_UINT64;

      *((uint64_t*)pout) = (uint64_t)val;

    }

    *tag_out = tag;

    result = true;

  } while (false);

  return result;

}

bool
tag_string_create(
                  uint8_t name_id,
                  wchar_t* name,
                  char* val,
                  TAG** tag_out
                 )
{
  bool result = false;
  TAG* tag = NULL;
  uint32_t name_len = 0;
  uint32_t val_len = 0;
  uint8_t* pout = NULL;

  do {

    if (!val || !tag_out) break;

    if (!name_id && !name) break;

    if (!name_id){

      name_len = str_wide_len(name);

    }

    val_len = strlen(val);

    tag = (TAG*)mem_alloc(sizeof(TAG) + (name_id?0:(name_len * 2)) + (val_len * 2 + 2));

    if (!tag){

      LOG_ERROR("Failed to allocate data for tag.");

      break;

    }

    tag->type = TAGTYPE_STRING;

    tag->name_len = name_len;

    if (!name_id) memcpy(tag->name, name, name_len * 2); else tag->name_id = name_id;

    tag->data_offset = tag->name_len?(10 + (tag->name_len - 1) * 2):10;

    pout = (uint8_t*)tag + tag->data_offset;

    *((uint16_t*)pout) = (uint16_t)val_len;

    str_utf8_to_unicode(val, val_len, (wchar_t*)(pout + 2), *((uint16_t*)pout) * 2, NULL);

    *tag_out = tag;
    
    result = true;

  } while (false);

  return result;
}

bool 
tag_create(
           uint8_t type,
           uint8_t name_id,
           wchar_t* name,
           uint64_t val,
           TAG** tag_out
           )
{
  bool result = false;

  do {

    switch (type) {

      case TAGTYPE_UINT64:
      case TAGTYPE_UINT32:
      case TAGTYPE_UINT16:
      case TAGTYPE_UINT8:

        result = tag_var_int_create(name_id, name, val, tag_out);

      break;

      case TAGTYPE_STRING:

        result = tag_string_create(name_id, name, (char*)val, tag_out);

      break;

    }

  } while (false);

  return result;
}

bool
tag_destroy(
            TAG* tag
           )
{
  bool result = false;

  do {

    if (!tag) break;

    mem_free(tag);

    result = true;

  } while (false);

  return result;
}

bool
tag_calc_buf_size(
                  TAG* tag,
                  uint32_t* size_out
                 )
{
  bool result = false;
  uint32_t size = 0;

  do {

    if (!tag || !size_out) break;

    size += 1; // Type.

    if (tag->name_id){

      size += 1; // Byte for name id.


    } else {

      size += sizeof(uint16_t) + // Name length
              tag->name_len;    // Name data.

    }

    switch (tag->type) {

      case TAGTYPE_STRING:

        size += sizeof(uint16_t) + ((TAG_STRING*)((uint8_t*)tag + tag->data_offset))->len;

      break;

      case TAGTYPE_UINT64:

        size += 8;

      break;

      case TAGTYPE_UINT32:

        size += 4;

      break;

      case TAGTYPE_UINT16:

        size += 2;

      break;

      case TAGTYPE_UINT8:

        size++;

      break;

    }

    *size_out = size;

    result = true;

  } while (false);

  return result;
}

bool
tag_emit(
         TAG* tag,
         uint8_t* buf,
         uint32_t buf_size,
         uint8_t** after_emit_out,
         uint32_t* bytes_emited_out
        )
{
  bool result = false;
  uint32_t calc_size = 0;
  uint8_t* p = NULL;
  uint32_t str_len = 0;

  do {

    if (!tag || !buf) break;

    if (!tag_calc_buf_size(tag, &calc_size) || buf_size < calc_size) break;

    p = buf;

    if (tag->name_id){

      *p++ = tag->type | TAG_NAME_ID_FLAG; // Type.

      *p++ = tag->name_id;

    } else {

      *p++ = tag->type; // Type.

      *((uint16_t*)p) = tag->name_len;

      p += 2;

      for (uint32_t i = 0; i < tag->name_len; i++){

        *p++ = (uint8_t)tag->name[i];

      }

    }

    switch (tag->type){

      case TAGTYPE_STRING:

        *((uint16_t*)p) = ((TAG_STRING*)((uint8_t*)tag + tag->data_offset))->len;

        p += sizeof(uint16_t);

        str_unicode_to_utf8(
                            ((TAG_STRING*)((uint8_t*)tag + tag->data_offset))->data,
                            ((TAG_STRING*)((uint8_t*)tag + tag->data_offset))->len,
                            (char*)p,
                            ((TAG_STRING*)((uint8_t*)tag + tag->data_offset))->len,
                            &str_len
                           );

        p += str_len;

      break;

      case TAGTYPE_UINT64:

        *((uint64_t*)p) = *((uint64_t*)((uint8_t*)tag + tag->data_offset));

        p += 8;

      break;

      case TAGTYPE_UINT32:

        *((uint32_t*)p) = *((uint32_t*)((uint8_t*)tag + tag->data_offset));

        p += 4;

      break;

      case TAGTYPE_UINT16:

        *((uint16_t*)p) = *((uint16_t*)((uint8_t*)tag + tag->data_offset));

        p += 2;

      break;

      case TAGTYPE_UINT8:

        *p = *((uint8_t*)((uint8_t*)tag + tag->data_offset));

        p++;

      break;

    }

    if (after_emit_out) *after_emit_out = p;

    if (bytes_emited_out) *bytes_emited_out = p - buf;

    result = true;

  } while (false);

  return result;
}

bool
tag_length(
           uint8_t* buf,
           uint32_t buf_len,
           uint32_t* tag_len_out
          )
{
  bool result = false;
  uint8_t* p = NULL;
  uint8_t type = 0;
  uint8_t* name = NULL;
  uint16_t name_len = 0;
  uint32_t tag_len = 0;

  do {

    if (!buf || !tag_len_out) break;

    p = buf;

    tag_len = 10;

    type = *p++; // Tag type.

    if (type & TAG_NAME_ID_FLAG){

      // Name id is used.
      
      type &= ~TAG_NAME_ID_FLAG;

      p++;

    } else {

      name_len = *(uint16_t*)p;

      p += sizeof(uint16_t);

      tag_len += (name_len * 2) - 2; // In TAG structure name stored in unicode.

      p += name_len;

    }

    // p points to type part.
    
    switch (type) {

      case TAGTYPE_HASH16:

        tag_len += 16;

      break;

      case TAGTYPE_STRING:

        tag_len += sizeof(uint16_t) + ((*(uint16_t*)p) * 2);

      break;

      case TAGTYPE_UINT32:

        tag_len += sizeof(uint32_t);

      break;

      case TAGTYPE_FLOAT32:

        tag_len += sizeof(float);

      break;

      case TAGTYPE_BOOL:

        tag_len++;

      break;

      case TAGTYPE_BOOLARRAY:

        // [IMPLEMENT]

      break;

      case TAGTYPE_BLOB:

        tag_len += sizeof(uint32_t) + *(uint32_t*)p;

      break;

      case TAGTYPE_UINT16:

        tag_len += sizeof(uint16_t);

      break;

      case TAGTYPE_UINT8:

        tag_len++;

      break;

      case TAGTYPE_BSOB:

        tag_len += sizeof(uint8_t) + *p;

      break;

      case TAGTYPE_UINT64:

        tag_len += sizeof(uint64_t);

      break;

    }

    *tag_len_out = tag_len;

    result = true;

  } while (false);

  return result;
}

bool
tag_read(
         uint8_t* buf,
         uint32_t buf_len,
         bool one_byte_name_is_id,
         TAG** tag_out,
         uint8_t** after_tag_out,
         uint32_t* bytes_read_out
        )
{
  bool result = false;
  uint32_t tag_len = 0;
  TAG* tag = NULL;
  uint8_t* p = NULL;
  uint8_t* pout = NULL;
  uint8_t type = 0;
  uint32_t i = 0;
  uint32_t io_bytes = 0;

  do {

    if (!buf || !buf_len || !tag_out) break;

    if (!tag_length(buf, buf_len, &tag_len)){

      LOG_ERROR("Failed to calculate tag size.");

      break;

    }

    tag = (TAG*)mem_alloc(tag_len);

    if (!tag){

      LOG_ERROR("Failed to allocate memory for tag.");

      break;

    }

    p = buf;

    type = *p++;

    if (type & TAG_NAME_ID_FLAG){

      // Name id is used.
      
      type &= ~TAG_NAME_ID_FLAG;

      tag->name_id = *p++;

    } else {

      tag->name_len = *(uint16_t*)p;

      p += sizeof(uint16_t);

      if (one_byte_name_is_id && tag->name_len == 1){

        tag->name_id = *p++;

      } else {

        for (uint32_t i = 0; i < tag->name_len; i++){

          tag->name[i] = *(p + i);

        }

        p += tag->name_len;

      }

    }

    tag->type = type;

    tag->data_offset = tag->name_len?(10 + (tag->name_len - 1) * 2):10;

    pout = (uint8_t*)tag + tag->data_offset;

    switch (type){

      case TAGTYPE_HASH16:

        memcpy(pout, p, 16);

        p += 16;

      break;

      case TAGTYPE_STRING:

        *(uint16_t*)pout = *(uint16_t*)p;

        str_utf8_to_unicode(
                            (char*)(p + 2),
                            *(uint16_t*)p,
                            (wchar_t*)(pout + 2),
                            *((uint16_t*)pout) * 2,
                            &io_bytes
                            );

        p += sizeof(uint16_t) + *(uint16_t*)p;

      break;

      case TAGTYPE_UINT32:

        *(uint32_t*)pout = *(uint32_t*)p;

        p += sizeof(uint32_t);

      break;

      case TAGTYPE_FLOAT32:

        memcpy(pout, p, sizeof(float));

        p += sizeof(float);

      break;

      case TAGTYPE_BOOL:

        *pout = *p;

        p++;

      break;

      case TAGTYPE_BOOLARRAY:

        // [IMPLEMENT]

      break;

      case TAGTYPE_BLOB:

        *(uint32_t*)pout = *(uint32_t*)p;

        memcpy(pout + 4, p + 4, *(uint32_t*)p);

        p += sizeof(uint32_t) + *(uint32_t*)p;

      break;

      case TAGTYPE_UINT16:

        *(uint16_t*)pout = *(uint16_t*)p;

        p += sizeof(uint16_t);

      break;

      case TAGTYPE_UINT8:

        *pout = *p;

        p++;

      break;

      case TAGTYPE_BSOB:

        *pout = *p;

        memcpy(pout + 1, p + 1, *p);

        p += sizeof(uint8_t) + *p;

      break;

      case TAGTYPE_UINT64:

        *(uint64_t*)pout = *(uint64_t*)p;

        p += sizeof(uint64_t);

      break;

    }

    *tag_out = tag;

    if (after_tag_out) *after_tag_out = p;

    if (bytes_read_out) *bytes_read_out = p - buf;

    result = true;

  } while (false);

  if (!result && tag) tag_destroy(tag);

  return result;
}

bool
tag_string_get_len(
                   TAG* tag,
                   uint32_t* len_out
                  )
{
  bool result = false;

  do {

    if (!tag || !len_out) break; 

    if (tag->type != TAGTYPE_STRING) break;

    *len_out = ((TAG_STRING*)((uint8_t*)tag + tag->data_offset))->len;

    result = true;

  } while (false);

  return result;
}

bool
tag_string_get_data(
                    TAG* tag,
                    uint8_t* buf,
                    uint32_t buf_len
                   )
{
  bool result = false;

  do {

    if (!tag || !buf || !buf_len) break;

    if (tag->type != TAGTYPE_STRING) break;

    if (!str_unicode_to_utf8(
                             ((TAG_STRING*)((uint8_t*)tag + tag->data_offset))->data,
                             ((TAG_STRING*)((uint8_t*)tag + tag->data_offset))->len,
                             (char*)buf,
                             buf_len,
                             NULL
                            )
    ){

      LOG_ERROR("String conversion failed.");

      break;

    }

    result = true;

  } while (false);

  return result;
}

bool
tag_get_name(
             TAG* tag,
             wchar_t* buf,
             uint32_t buf_len
            )
{
  bool result = false;

  do {

    if (!tag || !buf) break;

    if (tag->name_len > buf_len) break;

    memcpy(buf, tag->name, tag->name_len * 2);

    result = true;

  } while (false);

  return result;
}

bool
tag_get_id(
           TAG* tag,
           uint32_t* id_out
          )
{
  bool result = false;

  do {

    if (!tag || !id_out) break;

    if (!tag->name_id) break;

    *id_out = tag->name_id;

    result = true;

  } while (false);

  return result;
}

bool
tag_is_integer(
               TAG* tag
              )
{
  bool result = false;
  uint8_t t = 0;

  do {

    if (!tag) break;

    t = tag->type;

    if (!(t == TAGTYPE_UINT64 || t ==TAGTYPE_UINT32 || t == TAGTYPE_UINT16 || t == TAGTYPE_UINT8)) break;

    result = true;

  } while (false);

  return result;
}

bool
tag_get_integer(
                TAG* tag,
                uint64_t* int_out
               )
{
  bool result = false;
  uint8_t* p = NULL;
  uint32_t int_size = 0;

  do {

    if (!tag || !int_out) break;

    switch(tag->type){

      case TAGTYPE_UINT64:

        int_size = 8;

        break;

      case TAGTYPE_UINT32:

        int_size = 4;

        break;

      case TAGTYPE_UINT16:

        int_size = 2;

        break;

      case TAGTYPE_UINT8:

        int_size = 1;

        break;

    }

    memcpy(int_out, (uint8_t*)tag + tag->data_offset, int_size);

    result = true;

  } while (false);

  return result;
}

bool
tag_is_bsob(
            TAG* tag
           )
{
  bool result = false;

  do {

    if (!tag || tag->type != TAGTYPE_BSOB) break;

    result = true;

  } while (false);

  return result;
}

bool
tag_bsob_get_len(
                 TAG* tag,
                 uint32_t* len_out
                )
{
  bool result = false;

  do {

    if (!tag || !len_out || tag->type != TAGTYPE_BSOB) break;

    *len_out = ((TAG_BSOB*)((uint8_t*)tag + tag->data_offset))->len;

    result = true;

  } while (false);

  return result;
}

bool
tag_bsob_get_data(
                  TAG* tag,
                  uint8_t* buf,
                  uint32_t buf_len
                 )
{
  bool result = false;
  uint32_t bsob_len = 0;

  do {

    if (!tag || !buf) break;

    bsob_len = ((TAG_BSOB*)((uint8_t*)tag + tag->data_offset))->len;

    if (buf_len < bsob_len) break;

    memcpy(buf, ((TAG_BSOB*)((uint8_t*)tag + tag->data_offset))->data, bsob_len);

    result = true;

  } while (false);

  return result;
}
