#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <random.h>
#include <byteswap.h>

uint32_t
uint128_generate(UINT128* ui128)
{
  uint8_t i = 0;

  do {

    for (i = 0; i < UINT128_DWORDS_COUNT; i++) {

      ui128->data.dwordData[i] = random_uint32();

    }

  } while (false);

  return 1;

}

uint32_t
uint128_from_buffer(
                    UINT128* ui128,
                    uint8_t* buffer,
                    uint32_t bufferLen,
                    bool bigEndian // if set dwords in buffer treated as big endian
                    )
{
  uint32_t result = 0;

  do {

    if (!ui128 || !buffer) break;

    if (bufferLen < sizeof(UINT128)) break;

    if (bigEndian){

      for (uint8_t i = 0; i < bufferLen; i++){

        ui128->data.dwordData[i] = BSWAP32(((uint32_t*)buffer)[i]);

      }

    } else {
      
      memcpy(ui128, buffer, sizeof(UINT128));

    }

    result = 1;

  } while (false);

  return result;
}

uint32_t
uint128_xor(UINT128* first, UINT128* second, UINT128* xor_res)
{
  uint32_t result = 0;
  uint8_t i;

  do {

    if (!first || !second) break;

    if (!xor_res) xor_res = first;

    for (i = 0; i < UINT128_DWORDS_COUNT; i++){

      xor_res->data.dwordData[i] = first->data.dwordData[i] ^ second->data.dwordData[i];

    }

    result = 1;

  } while (false);

  return result;
}

uint8_t
uint128_set_bit_value(
                      UINT128* ui128,
                      uint32_t bit_idx,
                      uint8_t bit_val
                      )
{
  uint8_t result = 0;

  do {

    if (!ui128 || bit_idx > 127) break;

    if (bit_val){

      ui128->data.dwordData[3 - (bit_idx / 32)] |= 1 << (bit_idx % 32);

    } else {

      ui128->data.dwordData[3 - (bit_idx / 32)] &= ~(1 << (bit_idx % 32));

    }

    result = 1;

  } while (false);

  return result;
}

uint8_t
uint128_get_bit_string(
                       UINT128* ui128,
                       char* bit_str_buf,
                       uint32_t bit_str_buf_len
                      )
{
  uint8_t result = 0;
  uint32_t needed_len = 0;
  uint32_t dw;
  uint32_t k = 0;
  
  do {
      
    if (!ui128 || !bit_str_buf) break;

    needed_len = UINT128_BYTES_COUNT * 8 + 1;

    if (bit_str_buf_len < needed_len) break;

    for (uint8_t i = 0; i < UINT128_DWORDS_COUNT; i++) {

      dw = ui128->data.dwordData[i];

      for (int8_t j = 31; j >= 0; j--) {

        bit_str_buf[k++] = ((dw & (1 << j))?1:0) + 0x30;

      }

    }
    
    result = 1;

  } while (false);

  return result;

}

uint8_t
uint128_get_bit_string_reverse(
                               UINT128* ui128,
                               char* bit_str_buf,
                               uint32_t bit_str_buf_len
                               )
{
  uint8_t result = 0;
  uint32_t needed_len = 0;
  uint32_t dw;
  uint32_t k = 0;
  
  do {
      
    if (!ui128 || !bit_str_buf) break;

    needed_len = UINT128_BYTES_COUNT * 8 + 1;

    if (bit_str_buf_len < needed_len) break;

    for (int8_t i = UINT128_DWORDS_COUNT - 1; i >= 0; i--) {

      dw = ui128->data.dwordData[i];

      for (int8_t j = 0; j < 32; j++) {

        bit_str_buf[k++] = ((dw & (1 << j))?1:0) + 0x30;

      }

    }
    
    result = 1;

  } while (false);

  return result;

}

uint8_t
uint128_get_bit_value(
                      UINT128* ui128,
                      uint32_t bit_idx
                      )
{
  uint8_t result = 0;

  do {

    result = bit_idx < 128 ? (ui128->data.dwordData[3 - (bit_idx/32)] >> (bit_idx % 32)) & 1 : 0;

  } while (false);

  return result;
}

uint8_t
uint128_get_bit_value_reverse(
                              UINT128* ui128,
                              uint32_t bit_idx
                             )
{
  uint8_t result = 0;

  do {

    if (!ui128) break;

    result = bit_idx < 128 ? (ui128->data.dwordData[bit_idx/ 32] >> (31 - (bit_idx % 32))) & 1 : 0;


  } while (false);

  return result;
}

uint8_t
uint128_set_bit_value_reverse(
                              UINT128* ui128,
                              uint32_t bit_idx,
                              uint8_t bit_val
                             )
{
  uint8_t result = 0;

  do {

    if (!ui128 || bit_idx > 127) break;

    if (bit_val) {

      ui128->data.dwordData[bit_idx / 32] |= 1 << (31 - (bit_idx % 32));

    } else {
      
      ui128->data.dwordData[bit_idx / 32] &= ~(1 << (31 - (bit_idx % 32)));

    }

    result = 1;

  } while (false);

  return result;
}

uint8_t
uint128_compare(
                UINT128* f,
                UINT128* s
               )
{
  uint8_t result = 0;

  do {
    
    if (!f || !s) break;

    for (uint8_t i = 0; i < 4; i++){

      if (f->data.dwordData[i] > s->data.dwordData[i]){

        result = 1;

        break;

      } else if (f->data.dwordData[i] < s->data.dwordData[i]) {
        
        result = 0xff;

        break;

      }

    }

  } while (false);

  return result;
}

uint8_t
uint128_shift_left(
                   UINT128* ui128,
                   uint8_t bit_count,
                   UINT128* ui128_res
                  )
{
  uint8_t result = 0;
  int32_t idx_shift = 0;
  int64_t shifted = 0;
  int32_t i = 0;
  uint32_t shift_res[4] = {0};

  do {

    if (!ui128) break;

    if (bit_count > 127) {

      memset(ui128, 0, sizeof(UINT128));

    } else {

      idx_shift = bit_count / 32;

      for (i = 3; i >= idx_shift; i--){

        shifted += ((int64_t)ui128->data.dwordData[i]) << (bit_count % 32);

        shift_res[i - idx_shift] = (uint32_t)shifted;

        shifted >>= 32;

      }

      if (ui128_res) {

        memcpy(ui128_res, shift_res, sizeof(UINT128));

      } else {
        
        memcpy(ui128, shift_res, sizeof(UINT128));

      }

    }

  } while (false);

  return result;
}

uint8_t
uint128_add(
            UINT128* f,
            UINT128* s,
            UINT128* r
            )
{
  uint8_t result = 0;
  LARGE_INT sum = {0};
  uint32_t sum_res[4] = {0};

  do {

    if (!f || !s) break;

    for (int8_t i = 3; i >= 0; i--) {
      
      sum.quad_part += f->data.dwordData[i];

      sum.quad_part += s->data.dwordData[i];

      sum_res[i] = sum.low_part;

      sum.low_part = sum.high_part;

      sum.high_part = 0;

    }

    if (r) {

      memcpy(r, sum_res, sizeof(UINT128));

    } else {

      memcpy(f, sum_res, sizeof(UINT128));
      
    }

    result = 1;

  } while (false);

  return result;
}

uint8_t
uint128_add_dword(
                  UINT128* f,
                  uint32_t dw,
                  UINT128* r
                 )
{
  uint8_t result = 0;
  UINT128 s;

  do {

    memset(&s, 0, sizeof(s));

    s.data.dwordData[3] = dw;

    result = uint128_add(f, &s, r);

  } while (false);

  return result;
}

uint8_t
uint128_substract(
                  UINT128* f,
                  UINT128* s,
                  UINT128* r
                 )
{
  uint8_t result = 0;
  LARGE_INT sub = {0};
  uint32_t sub_res[4] = {0};
  uint8_t carry = 0;

  do {

     if (!f || !s) break;

     for (int8_t i = 3; i >= 0; i--) {
      
       sub.quad_part += f->data.dwordData[i] - carry;

       sub.quad_part -= s->data.dwordData[i];

       sub_res[i] = sub.low_part;

       if ((int32_t)(f->data.dwordData[i] - carry) < (int32_t)s->data.dwordData[i]) carry = 1; else carry = 0;

       sub.high_part = sub.low_part = 0;

     }
      
     if (r) {

       memcpy(r, sub_res, sizeof(UINT128));

     } else {
      
       memcpy(f, sub_res, sizeof(UINT128));

     }

    result = 1;

  } while (false);

  return result;
}

uint8_t
uint128_substract_dword(
                        UINT128* f,
                        uint32_t dw,
                        UINT128* r
                       )
{
  uint8_t result = 0;
  UINT128 s;

  do {

    memset(&s, 0, sizeof(s));

    s.data.dwordData[3] = dw;

    result = uint128_substract(f, &s, r);

  } while (false);

  return result;
}

uint8_t
uint128_compare_dword(
                      UINT128* f,
                      uint32_t dw
                     )
{
  uint8_t result = 0;

  do {

   if (f->data.dwordData[0] > 0 || f->data.dwordData[1] > 0 || f->data.dwordData[2] > 0 || f->data.dwordData[3] > dw) result = 1;

   else if (f->data.dwordData[3] < dw) result = 0xff;

   else result = 0;

  } while (false);

  return result;
}

uint8_t
uint128_init(
             UINT128* f,
             uint8_t v
            )
{
  uint8_t result = 0;

  do {

    if (!f) break;

    memset(f, v, sizeof(UINT128));

    result = 1;

  } while (false);

  return result;
}

uint8_t
uint128_copy_bits_be(
                     UINT128* s,
                     UINT128* d,
                     uint32_t num_bits,
                     bool rand_rem
                     )
{
  uint8_t result = 0;
  uint32_t num = 0;


  do {

    if (!s || !d) break;

    num = num_bits / 32;

    for (uint8_t i = 0; i < num; i++){

      d->data.dwordData[i] = s->data.dwordData[i];

    }

    for (uint8_t i = (32 * num); i < num_bits; i++){

      uint128_set_bit_value_reverse(
                                    d,
                                    i,
                                    uint128_get_bit_value_reverse(s, i)
                                    );

    }

    if (rand_rem){

      for (uint8_t i = num_bits; i < 128; i++){

        uint128_set_bit_value_reverse(d, i, random_uint32() % 2);

      }

    }

    result = 1;
  
  } while (false);

  return result;
}

uint8_t
uint128_emit(
             UINT128* ui128,
             void* buf,
             uint32_t buf_size
            )
{
  uint8_t result = 0;

  do {

    if (!ui128 || !buf) break;

    if (buf_size < sizeof(UINT128)) break;

    memcpy(buf, ui128, sizeof(UINT128));

    result = 1;

  } while (false);

  return result;
}

uint8_t
uint128_emit_be(
                UINT128* ui128,
                void* buf,
                uint32_t buf_size
               )
{
  uint32_t result = 0;
  uint32_t* p = NULL;

  do {

    if (!ui128 || !buf) break;

    if (buf_size < sizeof(UINT128)) break;

    p = (uint32_t*)buf;

    for (uint8_t i = 0; i < UINT128_DWORDS_COUNT; i++){

      p[i] = BSWAP32(ui128->data.dwordData[i]);

    }

    result = 1;

  } while (false);

  return result;
}

uint8_t
uint128_copy(
             UINT128* s,
             UINT128* d
            )
{
  uint8_t result = 0;

  do {

    if (!s || !d) break;

    memcpy(d, s, sizeof(UINT128));

    result = 1;

  } while (false);

  return result;
}

