#ifndef _UINT128_H_
#define _UINT128_H_

#define UINT128_BYTES_COUNT 16

#define UINT128_WORDS_COUNT UINT128_BYTES_COUNT / 2

#define UINT128_DWORDS_COUNT UINT128_WORDS_COUNT / 2

typedef struct _uint128 {
  union {
    uint32_t dwordData[UINT128_DWORDS_COUNT];
    uint16_t wordData[UINT128_WORDS_COUNT];
    uint8_t byteData[UINT128_BYTES_COUNT];
  } data;
} UINT128;

typedef union _large_int {
  struct {
    uint32_t low_part;
    int32_t high_part;
  };
  struct {
    uint32_t low_part;
    int32_t high_part;
  } u;
  int64_t quad_part;
} LARGE_INT;

uint32_t
uint128_generate(UINT128* ui128);

uint32_t
uint128_from_buffer(
                    UINT128* ui128,
                    uint8_t* buffer,
                    uint32_t bufferLen,
                    bool bigEndian
                    );

uint32_t
uint128_xor(
            UINT128* first, 
            UINT128* second, 
            UINT128* xorRes
            );

uint8_t
uint128_get_bit_string(
                       UINT128* ui128,
                       char* bit_str_buf,
                       uint32_t bit_str_buf_len
                      );

uint8_t
uint128_get_bit_string_reverse(
                               UINT128* ui128,
                               char* bit_str_buf,
                               uint32_t bit_str_buf_len
                               );

uint8_t
uint128_get_bit_value(
                      UINT128* ui128,
                      uint32_t bitIdx
                      );
uint8_t
uint128_get_bit_value_reverse(
                              UINT128* ui128,
                              uint32_t bit_idx
                             );

uint8_t
uint128_set_bit_value(
                      UINT128* ui128,
                      uint32_t bit_idx,
                      uint8_t bit_val
                      );

uint8_t
uint128_set_bit_value_reverse(
                              UINT128* ui128,
                              uint32_t bit_idx,
                              uint8_t bit_val
                             );

uint8_t
uint128_compare(
                UINT128* f,
                UINT128* s
               );

uint8_t
uint128_shift_left(
                   UINT128* ui128,
                   uint8_t bit_count,
                   UINT128* ui128_res
                  );

uint8_t
uint128_add(
            UINT128* f,
            UINT128* s,
            UINT128* r
            );

uint8_t
uint128_add_dword(
                  UINT128* f,
                  uint32_t dw,
                  UINT128* r
                 );

uint8_t
uint128_substract(
                  UINT128* f,
                  UINT128* s,
                  UINT128* r
                 );

uint8_t
uint128_substract_dword(
                        UINT128* f,
                        uint32_t dw,
                        UINT128* r
                       );

uint8_t
uint128_compare_dword(
                      UINT128* f,
                      uint32_t dw
                     );

uint8_t
uint128_init(
             UINT128* f,
             uint8_t v
            );

#define uint128_zero_init(f) uint128_init(f, 0)

uint8_t
uint128_copy_bits_be(
                     UINT128* s,
                     UINT128* d,
                     uint32_t num_bits,
                     bool rand_rem
                    );

uint8_t
uint128_emit(
             UINT128* ui128,
             void* buf,
             uint32_t buf_size
            );

uint8_t
uint128_emit_be(
                UINT128* ui128,
                void* buf,
                uint32_t buf_size
               );

uint8_t
uint128_copy(
             UINT128* s,
             UINT128* d
            );

#ifdef CONFIG_VERBOSE

#define LOG_DEBUG_UINT128(str, ui128) LOG_DEBUG("%s %.8x%.8x%.8x%.8x", str, ui128->data.dwordData[0], ui128->data.dwordData[1], ui128->data.dwordData[2], ui128->data.dwordData[3]);

#else

#define LOG_DEBUG_UINT128(str, id)

#endif

#endif // _UINT128_H_
