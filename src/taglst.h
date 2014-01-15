#ifndef _TAGLST_H_
#define _TAGLST_H_

bool
tag_list_emit(
              LIST* tl,
              uint8_t* buf,
              uint32_t buf_len,
              bool count_u32,
              uint8_t** buf_after_out,
              uint32_t* rem_len_out
             );

bool
tag_list_add(
            LIST** tl_ptr,
            TAG* t
           );

bool
tag_list_calc_buffer_length(
                            LIST* tl,
                            bool count_u32,
                            uint32_t* len_out
                           );

#endif // _TAGLST_H_
