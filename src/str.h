#ifndef _STR_H_
#define _STR_H_

bool
str_unicode_to_utf8(
                    wchar_t* uc_str,
                    size_t uc_str_len,
                    char* res_buf,
                    size_t res_buf_len
                   );

bool
str_utf8_to_unicode(
                    char* in_str,
                    size_t in_str_len,
                    wchar_t* out_buf,
                    size_t out_buf_len
                   );

uint32_t
str_wide_len(
             wchar_t* str
            );

uint8_t
str_wide_cmp(
             wchar_t* str1,
             wchar_t* str2
            );

#endif
