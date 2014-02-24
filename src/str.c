#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <iconv.h>
#include <str.h>
#include <log.h>

bool
str_unicode_to_utf8(
                    wchar_t* uc_str,
                    size_t uc_str_len,
                    char* res_buf,
                    size_t res_buf_len,
                    uint32_t* emited_len_out
                   )
{
  bool result = false;
  iconv_t ic = (iconv_t)-1;
  size_t uc_bytes_len = 0;
  size_t buf_len = 0;

  do {

    if (!uc_str || !res_buf) break;

    uc_bytes_len = uc_str_len * 2;

    ic = iconv_open("UTF-8", "UTF-16LE");

    if (ic == (iconv_t)-1){

      LOG_ERROR("Failed to create iconv descriptor.");

      break;

    }

    buf_len = res_buf_len;

    if (-1 == iconv(ic, (char**)&uc_str, (size_t*)&uc_bytes_len, &res_buf, (size_t*)&res_buf_len)) {

      LOG_ERROR("iconv failed, error code %s (%d).", strerror(errno), errno);

      break;

    }

    LOG_DEBUG("res_buf_len = %.8x, buf_len = %.8x", res_buf_len, buf_len);

    if (emited_len_out) *emited_len_out = buf_len - res_buf_len;

    result = true;

  } while (false);

  if (ic != (iconv_t)-1) iconv_close(ic);

  return result;
}

bool
str_utf8_to_unicode(
                    char* in_str,
                    size_t in_str_len,
                    wchar_t* out_buf,
                    size_t out_buf_len,
                    uint32_t* read_len_out
                   )
{
  bool result = false;
  iconv_t ic = (iconv_t)-1;
  uint32_t read_len = 0;
  uint32_t out_buf_len_base = 0;

  do {

    if (!in_str || !out_buf) break;

    ic = iconv_open("UTF-16LE", "UTF-8");

    if (ic == (iconv_t)-1){

      LOG_ERROR("Failed to create iconv descriptor.");

      break;

    }

    out_buf_len = out_buf_len *sizeof(wchar_t);

    out_buf_len_base = out_buf_len;

    if (-1 == iconv(ic, &in_str, &in_str_len, (char**)&out_buf, &out_buf_len)) {

      LOG_ERROR("iconv failed, error code %s (%d).", strerror(errno), errno);

      break;

    }

    if (read_len_out) *read_len_out = out_buf_len_base - out_buf_len;

    result = true;

  } while (false);

  if (ic != (iconv_t)-1) iconv_close(ic);

  return result;
}

uint32_t
str_wide_len(
             wchar_t* str
            )
{
  uint32_t result = 0;

  while (*str != 0) {

    result++;

    str++;

  }

  return result;
}

uint8_t
str_wide_cmp(
             wchar_t* str1,
             wchar_t* str2
            )
{
  uint8_t result = 0;
  uint32_t len1 = 0;
  uint32_t len2 = 0;

  do {
    
    if (!str1 || !str2) break;

    len1 = str_wide_len(str1);

    len2 = str_wide_len(str2);

    if (len1 > len2) {

      result = 1;

      break;

    }

    if (len1 < len2){

      result = 0xff;

      break;

    }

    for (uint32_t i = 0; i < len1; i++){

      if (str1[i] > str2[i]) {

        result = 1;

        break;

      } else if (str1[i] < str2[i]) {

        result = 0xff;

        break;

      }

    }

  } while (false);

  return result;
}
