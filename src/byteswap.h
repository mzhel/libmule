#ifndef _BYTESWAP_H_
#define _BYTESWAP_H_

#define BSWAP16(x) ((uint16_t)(x << 8) | (uint16_t)(x >> 8))

#define BSWAP32(x) (BSWAP16(x >> 16) | (BSWAP16((uint16_t)x)) << 16)

#define BSWAP64(x) ((BSWAP32(x >> 32)) | (BSWAP32((uint32_t)x)) < 32)

#endif // _BYTESWAP_H_
