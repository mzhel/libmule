#ifndef _TAG_H_
#define _TAG_H_

// Emule tags

#define CT_NAME                     0x01
#define CT_SERVER_UDPSEARCH_FLAGS   0x0e
#define CT_PORT                     0x0f
#define CT_VERSION                  0x11
#define CT_SERVER_FLAGS             0x20
#define CT_EMULECOMPAT_OPTIONS      0xef
#define CT_EMULE_RESERVED1          0xf0
#define CT_EMULE_RESERVED2          0xf1
#define CT_EMULE_RESERVED3          0xf2
#define CT_EMULE_RESERVED4          0xf3
#define CT_EMULE_RESERVED5          0xf4
#define CT_EMULE_RESERVED6          0xf5
#define CT_EMULE_RESERVED7          0xf6
#define CT_EMULE_RESERVED8          0xf7
#define CT_EMULE_RESERVED9          0xf8
#define CT_EMULE_UDPPORTS           0xf9
#define CT_EMULE_MISCOPTIONS1       0xfa
#define CT_EMULE_VERSION            0xfb
#define CT_EMULE_BUDDYIP            0xfc
#define CT_EMULE_BUDDYUDP           0xfd
#define CT_EMULE_MISCOPTIONS2       0xfe
#define CT_EMULE_RESERVED13         0xff

// KAD tags

#define TAG_FILENAME      L"\x01" // <string>
#define TAG_FILESIZE      L"\x02" // <uint32>
#define TAG_FILESIZE_HI   L"\x3a" // <uint32>
#define TAG_FILETYPE      L"\x03" // <string>
#define TAG_FILEFORMAT    L"\x04" // <string>
#define TAG_COLLECTION    L"\x05" // 
#define TAG_PART_PATH     L"\x06" // <string>
#define TAG_PART_HASH     L"\x07" //
#define TAG_COPIED        L"\x08" // <uint32>
#define TAG_GAP_START     L"\x09" // <uint32>
#define TAG_GAP_END       L"\x0a" // <uint32>
#define TAG_DESCRIPTION   L"\x0b" // <string>
#define TAG_PING          L"\x0c" // 
#define TAG_FAIL          L"\x0d" // 
#define TAG_PREFERENCE    L"\x0e" //
#define TAG_PORT          L"\x0f" //
#define TAG_IP_ADDRESS    L"\x10" //
#define TAG_VERSION       L"\x11" // <string>
#define TAG_TEMPFILE      L"\x12" // <string>
#define TAG_PRIORITY      L"\x13" // <uint32>
#define TAG_STATUS        L"\x14" // <uint32>
#define TAG_SOURCES       L"\x15" // <uint32>
#define TAG_AVAILABILITY  L"\x15" // <uint32>
#define TAG_PERMISSIONS   L"\x16" //
#define TAG_QTIME         L"\x16" // 
#define TAG_PARTS         L"\x17" //
#define TAG_PUBLISHINFO   L"\x33" // <uint32>
#define TAG_MEDIA_ARTIST  L"\xd0" // <string>
#define TAG_MEDIA_ALBUM   L"\xd1" // <string>
#define TAG_MEDIA_TITLE   L"\xd2" // <string>
#define TAG_MEDIA_LENGTH  L"\xd3" // <uint32>
#define TAG_MEDIA_BITRATE L"\xd4" // <uint32>
#define TAG_MEDIA_CODEC   L"\xd5" // <string>
#define TAG_KADMISCOPTIONS   L"\xf2" // <uint8>
#define TAG_ENCRYPTION    L"\xf3" // <uint8>
#define TAG_FILERATING    L"\xf7" // <uint8>
#define TAG_BUDDYHASH     L"\xf8" // <string>
#define TAG_CLIENTLOWID   L"\xf9" // <uint32>
#define TAG_SERVERPORT    L"\xfa" // <uint16>
#define TAG_SERVERIP      L"\xfb" // <uint32>
#define TAG_SOURCEUPORT   L"\xfc" // <uint16>
#define TAG_SOURCEPORT    L"\xfd" // <uint16>
#define TAG_SOURCEIP      L"\xfe" // <uint32>
#define TAG_SOURCETYPE    L"\xff" // <uint8>

#define TAGTYPE_HASH16    0x01
#define TAGTYPE_STRING    0x02
#define TAGTYPE_UINT32    0x03
#define TAGTYPE_FLOAT32   0x04
#define TAGTYPE_BOOL      0x05
#define TAGTYPE_BOOLARRAY 0x06
#define TAGTYPE_BLOB      0x07
#define TAGTYPE_UINT16    0x08
#define TAGTYPE_UINT8     0x09
#define TAGTYPE_BSOB      0x0a
#define TAGTYPE_UINT64    0x0b

#define TAG_NAME_ID_FLAG  0x80

typedef struct _tag_string {
  uint16_t len;
  wchar_t data[1];
} TAG_STRING;

typedef struct _tag_hash {
  uint8_t data[16];
} TAG_HASH;

typedef struct _tag_bsob {
  uint8_t len;
  uint8_t data[1];
} TAG_BSOB;

typedef struct  _tag_blob {
  uint32_t len;
  uint8_t data[1];
} TAG_BLOB;

typedef struct _tag {
  uint8_t type;
  uint8_t name_id;
  uint32_t data_offset;
  uint16_t name_len;
  wchar_t name[1];
  union {
    uint8_t   b;
    uint16_t  w;
    uint32_t  dw;
    uint64_t  qw;
    TAG_STRING s;
    TAG_HASH h;
    TAG_BSOB bs;
    TAG_BLOB bl;
  } data;
} TAG;

bool 
tag_create(
           uint8_t type,
           uint8_t name_id,
           wchar_t* name,
           uint64_t val,
           TAG** tag_out
           );

bool
tag_destroy(
            TAG* tag
           );

bool
tag_calc_buf_size(
                  TAG* tag,
                  uint32_t* size_out
                 );

bool
tag_emit(
         TAG* tag,
         uint8_t* buf,
         uint32_t buf_size,
         uint8_t** after_emit_out,
         uint32_t* bytes_emited_out
        );

bool
tag_length(
           uint8_t* buf,
           uint32_t buf_len,
           uint32_t* tag_len_out
          );

bool
tag_read(
         uint8_t* buf,
         uint32_t buf_len,
         bool one_byte_name_is_id,
         TAG** tag_out,
         uint8_t** after_tag_out,
         uint32_t* bytes_read_out
        );

bool
tag_string_get_len(
                   TAG* tag,
                   uint32_t* len_out
                  );

bool
tag_string_get_data(
                    TAG* tag,
                    uint8_t* buf,
                    uint32_t buf_len
                   );

bool
tag_get_name(
             TAG* tag,
             wchar_t* buf,
             uint32_t buf_len
            );

bool
tag_get_id(
           TAG* tag,
           uint32_t* id_out
          );

bool
tag_is_integer(
               TAG* tag
              );

bool
tag_get_integer(
                TAG* tag,
                uint64_t* int_out
               );

bool
tag_is_bsob(
            TAG* tag
           );

bool
tag_bsob_get_len(
                 TAG* tag,
                 uint32_t* len_out
                );

bool
tag_bsob_get_data(
                  TAG* tag,
                  uint8_t* buf,
                  uint32_t buf_len
                 );

#endif // _TAG_H_
