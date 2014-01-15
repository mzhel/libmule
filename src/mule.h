#ifndef _MULE_H_
#define _MULE_H_

#define OP_EDONKEYHEADER 0xe3
#define OP_EDONKEYPROT OP_EDONKEYHEADER
#define OP_EMULEPROT 0xc5

// Edonkey opcodes

#define OP_HELLO       0x01
#define OP_HELLOANSWER 0x4c

// Extended opcodes.

#define OP_FWCHECKUDPREQ      0xa7
#define OP_KAD_FWTCPCHECK_ACK 0xa8

// File operations.

#define OP_REQUESTFILENAME  0x58
#define OP_SETREQFILEID     0x4f
#define OP_AICHFILEHASHREQ  0x9e

#define OP_MULTIPACKET      0x92
#define OP_MULTIPACKET_EXT  0xa4

#define OP_MULTIPACKETANSWER    0x93
#define OP_REQFILENAMEANSWER    0x59
#define OP_HASHSETREQUEST       0x51
#define OP_FILESTATUS           0x50
#define OP_AICHFILEHASHANS      0x9d
#define OP_STARTUPLOADREQ       0x54
#define OP_HASHSETANSWER        0x52
#define OP_FILEREQANSNOFIL      0x48
#define OP_ACCEPTUPLOADREQ      0x55
#define OP_REQUESTPARTS         0x47
#define OP_SENDINGPART          0x46
#define OP_COMPRESSEDPART       0x40
#define OP_END_OF_DOWNLOAD      0x49
#define OP_CANCELTRANSFER       0x56
#define OP_OUTOFPARTREQS        0x57

#define OP_REQUESTSOURCES       0x81
#define OP_ANSWERSOURCES        0x82
#define OP_REQUESTSOURCES2      0x83
#define OP_ANSWERSOURCES2       0x84

#define EDONKEYVERSION  0x3c

#define SO_AMULE    3

#define	VERSION_MJR		2
#define	VERSION_MIN		2
#define	VERSION_UPDATE		6

#define  MAKE_FULL_ED2K_VERSION(a, b, c)\
((a << 17) | (b << 10) | (c << 7))

#define IP_NONE			        0
#define IP_EDONKEYPROTPACK	1
#define IP_EMULEPROTPACK	  2
#define IP_BOTH			        3

#define EMULE_DEFAULT_BLOCK_SIZE    92160
#define EMULE_REQUEST_BLOCKS_COUNT  3

typedef struct _mule_misc_opts_1 {
  uint32_t udp_ver;
  uint32_t data_comp_ver;
  uint32_t support_sec_ident;
  uint32_t source_exchange_ver;
  uint32_t extended_requests_ver;
  uint32_t accept_comment_ver;
  uint32_t no_view_shared_files;
  uint32_t multi_packet;
  uint32_t support_preview;
  uint32_t peer_cache;
  uint32_t unicode_support;
  uint32_t AICH_ver;
} MULE_MISC_OPTS_1;

typedef struct _mule_misc_opts_2 {
  uint32_t kad_version;
  uint32_t support_large_files;
  uint32_t ext_multi_packet;
  uint32_t reserved;
  uint32_t supports_crypt_layer;
  uint32_t requests_crypt_layer;
  uint32_t requires_crypt_layer;
  uint32_t supports_source_ex2;
  uint32_t direct_udp_callback;
} MULE_MISC_OPTS_2;

typedef struct _mule_compat_opts {
  uint8_t value_based_type_tags:1;
  uint8_t os_info_support:1;
} MULE_COMPAT_OPTS;

typedef struct _mule_request_block {
  uint64_t start;
  uint64_t length;
} MULE_REQUEST_BLOCK;

typedef struct _kad_mule {
  uint16_t udp_port;
} KAD_MULE;



#endif // _MULE_H_
