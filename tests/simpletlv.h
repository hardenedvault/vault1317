#ifndef _SIMPLETLV_H_
#define _SIMPLETLV_H_

#include <stdint.h>
#include <stdbool.h>
#include "vpool.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define DF_stlv_found(x)						\
  void (x)(void* userdata, const uint8_t* incoming_data,		\
	   size_t incoming_len)

typedef DF_stlv_found(stlv_found_ft);

struct stlv_descriptor {
  const uint8_t* magic;
  size_t magic_len;
  stlv_found_ft* found;
};
typedef struct stlv_descriptor stlv_descriptor;

static inline size_t stlv_header_len(const stlv_descriptor* desc)
{return desc->magic_len + sizeof(uint16_t);}

typedef enum {
    SP_IDLE,
    SP_WAIT
}stlv_parser_state;

struct stlv_parser {
  const stlv_descriptor* desc;
  void* userdata;
  struct vpool buf;
  size_t lack_len;
};
typedef struct stlv_parser stlv_parser;

int stlv_parser_feed(stlv_parser* ctx, const void* data, size_t len);
void stlv_parser_init(stlv_parser* ctx,
		      const stlv_descriptor* desc, void* userdata,
		      size_t blksize, size_t limit);
void stlv_parser_uninit(stlv_parser* ctx);
void* stlv_make_header(const stlv_descriptor* desc, size_t msglen);
void* stlv_assemble_msg(const stlv_descriptor* desc,
			const void* body, size_t bodylen);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
