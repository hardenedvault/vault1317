#include "simpletlv.h"
#include <string.h>
#include <stdlib.h>

static const void* my_memmem(const void *haystack, size_t haystacklen,
		       const void *needle, size_t needlelen)
{
  do {
    const void* target = memchr(haystack, *(const uint8_t*)needle, haystacklen);
    if ((target == NULL) // even first byte has no occurence.
	|| (0 == memcmp(target, needle, needlelen)))
      return target;
    else { //only first byte match
      haystacklen -= ((const uint8_t*)target - (const uint8_t*)haystack + 1);
      // retry from (target + 1)
      haystack = (const uint8_t*)target + 1;
    }
    // remain length less than needle, no match
  } while (haystacklen < needlelen);
  return NULL;
}

static size_t stlv_get_msg_len(const stlv_descriptor* desc,
			       const void* magic, size_t datalen,
			       int* msg_is_complete)
{
  const uint8_t* msglenp = (const uint8_t*)magic + desc->magic_len;
  size_t msglen = (msglenp[1] << 8) | msglenp[0];
  if (msg_is_complete)
    *msg_is_complete = (datalen >= stlv_header_len(desc) + msglen);
  return msglen;
}

static void stlv_parser_deliver_buf_and_new_data(stlv_parser* ctx,
						 const void* data)
{
  vpool_insert(&ctx->buf, UINT16_MAX, (void*)data, ctx->lack_len);
  ctx->lack_len = 0;
  size_t msglen = stlv_get_msg_len(ctx->desc, vpool_get_buf(&ctx->buf),
				   vpool_get_length(&ctx->buf), NULL);
  ctx->desc->found(ctx->userdata,
		  (const uint8_t*) vpool_get_buf(&ctx->buf)
		  + stlv_header_len(ctx->desc),
		  msglen);
}

int stlv_parser_feed(stlv_parser* ctx, const void* data, size_t len)
{
  int msg_num = 0;
  const void* magic = my_memmem(data, len,
				ctx->desc->magic,
				ctx->desc->magic_len);
  size_t msglen = 0;
  size_t mg_off = 0;
  size_t part_len = 0;
  if (magic) {
    mg_off = (const uint8_t*)magic - (const uint8_t*)data;
    if (ctx->lack_len) {
      /*
       * there is a partial message stored in buffer,
       * which needs to be processed first.
       */
      if (mg_off >= ctx->lack_len) {
	/*
	 * insert {data, ctx->lack_len} into buffer,
	 * and deliver buffer content.
	 */
	stlv_parser_deliver_buf_and_new_data(ctx, data);
	msg_num++;
      } else {
	/*
	 * otherwise, stored partial message is prematurely terminated,
	 * discard it.
	 */
	ctx->lack_len = 0;
      }
      vpool_reset(&ctx->buf);
    }
    // check whether a message lies after (void*)magic.
    part_len = len - mg_off;
    while (magic) {
      int msg_is_complete = false;
      msglen = stlv_get_msg_len(ctx->desc, magic, part_len,
				&msg_is_complete);
      if (msg_is_complete) {
	// a complete message lies in {magic, part_len}, deliver it.
	ctx->desc->found(ctx->userdata,
			(const uint8_t*)magic + stlv_header_len(ctx->desc),
			msglen);
	msg_num++;
	// find next magic.
	magic = my_memmem((const uint8_t*)magic + stlv_header_len(ctx->desc) + msglen,
			  part_len - stlv_header_len(ctx->desc) - msglen,
			  ctx->desc->magic,
			  ctx->desc->magic_len);
	part_len = (const uint8_t*)data + len - (const uint8_t*)magic;
      } else {
	// insert new partial message into buffer.
	vpool_insert(&ctx->buf, UINT16_MAX, (void*)magic, part_len);
	ctx->lack_len = msglen + stlv_header_len(ctx->desc) - part_len;
	break;
      }
    }
  } else if (ctx->lack_len) {
    if (len >= ctx->lack_len) {
      /*
       * insert {data, ctx->lack_len} into buffer,
       * and deliver buffer content, and discard remain data.
       */
      stlv_parser_deliver_buf_and_new_data(ctx, data);
      msg_num++;
      vpool_reset(&ctx->buf);
    } else {
      vpool_insert(&ctx->buf, UINT16_MAX, (void*)magic, part_len);
      ctx->lack_len -= len;
    }
  }
  // otherwise, ignore data.
  return msg_num;
}

void stlv_parser_init(stlv_parser* ctx,
		      const stlv_descriptor* desc, void* userdata,
		      size_t blksize, size_t limit)
{
  ctx->desc = desc;
  ctx->userdata = userdata;
  vpool_init(&ctx->buf, blksize, limit);
  ctx->lack_len = 0;
}

void stlv_parser_uninit(stlv_parser* ctx)
{
  vpool_final(&ctx->buf);
  ctx->desc = NULL;
  ctx->userdata = NULL;
  ctx->lack_len = 0;
}

static void stlv_fill_header(const stlv_descriptor* desc,
			     uint8_t* header, size_t msglen)
{
  memcpy(header, desc->magic, desc->magic_len);
  header[desc->magic_len] = msglen & 0xff;
  header[desc->magic_len + 1] = (msglen >> 8) & 0xff;
}

void* stlv_make_header(const stlv_descriptor* desc, size_t msglen)
{
  uint8_t* header = (uint8_t*)malloc(stlv_header_len(desc));
  stlv_fill_header(desc, header, msglen);
  return header;
}

void* stlv_assemble_msg(const stlv_descriptor* desc,
			const void* body, size_t bodylen)
{
  size_t rawlen = stlv_header_len(desc) + bodylen;
  uint8_t* msg = (uint8_t*)malloc(rawlen);
  stlv_fill_header(desc, msg, bodylen);
  memcpy(&msg[stlv_header_len(desc)], body, bodylen);
  return msg;
}
