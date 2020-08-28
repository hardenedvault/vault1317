#ifndef _HASHER_H_
#define _HASHER_H_

#include <assert.h>
#include "signal_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define DF_digest_size(func) int (func)(const void* digest_context, \
					void* user_data)
typedef DF_digest_size(digest_size_ft);

#define DF_digest_init(func) int (func)(void** digest_context, \
					void* user_data)
typedef DF_digest_init(digest_init_ft);

#define DF_digest_update(func) int (func)(void* digest_context, \
					  const uint8_t* data,	\
					  size_t data_len,	\
					  void* user_data)
typedef DF_digest_update(digest_update_ft);

#define DF_digest_final(func) int (func)(void* digest_context,	 \
					 signal_buffer** output, \
					 void* user_data)
typedef DF_digest_final(digest_final_ft);

#define DF_digest_cleanup(func) void (func)(void* digest_context, \
					    void* user_data)
typedef DF_digest_cleanup(digest_cleanup_ft);

typedef struct hasher_imp {
  const char* name;
  digest_init_ft* init;
  digest_update_ft* update;
  digest_final_ft* final;
  digest_cleanup_ft* cleanup;
} hasher_imp;

typedef struct hasher {
  const hasher_imp* imp;
  void* user_data;
} hasher;

static inline void hasher_init(hasher* h,
			       const hasher_imp* imp,
			       void* user_data)
{
  h->imp = imp;
  h->user_data = user_data;
}

static inline int hasher_ctx_init(hasher* h,
				  void **digest_context)
{
  assert(h);
  assert(h->imp);
  assert(h->imp->init);
  return h->imp->init(digest_context, h->user_data);
}

static inline int hasher_update(hasher* h,
				void *digest_context,
				const uint8_t *data,
				size_t data_len)
{
  assert(h);
  assert(h->imp);
  assert(h->imp->update);
  return h->imp->update(digest_context, data, data_len, h->user_data);
}

static inline int hasher_final(hasher* h,
			       void *digest_context,
			       signal_buffer **output)
{
  assert(h);
  assert(h->imp);
  assert(h->imp->final);
  return h->imp->final(digest_context, output, h->user_data);
}

static inline void hasher_ctx_cleanup(hasher* h,  void *digest_context)
{
  assert(h);
  assert(h->imp);
  assert(h->imp->cleanup);
  return h->imp->cleanup(digest_context, h->user_data);
}

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
