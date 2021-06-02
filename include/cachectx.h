#ifndef _CACHECTX_H_
#define _CACHECTX_H_

#include "axc_helper.h"
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

enum CACHECTX_SPECIAL_COMMAND {
  CACHECTX_COMMIT_RECORD = 1,
};

typedef struct sig_store_backend {
  signal_protocol_session_store sess_tmpl;
} sig_store_backend;

typedef struct axc_context_dake_cache {
  axc_context_dake base;
  sig_store_backend backend;
  GHashTable* sess_cache;
  uint32_t faux_regid;
  int has_offline_msg;
} axc_context_dake_cache;

typedef struct sess_cache_value {
  signal_buffer* rec;
  signal_buffer* urec;
} sess_cache_value;

/* duplicate a signal_protocol_address to the heap */
signal_protocol_address* sigaddr_heap_dup(const signal_protocol_address* a);

/* free a signal_protocol_address produced by sigaddr_heap_dup() */
void sigaddr_heap_free(signal_protocol_address* a);

int cachectx_create(axc_context_dake_cache ** ctx_pp);
void cachectx_destroy_all(axc_context * ctx_p);
int backend_is_good(const sig_store_backend* backend);
int cachectx_has_good_backend(const axc_context_dake_cache* ctx_p);

sess_cache_value* sess_cache_value_new(const uint8_t* rec, size_t rec_len,
				       const uint8_t* urec, size_t urec_len);
void sess_cache_value_free(sess_cache_value* v);
void cachectx_bind_backend(axc_context_dake_cache* ctx_p,
			   const signal_protocol_session_store* sess_tmpl);

void cachectx_set_faux_regid(axc_context_dake_cache* ctx_p,
			     uint32_t faux_regid);
uint32_t cachectx_get_faux_regid(const axc_context_dake_cache* ctx_p);
int cachectx_has_offline_msg(const axc_context_dake_cache* ctx_p);
void cachectx_set_offline_msg_state(axc_context_dake_cache* ctx_p, int state);

extern const signal_protocol_session_store cachectx_sess_store_tmpl;
#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
