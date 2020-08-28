#ifndef _AXC_INTERNAL_TYPES_H_
#define _AXC_INTERNAL_TYPES_H_

#include "axc.h"
#include "signal_internal_types.h"
#ifndef NO_THREADS
#include <pthread.h> // mutex stuff
#endif

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

typedef struct axc_mutexes {
  #ifndef NO_THREADS
  pthread_mutex_t * mutex_p;
  pthread_mutexattr_t * mutex_attr_p;
  #endif
} axc_mutexes;

int axc_mutexes_create_and_init(axc_mutexes ** mutexes_pp);
void axc_mutexes_destroy(axc_mutexes * mutexes_p);

struct axc_context {
    signal_context * axolotl_global_context_p;
    signal_protocol_store_context * axolotl_store_context_p;
    axc_mutexes * mutexes_p;
    char * db_filename;
    void (*log_func)(int level, const char * message, size_t len, void * user_data);
    int log_level;
};

struct axc_buf_list_item {
  uint32_t id;
  axc_buf * buf_p;
  axc_buf_list_item * next_p;
};

struct axc_bundle {
  uint32_t registration_id;
  axc_buf_list_item * pre_keys_head_p;
  uint32_t signed_pre_key_id;
  axc_buf * signed_pre_key_public_serialized_p;
  axc_buf * signed_pre_key_signature_p;
  axc_buf * identity_key_public_serialized_p;
};

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
