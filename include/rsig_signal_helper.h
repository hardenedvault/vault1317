#ifndef _RSIG_SIGNAL_HELPER_H_
#define _RSIG_SIGNAL_HELPER_H_

#include "keymap.h"
#include "signal_protocol_internal.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define DJB_PUBKEY_MAGIC 0x05

/* 
 * This structure below is essentially identical to 
 * ec_public_key and ec_private_key
 */
typedef struct ec_key
{
    signal_type_base base;
    keybytes data;
} ec_key;

static inline const keybytes* ec_key_get_bytes(const ec_key* key)
{
  return &(key->data);
}

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
