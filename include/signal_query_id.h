#ifndef _SIGNAL_QUERY_IDKEY_H_
#define _SIGNAL_QUERY_IDKEY_H_

#include "signal_protocol.h"
#include "signal_protocol_types.h"
#include "rsig_signal_helper.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define SIG_PUBKEY_MAGIC (uint8_t)0x05

typedef enum {
  COMPATIBILITY = 0, /*
		      * whether this implementation support idkey querying,
		      * key_data must be NULL in this mode. returns zero when
		      * supporting, maybe SG_ERR_INVAL if not supporting.
		      */
  
  KEYDATA,
  TRUST_LEVEL, // Used by functions changing the trust level of an identity key.
  ID_LIST, // Used by functions to query all device id under a name.
  SIG_PUBKEY_LEN = (sizeof(keybytes) + 1),
} Query_IdKey_Mode;

/*
 * This originally is virtually defined in signal_protocol.h, used to query whether
 * an identity key is trusted, but it will be multiplexed as a function to query the
 * identity key of a known remote address.
 */
#define DF_signal_is_trusted_idkey(f) int (f)(const signal_protocol_address* address, \
					      uint8_t* key_data, size_t key_len, \
					      void* user_data)
typedef DF_signal_is_trusted_idkey(signal_is_trusted_idkey_ft);

/*
 * Converted from the prototype above, if mode/key_len does not equal to SIG_PUBKEY_LEN,
 * the function will work as signal_query_idkey_ft. 
 */
#define DF_signal_query_idkey(f) int (f)(const signal_protocol_address* address, \
					 uint8_t* key_data, size_t mode, \
					 void* user_data)
typedef DF_signal_query_idkey(signal_query_idkey_ft);

int sig_ext_query_idkey(signal_protocol_store_context* sctx,
			const signal_protocol_address* addr,
			ec_public_key** idkey);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
