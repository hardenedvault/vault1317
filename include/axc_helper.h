#ifndef _AXC_HELPER_H_
#define _AXC_HELPER_H_

#include <sqlite3.h>
#include "axc_crypto.h"
#include "axc_store.h"
#include "axc.h"
#include "signal_query_id.h"
#include "axc_internal_types.h"
#include "clinklst.h"
#include "odake.h"
#include "pbdumper.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

typedef struct axc_context_dake {
  axc_context base;
  cl_node* l_authinfo;
  const pbdumper* dumper;
} axc_context_dake;

#define DF_axc_log_func(x) void (x)(int level, const char * message, size_t len, void * user_data)
typedef DF_axc_log_func(axc_log_func_ft);

int axc_context_dake_create(axc_context_dake ** ctx_pp);
void axc_context_dake_destroy_all(axc_context * ctx_p);
void recursive_mutex_lock(void * user_data);
void recursive_mutex_unlock(void * user_data);

int axc_init_with_imp(axc_context* ctx_p,
		      const signal_protocol_session_store* session_store_tmpl,
		      const signal_protocol_pre_key_store* pre_key_store_tmpl,
		      const signal_protocol_signed_pre_key_store* spk_store_tmpl,
		      const signal_protocol_identity_key_store* idk_store_tmpl,
		      const signal_crypto_provider* crypto_provider_tmpl);

int axc_msg_enc_and_ser_dake(axc_buf * msg_p,
			     const axc_address * recipient_addr_p,
			     axc_context * ctx_p,
			     axc_buf ** ciphertext_pp);

int axc_message_dec_from_ser_dake (axc_buf * msg_p,
				   const axc_address * sender_addr_p,
				   axc_context * ctx_p,
				   axc_buf ** plaintext_pp);

int axc_session_from_bundle_dake(uint32_t pre_key_id,
				 axc_buf * pre_key_public_serialized_p,
				 uint32_t signed_pre_key_id,
				 axc_buf * signed_pre_key_public_serialized_p,
				 axc_buf * signed_pre_key_signature_p,
				 axc_buf * identity_key_public_serialized_p,
				 const axc_address * remote_address_p,
				 axc_context * ctx_p);

int axc_pre_key_message_process_dake(axc_buf * pre_key_msg_serialized_p,
				     const axc_address * remote_address_p,
				     axc_context * ctx_p,
				     axc_buf ** plaintext_pp);

int axc_query_identity_dake(const signal_protocol_address * addr_p,
			    uint8_t * key_data, size_t key_len,
			    void * user_data);

int axc_db_identity_is_trusted_wrapper(const signal_protocol_address * addr_p,
				       uint8_t * key_data,
				       size_t key_len,
				       void * user_data);

int axc_db_identity_save_or_trust(const signal_protocol_address * addr_p,
				  uint8_t * key_data,
				  size_t key_len,
				  void * user_data);

int axc_db_set_identity_trusted_dake(const signal_protocol_address * addr_p,
				     bool trusted,
				     void* user_data);

int axc_Idake_start_for_addr(axc_context_dake* dctx_p,
			     const signal_protocol_address* addr,
			     const signal_buffer** kdmsg);

int axc_Idake_handle_msg(axc_context_dake* dctx_p,
			 const Signaldakez__IdakeMessage* msg,
			 const signal_protocol_address* addr,
			 const signal_buffer** lastauthmsg);

extern const signal_protocol_identity_key_store axc_dakes_identity_key_store_tmpl;

const pbdumper* axc_context_dake_get_dumper(const axc_context_dake* dctx_p);
void axc_context_dake_set_dumper(axc_context_dake* dctx_p, const pbdumper* dumper);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif
#endif
