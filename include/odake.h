#ifndef _ODAKE_H_
#define _ODAKE_H_

#include "idake.h"
#include "signal_internal_types.h"
#include "signal_query_id.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define HASH_OUTPUT_SIZE 32
#define DERIVED_MESSAGE_SECRETS_SIZE 80
#define DERIVED_ROOT_SECRETS_SIZE 64
#define CIPHERTEXT_ODAKE_PREKEY_TYPE (8+3)

typedef struct session_pending_pre_key
{
    int has_pre_key_id;
    uint32_t pre_key_id;
    uint32_t signed_pre_key_id;
    ec_public_key *base_key;
} session_pending_pre_key;

typedef struct pre_key_odake_message
{
  ciphertext_message base_message;
  uint8_t version;
  uint32_t registration_id;//ID[a]
  int has_pre_key_id;
  uint32_t pre_key_id;//i
  uint32_t signed_pre_key_id;//j
  ec_public_key* alice_basekey;//g^E[a,0]
  ec_public_key* alice_idkey;//g^I[a]
  signal_buffer* mac;//M
  signal_buffer* rsig;//P
  signal_buffer* ek;
  signal_buffer* enc_idmsg;//cache before post_deserialization
  signal_message* payload;
} pre_key_odake_message;

int ratcheting_session_alice_initialize_odake(session_state *state,
					      alice_signal_protocol_parameters *parameters,
					      signal_context *global_context);

int ratcheting_session_bob_calc_ss_odake(signal_buffer** shared_secret,
					 bob_signal_protocol_parameters *parameters,
					 signal_context *global_context);

int Odake_verify_signed_pre_key(ec_public_key* r_idkey, ec_public_key* r_spk,
				const uint8_t* sig, size_t sig_len);

//The idkey in the bundle is ignored, and a bundle for odake should not contain an idkey in the first place.
int session_builder_process_pre_key_bundle_odake(session_builder *builder, session_pre_key_bundle *bundle);

void session_state_set_pending_pre_key(session_state* state,
				       session_pending_pre_key* ppk);

void session_state_get_pending_pre_key(session_state* state,
				       session_pending_pre_key* ppk);

void unref_pending_pre_key(session_pending_pre_key* ppk);

int Odake_derive_ek(signal_context *gctx,
		    const uint8_t* sharedsec,
		    size_t ss_len,
		    symskey* ek);

int Odake_derive_mk(signal_context *gctx,
		    const symskey* ek,
		    symkey* mk);

int session_state_store_ek_dirty(signal_context* gctx,
				 session_state *state, const symskey* ek);

int session_state_get_ek_dirty(signal_context* gctx,
			       session_state *state, symskey* ek);

int session_state_restore_idkeys_odake(session_builder *builder,
				       session_state *state);

int pre_key_odake_message_serialize(signal_buffer **buffer,
				    const pre_key_odake_message *message);

int pre_key_odake_message_pre_deserialize(pre_key_odake_message** message,
					  const uint8_t* data, size_t len,
					  signal_context* gctx);

int pre_key_odake_message_is_pre_deserialized(const pre_key_odake_message* message);

int pre_key_odake_message_is_post_deserialized(const pre_key_odake_message* message);

int pre_key_odake_message_post_deserialize(pre_key_odake_message* message,
					   const uint8_t* ek_buf, size_t ek_len);

int bob_parameters_from_pre_key_msg(signal_protocol_store_context* sctx,
				    const pre_key_odake_message *message,
				    bob_signal_protocol_parameters **bob_param);

int pre_key_odake_message_handshake(signal_context *gctx,
				    pre_key_odake_message *message,
				    bob_signal_protocol_parameters *bob_param,
				    uint32_t l_regid,
				    signal_buffer** result_ss);

int pre_key_odake_message_init_session(const pre_key_odake_message *message,
				       const bob_signal_protocol_parameters *bob_param,
				       uint32_t l_regid,
				       signal_buffer* sharedsec,
				       session_state* state,
				       signal_context* gctx);

int pre_key_odake_message_get_unsigned_pre_key_id(const pre_key_odake_message *message,
						  uint32_t *unsigned_pre_key_id);

int pre_key_odake_message_create(pre_key_odake_message **message,
				 uint8_t version,
				 uint32_t our_regid,
				 uint32_t their_regid,
				 const uint32_t *pre_key_id,
				 uint32_t signed_pre_key_id,
				 ec_public_key *our_basekey,
				 ec_public_key *their_pre_key,
				 ec_public_key *their_idkey,
				 ec_key_pair *our_idkey,
				 const uint8_t* ek_buf,
				 size_t ek_len,
				 signal_message *payload,
				 signal_context *gctx);

int pre_key_odake_message_copy(pre_key_odake_message **newmsg,
			       pre_key_odake_message *srcmsg,
			       signal_context *gctx);

int session_builder_process_pre_key_odake_message(session_builder *builder,
						  session_record *record,
						  pre_key_odake_message *message,
						  uint32_t *unsigned_pre_key_id);

int session_cipher_encrypt_odake_wrapper(session_cipher *cipher,
					 const uint8_t *padded_message,
					 size_t padded_message_len,
					 ciphertext_message **encrypted_message);

int session_cipher_decrypt_pre_key_odake_message_wrapper(session_cipher *cipher,
							 pre_key_odake_message *omsg,
							 void *decrypt_context,
							 signal_buffer **plaintext);

int session_cipher_decrypt_signal_message_wrapper(session_cipher *cipher,
						  signal_message *ciphertext,
						  void *decrypt_context,
						  signal_buffer **plaintext);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
