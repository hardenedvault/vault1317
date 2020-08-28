#ifndef _SIGNAL_INTERNAL_TYPES_H_
#define _SIGNAL_INTERNAL_TYPES_H_

#include "protocol.h"
#include "ratchet.h"
#include "signal_protocol_internal.h"
#include "session_builder.h"
#include "session_state.h"
#include "session_cipher.h"
#include "session_pre_key.h"
#include "signal_protocol_types.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

//This file contains types needed by odake hidden in libs-p-c's source files.

#define DJB_KEY_LEN 32
#define SIGNAL_MESSAGE_MAC_LENGTH 8

struct signal_protocol_store_context {
    signal_context *global_context;
    signal_protocol_session_store session_store;
    signal_protocol_pre_key_store pre_key_store;
    signal_protocol_signed_pre_key_store signed_pre_key_store;
    signal_protocol_identity_key_store identity_key_store;
    signal_protocol_sender_key_store sender_key_store;
};

struct session_builder
{
    signal_protocol_store_context *store;
    const signal_protocol_address *remote_address;
    signal_context *global_context;
};

struct alice_signal_protocol_parameters
{
  signal_type_base base;
  ratchet_identity_key_pair *our_identity_key;
  ec_key_pair *our_base_key;
  ec_public_key *their_identity_key;
  ec_public_key *their_signed_pre_key;
  ec_public_key *their_one_time_pre_key; /* optional */
  ec_public_key *their_ratchet_key; //usually same as their_signed_pre_key
};

struct bob_signal_protocol_parameters
{
  signal_type_base base;
  ratchet_identity_key_pair *our_identity_key;
  ec_key_pair *our_signed_pre_key;
  ec_key_pair *our_one_time_pre_key; /* optional */
  ec_key_pair *our_ratchet_key;
  ec_public_key *their_identity_key;
  ec_public_key *their_base_key;
};

struct ciphertext_message
{
  signal_type_base base;
  int message_type;
  signal_context *global_context;
  signal_buffer *serialized;
};

struct session_cipher
{
    signal_protocol_store_context *store;
    const signal_protocol_address *remote_address;
    session_builder *builder;
    signal_context *global_context;
    int (*decrypt_callback)(session_cipher *cipher, signal_buffer *plaintext, void *decrypt_context);
    int inside_callback;
    void *user_data;
};

struct session_record
{
    signal_type_base base;
    session_state *state;
    session_record_state_node *previous_states_head;
    int is_fresh;
    signal_buffer *user_record;
    signal_context *global_context;
};

int ratcheting_session_calculate_derived_keys(ratchet_root_key **root_key,
					      ratchet_chain_key **chain_key,
					      uint8_t *secret, size_t secret_len,
					      signal_context *global_context);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
