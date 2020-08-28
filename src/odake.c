#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "vpool.h"
#include "DakesProtocol.pb-c.h"
#include "signal_query_id.h"
#include "hkdf.h"
#include "odake.h"
#include "pbdumper.h"

/*
 * ratchet_identity_key_pair is definitionally identical to ec_key_pair,
 * except to be destroyed by ratchet_identity_key_pair_destroy().
 */

int ratcheting_session_alice_initialize_odake(session_state *state,
					      alice_signal_protocol_parameters *parameters,
					      signal_context *global_context)
{
  int result = 0;
  uint8_t *agreement = 0;
  int agreement_len = 0;
  ec_key_pair *sending_ratchet_key = 0;
  struct vpool vp;
  const uint8_t* sharedsec = 0;
  size_t ss_len = 0;
  symskey ek;

  assert(state);
  assert(parameters);
  assert(global_context);

  vpool_init(&vp, 1024, 0);

  result = curve_generate_key_pair(global_context, &sending_ratchet_key);
  if(result < 0) {
    goto complete;
  }

  if(parameters->their_one_time_pre_key) {
    agreement_len
      = curve_calculate_agreement(&agreement,
				  parameters->their_one_time_pre_key,
				  ec_key_pair_get_private(parameters->our_base_key));
    if(agreement_len < 0) {
      result = agreement_len;
      goto complete;
    }
    if(vpool_insert(&vp, vpool_get_length(&vp), agreement, (size_t)agreement_len)) {
      free(agreement); agreement = 0; agreement_len = 0;
    }
    else {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  {
    agreement_len
      = curve_calculate_agreement(&agreement,
				  parameters->their_signed_pre_key,
				  ec_key_pair_get_private(parameters->our_base_key));
    if(agreement_len < 0) {
      result = agreement_len;
      goto complete;
    }
    if(vpool_insert(&vp, vpool_get_length(&vp), agreement, (size_t)agreement_len)) {
      free(agreement); agreement = 0; agreement_len = 0;
    }
    else {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  {
    agreement_len
      = curve_calculate_agreement(&agreement,
				  parameters->their_identity_key,
				  ec_key_pair_get_private(parameters->our_base_key));
    if(agreement_len < 0) {
      result = agreement_len;
      goto complete;
    }
    if(vpool_insert(&vp, vpool_get_length(&vp), agreement, (size_t)agreement_len)) {
      free(agreement); agreement = 0; agreement_len = 0;
    }
    else {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  if(vpool_is_empty(&vp)) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  sharedsec = vpool_get_buf(&vp);
  ss_len = vpool_get_length(&vp);

  result = session_state_init_session(global_context,
				      state,
				      sharedsec,
				      ss_len,
				      parameters->their_ratchet_key,
				      sending_ratchet_key);
  if(result < 0) {
    goto complete;
  }

  result = Odake_derive_ek(global_context, sharedsec, ss_len, &ek);
  if(result < 0) {
    goto complete;
  }

  result = session_state_store_ek_dirty(global_context, state, &ek);
  if(result < 0) {
    goto complete;
  }

  session_state_set_session_version(state, CIPHERTEXT_CURRENT_VERSION);

complete:
    vpool_final(&vp);
    free(agreement);
    SIGNAL_UNREF(sending_ratchet_key);
    memset(&ek, 0, sizeof(ek));

    return result;
}

int ratcheting_session_bob_calc_ss_odake(signal_buffer** shared_secret,
					 bob_signal_protocol_parameters *parameters,
					 signal_context *global_context)
{
  int result = 0;
  uint8_t *agreement = 0;
  int agreement_len = 0;
  struct vpool vp;
  signal_buffer* concat = 0;

  assert(parameters);
  assert(global_context);

  vpool_init(&vp, 1024, 0);

  if(parameters->our_one_time_pre_key) {
    agreement_len
      = curve_calculate_agreement(&agreement,
				  parameters->their_base_key,
				  ec_key_pair_get_private(parameters->our_one_time_pre_key));
    if(agreement_len < 0) {
      result = agreement_len;
      goto complete;
    }
    if(vpool_insert(&vp, vpool_get_length(&vp), agreement, (size_t)agreement_len)) {
      free(agreement); agreement = 0; agreement_len = 0;
    }
    else {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  {
    agreement_len
      = curve_calculate_agreement(&agreement,
				  parameters->their_base_key,
				  ec_key_pair_get_private(parameters->our_signed_pre_key));
    if(agreement_len < 0) {
      result = agreement_len;
      goto complete;
    }
    if(vpool_insert(&vp, vpool_get_length(&vp), agreement, (size_t)agreement_len)) {
      free(agreement); agreement = 0; agreement_len = 0;
    }
    else {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  {
    agreement_len
      = curve_calculate_agreement(&agreement,
				  parameters->their_base_key,
				  ratchet_identity_key_pair_get_private(parameters->our_identity_key));
    if(agreement_len < 0) {
      result = agreement_len;
      goto complete;
    }
    if(vpool_insert(&vp, vpool_get_length(&vp), agreement, (size_t)agreement_len)) {
      free(agreement); agreement = 0; agreement_len = 0;
    }
    else {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  if(vpool_is_empty(&vp)) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  concat = signal_buffer_create(vpool_get_buf(&vp), vpool_get_length(&vp));
  *shared_secret = concat;

 complete:
  vpool_final(&vp);
  free(agreement);

  return result;
}

//The idkey in the bundle is ignored, and a bundle for odake should not contain an idkey in the first place.
int session_builder_process_pre_key_bundle_odake(session_builder *builder, session_pre_key_bundle *bundle)
{
  int result = 0;
  session_record *record = 0;
  ec_key_pair *our_base_key = 0;
  ratchet_identity_key_pair *our_identity_key = 0;
  alice_signal_protocol_parameters *parameters = 0;
  ec_public_key *signed_pre_key = 0;
  ec_public_key *pre_key = 0;
  ec_public_key *their_identity_key = 0;
  ec_public_key *their_signed_pre_key = 0;
  ec_public_key *their_one_time_pre_key = 0;
  int has_their_one_time_pre_key_id = 0;
  uint32_t their_one_time_pre_key_id = 0;
  session_state *state = 0;
  uint32_t local_registration_id = 0;

  assert(builder);
  assert(builder->store);
  assert(bundle);
#ifdef DUMPMSG
  {
    int dump_ret = 0;
    const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(builder->global_context));
    if (dumper && pbdumper_is_valid(dumper)) {
      dump_ret = dump_pb(builder->global_context, dumper, __FILE__, __LINE__, __func__,
			 "session_pre_key_bundle", "fetched",
			 dumper->bundle2str(bundle));
    }
    if (dump_ret < 0)
      result = dump_ret;
  }
#endif
  signal_lock(builder->global_context);

  result = sig_ext_query_idkey(builder->store,
			       builder->remote_address,
			       &their_identity_key);
  if(result < 0) {
    goto complete;
  }

  signed_pre_key = session_pre_key_bundle_get_signed_pre_key(bundle);
  pre_key = session_pre_key_bundle_get_pre_key(bundle);

  if(signed_pre_key) {
    signal_buffer *signature = session_pre_key_bundle_get_signed_pre_key_signature(bundle);

    signal_buffer *serialized_signed_pre_key = 0;
    result = ec_public_key_serialize(&serialized_signed_pre_key, signed_pre_key);
    if(result < 0) {
      goto complete;
    }

    result = curve_verify_signature(their_identity_key,
				    signal_buffer_data(serialized_signed_pre_key),
				    signal_buffer_len(serialized_signed_pre_key),
				    signal_buffer_data(signature),
				    signal_buffer_len(signature));

    signal_buffer_free(serialized_signed_pre_key);

    if(result == 0) {
      signal_log(builder->global_context, SG_LOG_WARNING, "signature mismatch with idkey!");
      result = SG_ERR_INVALID_KEY;
    }
    if(result < 0) {
      goto complete;
    }
  }

  if(!signed_pre_key) {
    result = SG_ERR_INVALID_KEY;
    signal_log(builder->global_context, SG_LOG_WARNING, "no signed pre key!");
    goto complete;
  }

  result = signal_protocol_session_load_session(builder->store, &record, builder->remote_address);
  if(result < 0) {
    goto complete;
  }

  result = curve_generate_key_pair(builder->global_context, &our_base_key);
  if(result < 0) {
    goto complete;
  }

  their_signed_pre_key = signed_pre_key;
  their_one_time_pre_key = pre_key;

  if(their_one_time_pre_key) {
    has_their_one_time_pre_key_id = 1;
    their_one_time_pre_key_id = session_pre_key_bundle_get_pre_key_id(bundle);
  }

  result = signal_protocol_identity_get_key_pair(builder->store, &our_identity_key);
  if(result < 0) {
    goto complete;
  }

  result = alice_signal_protocol_parameters_create(&parameters,
						   our_identity_key,
						   our_base_key,
						   their_identity_key,
						   their_signed_pre_key,
						   their_one_time_pre_key,
						   their_signed_pre_key);
  if(result < 0) {
    goto complete;
  }

  if(!session_record_is_fresh(record)) {
    result = session_record_archive_current_state(record);
    if(result < 0) {
      goto complete;
    }
  }

  state = session_record_get_state(record);

  result = ratcheting_session_alice_initialize_odake(state, parameters,
						     builder->global_context);
  if(result < 0) {
    goto complete;
  }

  /*
   * Since the public part of our_base_key will be stored as alice_base_key,
   * the base_key inside session_pending_pre_key could be reused to cache
   * their_one_time_pre_key before rsign, when their_one_time_pre_key is available.
   */
  session_state_set_unacknowledged_pre_key_message(state,
						   has_their_one_time_pre_key_id?
						   &their_one_time_pre_key_id : 0,
						   session_pre_key_bundle_get_signed_pre_key_id(bundle),
						   has_their_one_time_pre_key_id?
						   their_one_time_pre_key:
						   ec_key_pair_get_public(our_base_key));

  result = signal_protocol_identity_get_local_registration_id(builder->store, &local_registration_id);
  if(result < 0) {
    goto complete;
  }

  session_state_set_local_registration_id(state, local_registration_id);
  session_state_set_remote_registration_id(state,
					   session_pre_key_bundle_get_registration_id(bundle));
  session_state_set_alice_base_key(state, ec_key_pair_get_public(our_base_key));


  result = signal_protocol_session_store_session(builder->store,
						 builder->remote_address,
						 record);
  if(result < 0) {
    goto complete;
  }

complete:
    SIGNAL_UNREF(record);
    SIGNAL_UNREF(our_base_key);
    SIGNAL_UNREF(our_identity_key);
    SIGNAL_UNREF(parameters);
    signal_unlock(builder->global_context);
    return result;
}

void session_state_set_pending_pre_key(session_state* state,
				       session_pending_pre_key* ppk)
{
  assert(state);
  assert(ppk);
  session_state_set_unacknowledged_pre_key_message(state,
						   ppk->has_pre_key_id?
						   &ppk->pre_key_id:NULL,
						   ppk->signed_pre_key_id,
						   ppk->base_key);
}

void session_state_get_pending_pre_key(session_state* state,
				       session_pending_pre_key* ppk)
{
  assert(state);
  assert(ppk);
  ppk->has_pre_key_id
    = session_state_unacknowledged_pre_key_message_has_pre_key_id(state);
  ppk->pre_key_id
    = session_state_unacknowledged_pre_key_message_get_pre_key_id(state);
  ppk->signed_pre_key_id
    = session_state_unacknowledged_pre_key_message_get_signed_pre_key_id(state);
  ppk->base_key
    = session_state_unacknowledged_pre_key_message_get_base_key(state);
  SIGNAL_REF(ppk->base_key);
}

void unref_pending_pre_key(session_pending_pre_key* ppk)
{
  SIGNAL_UNREF(ppk->base_key);
}

int Odake_derive_ek(signal_context *gctx,
		    const uint8_t* sharedsec,
		    size_t ss_len,
		    symskey* ek)
{
  hkdf_context* kdf = 0;
  int result = 0;
  uint8_t* resbuf = 0;
  ssize_t result_size = 0;
  result = hkdf_create(&kdf, 3, gctx);
  if(result < 0) {
    goto complete;
  }

  result_size = hkdf_derive_secrets(kdf, &resbuf,
				    sharedsec, ss_len,
				    empty_salt, sizeof(empty_salt),
				    (const uint8_t*)kinf_odake_ek, STRLEN_S(kinf_odake_ek),
				    sizeof(*ek));

  if(result_size != sizeof(*ek)) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  memcpy(ek, resbuf, sizeof(*ek));

 complete:
  free(resbuf);
  SIGNAL_UNREF(kdf);
  return result;
}

int Odake_derive_mk(signal_context *gctx,
		    const symskey* ek,
		    symkey* mk)
{
  hkdf_context* kdf = 0;
  int result = 0;
  uint8_t* resbuf = 0;
  ssize_t result_size = 0;
  result = hkdf_create(&kdf, 3, gctx);
  if(result < 0) {
    goto complete;
  }

  result_size = hkdf_derive_secrets(kdf, &resbuf,
				    (const uint8_t*)ek, sizeof(*ek),
				    empty_salt, sizeof(empty_salt),
				    (const uint8_t*)kinf_odake_ek, STRLEN_S(kinf_odake_ek),
				    sizeof(*mk));

  if(result_size != sizeof(*mk)) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  memcpy(mk, resbuf, sizeof(*mk));

 complete:
  free(resbuf);
  SIGNAL_UNREF(kdf);
  return result;
}

int session_state_store_ek_dirty(signal_context* gctx,
				 session_state *state, const symskey* ek)
{
  ec_public_key* key = 0;
  ec_public_key* iv = 0;
  signal_buffer* buf = 0;
  uint8_t* data = 0;
  int result = 0;

  buf = signal_buffer_alloc(sizeof(uint8_t) * (sizeof(ek->key) + 1));
  data = signal_buffer_data(buf);
  data[0] = DJB_PUBKEY_MAGIC;

  memcpy(data + 1, &ek->iv, sizeof(ek->iv));
  result = curve_decode_point(&iv, data, (sizeof(ek->key) + 1), gctx);
  if(result < 0) {
    goto complete;
  }

  memcpy(data + 1, &ek->key, sizeof(ek->key));
  result = curve_decode_point(&key, data, (sizeof(ek->key) + 1), gctx);
  if(result < 0) {
    goto complete;
  }

  /*
   * temporary store these keys in the places of ec idkeys,
   * they are to be replaced with true id keys after pre-key msg is generated.
   */
  session_state_set_local_identity_key(state, key);
  session_state_set_remote_identity_key(state, iv);

 complete:
  SIGNAL_UNREF(key);
  SIGNAL_UNREF(iv);
  signal_buffer_bzero_free(buf);

  return result;
}

int session_state_get_ek_dirty(signal_context* gctx,
			       session_state *state, symskey* ek)
{
  int result = session_state_has_unacknowledged_pre_key_message(state);
  if (result != true) {
    return result;
  }
  memcpy(&ek->key,
	 ec_key_get_bytes((const ec_key*)session_state_get_local_identity_key(state)),
	 sizeof(ek->key));
  memcpy(&ek->iv,
	 ec_key_get_bytes((const ec_key*)session_state_get_remote_identity_key(state)),
	 sizeof(ek->iv));
  return result;
}

int session_state_restore_idkeys_odake(session_builder *builder,
				       session_state *state)
{
  int result = 0;
  ratchet_identity_key_pair* l_idkey = 0;
  ec_public_key* r_idkey = 0;

  result = sig_ext_query_idkey(builder->store,
			       builder->remote_address,
			       &r_idkey);
  if(result < 0) {
    goto complete;
  }

  result = signal_protocol_identity_get_key_pair(builder->store,
						 &l_idkey);
  if(result < 0) {
    goto complete;
  }

  session_state_set_local_identity_key(state, ec_key_pair_get_public((ec_key_pair*)
								     l_idkey));
  session_state_set_remote_identity_key(state, r_idkey);

 complete:
  SIGNAL_UNREF(l_idkey);
  SIGNAL_UNREF(r_idkey);
  return result;
}

static void pre_key_odake_message_destroy(signal_type_base *type)
{
    pre_key_odake_message *message = (pre_key_odake_message *)type;
    signal_buffer_free(message->base_message.serialized);
    SIGNAL_UNREF(message->alice_basekey);
    SIGNAL_UNREF(message->alice_idkey);
    signal_buffer_free(message->mac);
    signal_buffer_free(message->rsig);
    signal_buffer_bzero_free(message->ek);
    signal_buffer_free(message->enc_idmsg);
    SIGNAL_UNREF(message->payload);
    free(message);
}

int pre_key_odake_message_serialize(signal_buffer **buffer,
				    const pre_key_odake_message *message)
{
  int result = 0;
  size_t len = 0;
  size_t plen = 0;
  signal_buffer *result_buf = 0;
  Signaldakez__OdakeIdMessage idmsg = SIGNALDAKEZ__ODAKE_ID_MESSAGE__INIT;
  Signaldakez__OdakePreKeyMessage pkmsg = SIGNALDAKEZ__ODAKE_PRE_KEY_MESSAGE__INIT;
  const ciphertext_message* payload = 0;
  const symskey* ek = 0;
  signal_buffer* ser_basekey = 0;
  signal_buffer* ser_idkey = 0;
  signal_buffer* ser_idmsg = 0;
  signal_buffer* enc_idmsg = 0;

  uint8_t version = (message->version << 4) | CIPHERTEXT_CURRENT_VERSION;

  idmsg.has_regid = true;
  idmsg.regid = message->registration_id;

  if(message->has_pre_key_id) {
    pkmsg.has_rpkid = true;
    pkmsg.rpkid = message->pre_key_id;
  }

  pkmsg.has_rspkid = true;
  pkmsg.rspkid = message->signed_pre_key_id;

  result = ec_public_key_serialize(&ser_basekey, message->alice_basekey);
  if(result < 0) {
    goto complete;
  }
  pkmsg.has_prekey = true;
  pkmsg.prekey.data = signal_buffer_data(ser_basekey);
  pkmsg.prekey.len = signal_buffer_len(ser_basekey);

  result = ec_public_key_serialize(&ser_idkey, message->alice_idkey);
  if(result < 0) {
    goto complete;
  }

  idmsg.has_idkey = true;
  idmsg.idkey.data = signal_buffer_data(ser_idkey);
  idmsg.idkey.len = signal_buffer_len(ser_idkey);

  payload = (const ciphertext_message*)message->payload;
  pkmsg.has_payload = true;
  pkmsg.payload.data = signal_buffer_data(payload->serialized);
  pkmsg.payload.len = signal_buffer_len(payload->serialized);

  idmsg.has_mac = true;
  idmsg.mac.data = signal_buffer_data(message->mac);
  idmsg.mac.len = signal_buffer_len(message->mac);

  idmsg.has_rsig = true;
  idmsg.rsig.data = signal_buffer_data(message->rsig);
  idmsg.rsig.len = signal_buffer_len(message->rsig);

  len = signaldakez__odake_id_message__get_packed_size(&idmsg);
  ser_idmsg = signal_buffer_alloc(len);
  if(!ser_idmsg) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  plen = signaldakez__odake_id_message__pack(&idmsg, signal_buffer_data(ser_idmsg));
  if(plen != len) {
    result = SG_ERR_INVALID_PROTO_BUF;
    goto complete;
  }

  ek = (const symskey*)signal_buffer_data(message->ek);

  result = (signal_buffer_len(message->ek) != sizeof(symskey))?
    SG_ERR_UNKNOWN:signal_encrypt(message->base_message.global_context,
				  &enc_idmsg, SG_CIPHER_AES_CBC_PKCS5,
				  ek->key.a, sizeof(ek->key),
				  ek->iv.a, sizeof(ek->iv),
				  signal_buffer_data(ser_idmsg),
				  signal_buffer_len(ser_idmsg));
  if(result < 0) {
    goto complete;
  }

  pkmsg.has_encidmsg = true;
  pkmsg.encidmsg.data = signal_buffer_data(enc_idmsg);
  pkmsg.encidmsg.len = signal_buffer_len(enc_idmsg);

  len = signaldakez__odake_pre_key_message__get_packed_size(&pkmsg);
  result_buf = signal_buffer_alloc(len + 1);
  if(!result_buf) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  signal_buffer_data(result_buf)[0] = version;

  plen = signaldakez__odake_pre_key_message__pack(&pkmsg,
						  signal_buffer_data(result_buf) + 1);
  if(plen != len) {
    result = SG_ERR_INVALID_PROTO_BUF;
  }
#ifdef DUMPMSG
    {
      int dump_ret = 0;
      signal_context* gctx = message->base_message.global_context;
      const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
      if (dumper && pbdumper_is_valid(dumper)) {
	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "OdakeIdMessage", "to be encrypted as OdakePreKeyMessage::encidmsg",
			   dumper->oid2str((const ProtobufCMessage*)&idmsg));
      }
      if (dump_ret < 0) {
	result = dump_ret;
	goto complete;
      }
      {
	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "IdakeEncryptedIdKeyMessage", "to send",
			   dumper->opk2str((const ProtobufCMessage*)&pkmsg));
      }
      if (dump_ret < 0)
	result = dump_ret;
    }
#endif

 complete:
  signal_buffer_free(ser_basekey);
  signal_buffer_free(ser_idkey);
  signal_buffer_free(ser_idmsg);
  signal_buffer_free(enc_idmsg);
  if(result >= 0) {
    *buffer = result_buf;
  } else {
    signal_buffer_free(result_buf);
  }

  return result;
}

int pre_key_odake_message_pre_deserialize(pre_key_odake_message** message,
					  const uint8_t* data, size_t len,
					  signal_context* gctx)
{
  int result = 0;
  pre_key_odake_message *result_message = 0;
  Signaldakez__OdakePreKeyMessage* pkmsg = 0;
  uint8_t version = 0;
  const uint8_t *message_data = 0;
  size_t message_len = 0;

  assert(gctx);

  if(!data || len <= 1) {
    result = SG_ERR_INVAL;
    goto complete;
  }

  version = (data[0] & 0xF0) >> 4;

  /* Set some pointers and lengths for the sections of the raw data */
  message_data = data + 1;
  message_len = len - 1;

  // TODO: replace CIPHERTEXT_CURRENT_VERSION with magic for dakez.
  if(version < CIPHERTEXT_CURRENT_VERSION) {
    signal_log(gctx, SG_LOG_WARNING, "Unsupported legacy version: %d", version);
    result = SG_ERR_LEGACY_MESSAGE;
    goto complete;
  }

  if(version > CIPHERTEXT_CURRENT_VERSION) {
    signal_log(gctx, SG_LOG_WARNING, "Unknown version: %d", version);
    result = SG_ERR_INVALID_VERSION;
    goto complete;
  }

  pkmsg = signaldakez__odake_pre_key_message__unpack(0, message_len, message_data);
  if(!pkmsg) {
    result = SG_ERR_INVALID_PROTO_BUF;
    goto complete;
  }

  if(!pkmsg->has_prekey ||
     !pkmsg->has_rpkid ||
     !pkmsg->has_rspkid ||
     !pkmsg->has_encidmsg) {
    signal_log(gctx, SG_LOG_WARNING, "Incomplete message");
    result = SG_ERR_INVALID_MESSAGE;
    goto complete;
  }

  result_message = malloc(sizeof(pre_key_odake_message));
  if(!result_message) {
    result = SG_ERR_NOMEM;
    goto complete;
  }
  memset(result_message, 0, sizeof(pre_key_odake_message));
  SIGNAL_INIT(result_message, pre_key_odake_message_destroy);

  result_message->base_message.message_type = CIPHERTEXT_ODAKE_PREKEY_TYPE;
  result_message->base_message.global_context = gctx;

  result_message->version = version;

  if(pkmsg->has_rpkid) {
    result_message->has_pre_key_id = true;
    result_message->pre_key_id = pkmsg->rpkid;
  }

  if(pkmsg->has_rspkid) {
    result_message->signed_pre_key_id = pkmsg->rspkid;
  }

  if(pkmsg->has_prekey) {
    result = curve_decode_point(&result_message->alice_basekey,
				pkmsg->prekey.data, pkmsg->prekey.len,
				gctx);
    if(result < 0) {
      goto complete;
    }
  }

  if(pkmsg->has_encidmsg) {
    result_message->enc_idmsg = signal_buffer_create(pkmsg->encidmsg.data,
						     pkmsg->encidmsg.len);
    if(!result_message->enc_idmsg) {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  if(pkmsg->has_payload) {
    result = signal_message_deserialize(&result_message->payload,
					pkmsg->payload.data,
					pkmsg->payload.len,
					gctx);
    if(result < 0) {
      goto complete;
    }
    if(signal_message_get_message_version(result_message->payload) != version) {
      signal_log(gctx, SG_LOG_WARNING, "Inner message version mismatch: %d != %d",
		 signal_message_get_message_version(result_message->payload), version);
      result = SG_ERR_INVALID_VERSION;
      goto complete;
    }
  }

  result_message->base_message.serialized = signal_buffer_create(data, len);
  if(!result_message->base_message.serialized) {
    result = SG_ERR_NOMEM;
    goto complete;
  }
#ifdef DUMPMSG
    {
      int dump_ret = 0;
      const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
      if (dumper && pbdumper_is_valid(dumper)) {
	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "IdakeEncryptedIdKeyMessage", "received",
			   dumper->opk2str((const ProtobufCMessage*)pkmsg));
      }
      if (dump_ret < 0)
	result = dump_ret;
    }
#endif

 complete:
  signaldakez__odake_pre_key_message__free_unpacked(pkmsg, 0);
  if(result >= 0) {
    *message = result_message;
  } else {
    SIGNAL_UNREF(result_message);
  }
  return result;
}

int pre_key_odake_message_is_pre_deserialized(const pre_key_odake_message* message)
{
  return ((message->alice_basekey) &&
	  (message->enc_idmsg) &&
	  (message->payload) &&
	  (message->base_message.serialized) &&
	  (!message->alice_idkey) ||
	  (!message->mac) ||
	  (!message->rsig) ||
	  (!message->ek));
}

int pre_key_odake_message_is_post_deserialized(const pre_key_odake_message* message)
{
  return ((message->alice_basekey) &&
	  (message->payload) &&
	  (message->base_message.serialized) &&
	  (message->alice_idkey) &&
	  (message->mac) &&
	  (message->rsig) &&
	  (message->ek) &&
	  (!message->enc_idmsg));
}

int pre_key_odake_message_post_deserialize(pre_key_odake_message* message,
					   const uint8_t* ek_buf, size_t ek_len)
{
  int result = 0;
  Signaldakez__OdakeIdMessage* idmsg = 0;
  signal_buffer* ser_idmsg = 0;
  const symskey* ek = 0;

  assert(message->base_message.global_context);

  if(!pre_key_odake_message_is_pre_deserialized(message)) {
    if(pre_key_odake_message_is_post_deserialized(message)) {
      signal_log(message->base_message.global_context, SG_LOG_WARNING, "Message already post-deserialized.");
    } else {
      result = SG_ERR_INVALID_MESSAGE;
    }
    goto complete;
  }

  if((!ek_buf) || (ek_len != sizeof(symskey))) {
    result = SG_ERR_INVALID_KEY;
    goto complete;
  }

  ek = (const symskey*)ek_buf;

  result = signal_decrypt(message->base_message.global_context,
			  &ser_idmsg, SG_CIPHER_AES_CBC_PKCS5,
			  ek->key.a, sizeof(ek->key),
			  ek->iv.a, sizeof(ek->iv),
			  signal_buffer_data(message->enc_idmsg),
			  signal_buffer_len(message->enc_idmsg));
  if(result < 0) {
    goto complete;
  }

  idmsg = signaldakez__odake_id_message__unpack(0,
						signal_buffer_len(ser_idmsg),
						signal_buffer_data(ser_idmsg));
  if(!idmsg) {
    result = SG_ERR_INVALID_PROTO_BUF;
    goto complete;
  }

  if(idmsg->has_idkey) {
    result = curve_decode_point(&message->alice_idkey,
				idmsg->idkey.data, idmsg->idkey.len,
				message->base_message.global_context);
    if(result < 0) {
      goto complete;
    }
  }

  if(idmsg->has_regid) {
    message->registration_id = idmsg->regid;
  }

  if(idmsg->has_mac) {
    message->mac = signal_buffer_create(idmsg->mac.data, idmsg->mac.len);
    if(!message->mac) {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  if(idmsg->has_rsig) {
    message->rsig = signal_buffer_create(idmsg->rsig.data, idmsg->rsig.len);
    if(!message->rsig) {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  message->ek = signal_buffer_create(ek_buf, ek_len);
  if(!message->ek) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  signal_buffer_bzero_free(message->enc_idmsg);
  message->enc_idmsg = 0;

  if(!pre_key_odake_message_is_post_deserialized(message)) {
    signal_log(message->base_message.global_context,
	       SG_LOG_WARNING, "Message post-deserialization failed");
    result = SG_ERR_UNKNOWN;
  }
#ifdef DUMPMSG
    {
      int dump_ret = 0;
      signal_context* gctx = message->base_message.global_context;
      const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
      if (dumper && pbdumper_is_valid(dumper)) {
	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "OdakeIdMessage", "decrypted",
			   dumper->oid2str((const ProtobufCMessage*)idmsg));
      }
      if (dump_ret < 0)
	result = dump_ret;
    }
#endif
  

 complete:
  signaldakez__odake_id_message__free_unpacked(idmsg, 0);
  signal_buffer_bzero_free(ser_idmsg);

  return result;
}

static int session_builder_process_pre_key_odake_message_v0(session_builder *builder,
							    session_state* state,
							    pre_key_odake_message *message,
							    uint32_t *unsigned_pre_key_id)
{
  int result = 0;
  uint32_t unsigned_pre_key_id_result = 0;
  session_signed_pre_key *our_signed_pre_key = 0;
  ratchet_identity_key_pair *our_identity_key = 0;
  bob_signal_protocol_parameters *parameters = 0;
  session_pre_key *session_our_one_time_pre_key = 0;
  ec_key_pair *our_one_time_pre_key = 0;
  uint32_t local_registration_id = 0;
  signal_buffer* sharedsec = 0;
  signal_buffer* sign_payload = 0;
  signal_buffer* mac = 0;
  symskey ek;
  symkey mk;
  symkey assoctag;

  result = signal_protocol_signed_pre_key_load_key(builder->store,
            &our_signed_pre_key,
            message->signed_pre_key_id);
  if(result < 0) {
    goto complete;
  }

  result = signal_protocol_identity_get_key_pair(builder->store, &our_identity_key);
  if(result < 0) {
    goto complete;
  }

  if(message->has_pre_key_id) {
    result = signal_protocol_pre_key_load_key(builder->store,
					      &session_our_one_time_pre_key,
					      message->pre_key_id);
    if(result < 0) {
      goto complete;
    }
    our_one_time_pre_key = session_pre_key_get_key_pair(session_our_one_time_pre_key);
  }
  /*
   * their_idkey is not used in odake, since it could only
   * be obtained after the message gets post-deserialized,
   * but bob_signal_protocol_parameters_create() asks for
   * a "remote id key", so it is mocked with public part
   * of our_identity_key.
   */
  result = bob_signal_protocol_parameters_create
    (&parameters,
     our_identity_key,
     session_signed_pre_key_get_key_pair(our_signed_pre_key),
     our_one_time_pre_key,
     session_signed_pre_key_get_key_pair(our_signed_pre_key),
     ratchet_identity_key_pair_get_public(our_identity_key),
     message->alice_basekey);
  if(result < 0) {
    goto complete;
  }

  result = signal_protocol_identity_get_local_registration_id(builder->store, &local_registration_id);
  if(result < 0) {
    goto complete;
  }

  result = ratcheting_session_bob_calc_ss_odake(&sharedsec,
						parameters,
						builder->global_context);
  if(result < 0) {
    goto complete;
  }

  result = Odake_derive_ek(builder->global_context,
			   signal_buffer_data(sharedsec),
			   signal_buffer_len(sharedsec),
			   &ek);
  if(result < 0) {
    goto complete;
  }

  result = Odake_derive_mk(builder->global_context,
			   &ek, &mk);
  if(result < 0) {
    goto complete;
  }

  result = pre_key_odake_message_post_deserialize(message,
						  (const uint8_t*)&ek,
						  sizeof(ek));
  if(result < 0) {
    goto complete;
  }

  result = dake_concat_sign_payload(&sign_payload,
				    true,
				    message->registration_id,
				    local_registration_id,
				    message->alice_basekey,
				    ec_key_pair_get_public(our_one_time_pre_key),
				    (message->has_pre_key_id)?
				    &message->pre_key_id:NULL);
  if(result < 0) {
    goto complete;
  }

  result = dake_compute_assoctag(builder->global_context,
				 message->alice_idkey,
				 ec_key_pair_get_public((const ec_key_pair*)
							our_identity_key),
				 &assoctag);
  if(result < 0) {
    goto complete;
  }

  result = dake_mac_sign_payload(builder->global_context, &mac,
				 mk.a, sizeof(mk),
				 signal_buffer_data(sign_payload),
				 signal_buffer_len(sign_payload),
				 assoctag.a,
				 sizeof(assoctag),
				 (const uint8_t*)kinf_iht,
				 STRLEN_S(kinf_iht));
  if(result < 0) {
    goto complete;
  }

  if(0 != signal_buffer_compare(mac, message->mac)) {
    result = SG_ERR_INVALID_MAC;
    goto complete;
  }

  result = dake_rvrf(builder->global_context,
		     (const rsig*)signal_buffer_data(message->rsig),
		     message->alice_idkey,
		     ratchet_identity_key_pair_get_public(our_identity_key),
		     ec_key_pair_get_public(our_one_time_pre_key),
		     signal_buffer_data(sign_payload),
		     signal_buffer_len(sign_payload),
		     assoctag.a,
		     sizeof(assoctag),
		     (const uint8_t*)kinf_iht,
		     STRLEN_S(kinf_iht));
  if(result < 0) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  } else if(result == false) {
    result = SG_ERR_INVALID_KEY;
    goto complete;
  }

  //odake complete! initialize the session.
  result =
    session_state_init_session(builder->global_context,
			       state,
			       signal_buffer_data(sharedsec),
			       signal_buffer_len(sharedsec),
			       NULL,
			       session_signed_pre_key_get_key_pair(our_signed_pre_key));
  if(result < 0) {
    goto complete;
  }


  session_state_set_local_registration_id(state, local_registration_id);
  session_state_set_remote_registration_id(state, message->registration_id);
  session_state_set_local_identity_key(state, ratchet_identity_key_pair_get_public(our_identity_key));
  session_state_set_remote_identity_key(state, message->alice_idkey);
  session_state_set_alice_base_key(state, message->alice_basekey);
  session_state_set_session_version(state, CIPHERTEXT_CURRENT_VERSION);

  if (message->has_pre_key_id &&
      message->pre_key_id != PRE_KEY_MEDIUM_MAX_VALUE) {
    unsigned_pre_key_id_result = message->pre_key_id;
    result = true;
  } else {
    result = false;
  }

 complete:
  SIGNAL_UNREF(parameters);
  SIGNAL_UNREF(our_identity_key);
  SIGNAL_UNREF(our_signed_pre_key);
  SIGNAL_UNREF(session_our_one_time_pre_key);
  signal_buffer_bzero_free(sharedsec);
  signal_buffer_bzero_free(sign_payload);
  signal_buffer_free(mac);
  memset(&ek, 0, sizeof(ek));
  memset(&mk, 0, sizeof(mk));
  if(result >= 0) {
    *unsigned_pre_key_id = unsigned_pre_key_id_result;
  }
  return result;
}

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
				 signal_context *gctx)
{
  int result = 0;
  pre_key_odake_message *r_msg = 0;
  signal_buffer* sign_payload = 0;
  const symskey* ek = 0;
  symkey mk;
  symkey assoctag;
  rsig sig;

  assert(gctx);

  r_msg = calloc(1, sizeof(pre_key_odake_message));
  if (!r_msg) {
    return SG_ERR_NOMEM;
  }
  SIGNAL_INIT(r_msg, pre_key_odake_message_destroy);

  r_msg->base_message.message_type = CIPHERTEXT_ODAKE_PREKEY_TYPE;
  r_msg->base_message.global_context = gctx;
  r_msg->version = version;

  if(pre_key_id) {
    r_msg->has_pre_key_id = true;
    r_msg->pre_key_id = *pre_key_id;
  }
  r_msg->signed_pre_key_id = signed_pre_key_id;
  r_msg->registration_id = our_regid;

  r_msg->alice_basekey = our_basekey;
  SIGNAL_REF(r_msg->alice_basekey);
  r_msg->alice_idkey = ec_key_pair_get_public(our_idkey);
  SIGNAL_REF(r_msg->alice_idkey);

  r_msg->payload = payload;
  SIGNAL_REF(r_msg->payload);

  if((!ek_buf) || (ek_len != sizeof(symskey))) {
    result = SG_ERR_INVALID_KEY;
    goto complete;
  }

  r_msg->ek = signal_buffer_create(ek_buf, ek_len);
  if (!r_msg->ek) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  ek = (const symskey*)ek_buf;
  result = Odake_derive_mk(gctx,
			   ek, &mk);
  if(result < 0) {
    goto complete;
  }

  result = dake_concat_sign_payload(&sign_payload,
				    true,
				    our_regid,
				    their_regid,
				    our_basekey,
				    their_pre_key,
				    (pre_key_id)?
				    pre_key_id:NULL);
  if(result < 0) {
    goto complete;
  }

  result = dake_compute_assoctag(gctx,
				 r_msg->alice_idkey,
				 their_idkey,
				 &assoctag);
  if(result < 0) {
    goto complete;
  }

  result = dake_mac_sign_payload(gctx, &r_msg->mac,
				 mk.a, sizeof(mk),
				 signal_buffer_data(sign_payload),
				 signal_buffer_len(sign_payload),
				 assoctag.a,
				 sizeof(assoctag),
				 (const uint8_t*)kinf_iht,
				 STRLEN_S(kinf_iht));
  if(result < 0) {
    goto complete;
  }

  result = dake_rsign(gctx, &sig, r_msg->alice_idkey, their_idkey,
		      their_pre_key, ec_key_pair_get_private(our_idkey),
		      signal_buffer_data(sign_payload),
		      signal_buffer_len(sign_payload),
		      assoctag.a,
		      sizeof(assoctag),
		      (const uint8_t*)kinf_iht,
		      STRLEN_S(kinf_iht));

  if(result < 0) {
    goto complete;
  }

  r_msg->rsig = signal_buffer_create((const uint8_t*)&sig, sizeof(sig));
  if (!r_msg->rsig) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  result = pre_key_odake_message_serialize(&r_msg->base_message.serialized, r_msg);

 complete:
  if(result >= 0) {
    result = 0;
    *message = r_msg;
  }
  else {
    SIGNAL_UNREF(r_msg);
  }
  signal_buffer_bzero_free(sign_payload);
  memset(&mk, 0, sizeof(mk));
  memset(&sig, 0, sizeof(sig));

  return result;
}

int pre_key_odake_message_copy(pre_key_odake_message **newmsg,
			       pre_key_odake_message *srcmsg,
			       signal_context *gctx)
{
  int result = 0;
  pre_key_odake_message *r_msg = 0;

  assert(newmsg);
  assert(gctx);

  result =
    pre_key_odake_message_pre_deserialize(&r_msg,
					  signal_buffer_data(srcmsg->base_message.serialized),
					  signal_buffer_len(srcmsg->base_message.serialized),
					  gctx);
  if(result < 0) {
    goto complete;
  }

  if(pre_key_odake_message_is_post_deserialized(srcmsg)) {
    result = pre_key_odake_message_post_deserialize(r_msg,
						    signal_buffer_data(srcmsg->ek),
						    signal_buffer_len(srcmsg->ek));
  }
 complete:
  if(result >= 0) {
    *newmsg = r_msg;
  } else {
    SIGNAL_UNREF(r_msg);
  }
  return result;
}

int session_builder_process_pre_key_odake_message(session_builder *builder,
						  session_record *record,
						  pre_key_odake_message *message,
						  uint32_t *unsigned_pre_key_id)
{
  int result = 0;
  int has_unsigned_pre_key_id_result = 0;
  uint32_t unsigned_pre_key_id_result = 0;
  session_state* newstate = 0;

  int has_session_state
    = session_record_has_session_state(record,
				       message->version,
				       message->alice_basekey);

  if(has_session_state) {
    signal_log(builder->global_context, SG_LOG_INFO,
	       "We've already setup a session for this Odake V0 message, "
	       "letting bundled message fall through...");
    //(*record) will be unchanged.
  } else {
    /*
     * create a new session_state and initialize it with
     * incoming pre_key_odake_message, then promote the new
     * state to (*record).
     */
    result = session_state_create(&newstate, record->global_context);
    if(result < 0) {
        goto complete;
    }

    result
      = session_builder_process_pre_key_odake_message_v0(builder,
							 newstate,
							 message,
							 &unsigned_pre_key_id_result);

    if(result < 0) {
        goto complete;
    }
    has_unsigned_pre_key_id_result = result;

    result
      = signal_protocol_identity_is_trusted_identity(builder->store,
						     builder->remote_address,
						     message->alice_idkey);
    if(result < 0) {
      goto complete;
    }
    if(result == 0) {
      result = SG_ERR_UNTRUSTED_IDENTITY;
      goto complete;
    }

    if(!session_record_is_fresh(record)) {
      result = session_record_archive_current_state(record);
      if(result < 0) {
	goto complete;
      }
    }
    session_record_set_state(record, newstate);
  }

  result = signal_protocol_identity_save_identity(builder->store,
						  builder->remote_address,
						  message->alice_idkey);
  if(result < 0) {
    goto complete;
  }

  result = has_unsigned_pre_key_id_result;

 complete:
  SIGNAL_UNREF(newstate);
  if(result >= 0) {
    *unsigned_pre_key_id = unsigned_pre_key_id_result;
  }
  return result;
}

int session_cipher_encrypt_odake_wrapper(session_cipher *cipher,
					 const uint8_t *padded_message,
					 size_t padded_message_len,
					 ciphertext_message **encrypted_message)
{
  int result = 0;
  session_record *record = 0;
  session_state *state = 0;
  ratchet_identity_key_pair* our_idkey = 0;
  ciphertext_message* payload = 0;
  pre_key_odake_message* omsg = 0;
  session_pending_pre_key ppk
    = {0, 0, 0, 0};
  symskey ek;

  assert(cipher);
  signal_lock(cipher->global_context);

  if(cipher->inside_callback == 1) {
    result = SG_ERR_INVAL;
    goto complete;
  }

  result = signal_protocol_session_load_session(cipher->store, &record, cipher->remote_address);
  if(result < 0) {
    goto complete;
  }

  state = session_record_get_state(record);
  if(!state) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  if(session_state_has_unacknowledged_pre_key_message(state) == 1) {
    /*
     * cache and clear pending_pre_key in state, so
     * session_cipher_encrypt() will spit a signal_message.
     */
    session_state_get_pending_pre_key(state, &ppk);
    //Note that ppk.base_key is actually used to store remote prekey.
    if(!ppk.base_key) {
      result = SG_ERR_UNKNOWN;
      goto complete;
    }

    //extract and clear ek cached in the state.
    result = session_state_get_ek_dirty(cipher->global_context,
					state,
					&ek);
    if(result < 0) {
      goto complete;
    }
    session_state_clear_unacknowledged_pre_key_message(state);
    result = session_state_restore_idkeys_odake(cipher->builder,
						state);
    if(result < 0) {
      goto complete;
    }

    result = signal_protocol_session_store_session(cipher->store,
						   cipher->remote_address,
						   record);
    if(result < 0) {
      goto complete;
    }
  }

  SIGNAL_UNREF(record);
  signal_unlock(cipher->global_context);
  result = session_cipher_encrypt(cipher,
				  padded_message,
				  padded_message_len,
				  &payload);
  if(result < 0) {
    goto complete;
  }

  signal_lock(cipher->global_context);

  if(ppk.base_key) {
    //pending_pre_key exist, pack payload as pre_key_odake_message.
    result = signal_protocol_session_load_session(cipher->store,
						  &record,
						  cipher->remote_address);
    if(result < 0) {
      goto complete;
    }

    state = session_record_get_state(record);
    if(!state) {
      result = SG_ERR_UNKNOWN;
      goto complete;
    }

    result = signal_protocol_identity_get_key_pair(cipher->store, &our_idkey);
    if(result < 0) {
      goto complete;
    }

    result =
      pre_key_odake_message_create(&omsg,
				   session_state_get_session_version(state),
				   session_state_get_local_registration_id(state),
				   session_state_get_remote_registration_id(state),
				   (ppk.has_pre_key_id)?(&ppk.pre_key_id):0,
				   ppk.signed_pre_key_id,
				   session_state_get_alice_base_key(state),
				   ppk.base_key,
				   session_state_get_remote_identity_key(state),
				   (ec_key_pair*)our_idkey,
				   (const uint8_t*)&ek,
				   sizeof(ek),
				   (signal_message*)payload,
				   cipher->global_context);
    if(result < 0) {
      goto complete;
    }
    SIGNAL_UNREF(payload);


    //restore pending_pre_key and ek into state until receiving a valid reply.
    session_state_set_pending_pre_key(state, &ppk);
    session_state_store_ek_dirty(cipher->global_context, state, &ek);

    result = signal_protocol_session_store_session(cipher->store,
						   cipher->remote_address,
						   record);
    if(result < 0) {
      goto complete;
    }
  }

 complete:
  if(result >= 0) {
    if(ppk.base_key) {
      *encrypted_message = (ciphertext_message *)omsg;
    }
    else {
      *encrypted_message = payload;
    }
  } else {
    SIGNAL_UNREF(omsg);
    SIGNAL_UNREF(payload);
  }
  unref_pending_pre_key(&ppk);
  SIGNAL_UNREF(record);
  SIGNAL_UNREF(our_idkey);
  memset(&ppk, 0, sizeof(ppk));
  memset(&ek, 0, sizeof(ek));
  signal_unlock(cipher->global_context);
  return result;
}

int session_cipher_decrypt_pre_key_odake_message_wrapper(session_cipher *cipher,
							 pre_key_odake_message *omsg,
							 void *decrypt_context,
							 signal_buffer **plaintext)
{
  int result = 0;
  session_record *record = 0;
  int has_unsigned_pre_key_id = 0;
  uint32_t unsigned_pre_key_id = 0;
  signal_buffer *result_buf = 0;

  assert(cipher);
  signal_lock(cipher->global_context);

  if(cipher->inside_callback == 1) {
    result = SG_ERR_INVAL;
    goto complete;
  }

  result = signal_protocol_session_load_session(cipher->store, &record,
						cipher->remote_address);
  if(result < 0) {
    goto complete;
  }

  result = session_builder_process_pre_key_odake_message(cipher->builder,
							 record, omsg,
							 &unsigned_pre_key_id);
  if(result < 0) {
    goto complete;
  }
  has_unsigned_pre_key_id = result;
  result = signal_protocol_session_store_session(cipher->store,
						 cipher->remote_address, record);
  if(result < 0) {
    goto complete;
  }
  signal_unlock(cipher->global_context);

  result = session_cipher_decrypt_signal_message(cipher,
						 (signal_message*)omsg->payload,
						 decrypt_context, &result_buf);

  if(result < 0) {
    goto complete;
  }
  signal_lock(cipher->global_context);
  if(has_unsigned_pre_key_id) {
    result = signal_protocol_pre_key_remove_key(cipher->store, unsigned_pre_key_id);
  }

 complete:
  SIGNAL_UNREF(record);
  if(result >= 0) {
    *plaintext = result_buf;
  } else {
    signal_buffer_free(result_buf);
  }
  signal_unlock(cipher->global_context);
  return result;
}

int session_cipher_decrypt_signal_message_wrapper(session_cipher *cipher,
						  signal_message *ciphertext,
						  void *decrypt_context,
						  signal_buffer **plaintext)
{
  int result = 0;
  int dec_result = 0;
  signal_buffer *result_buf = 0;
  session_record *record = 0;
  session_state* state = 0;
  symskey ek;

  assert(cipher);
  signal_lock(cipher->global_context);

  if(cipher->inside_callback == 1) {
    result = SG_ERR_INVAL;
    goto complete;
  }

  result = signal_protocol_session_contains_session(cipher->store, cipher->remote_address);
  if(result == 0) {
    signal_log(cipher->global_context, SG_LOG_WARNING, "No session for: %s:%d", cipher->remote_address->name, cipher->remote_address->device_id);
    result = SG_ERR_NO_SESSION;
    goto complete;
  }
  else if(result < 0) {
    goto complete;
  }

  result = signal_protocol_session_load_session(cipher->store, &record,
						cipher->remote_address);
  if(result < 0) {
    goto complete;
  }

  state = session_record_get_state(record);
  if(!state) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  if(session_state_has_unacknowledged_pre_key_message(state) == 1) {
    result = session_state_get_ek_dirty(cipher->global_context,
					state,
					&ek);
    if(result < 0) {
      goto complete;
    }
    result = session_state_restore_idkeys_odake(cipher->builder,
						state);
    if(result < 0) {
      goto complete;
    }

    result = signal_protocol_session_store_session(cipher->store,
						   cipher->remote_address,
						   record);
    if(result < 0) {
      goto complete;
    }
  }

  SIGNAL_UNREF(record);
  signal_unlock(cipher->global_context);
  dec_result = session_cipher_decrypt_signal_message(cipher,
						     ciphertext,
						     decrypt_context, &result_buf);

  signal_lock(cipher->global_context);

  result = signal_protocol_session_load_session(cipher->store, &record,
						cipher->remote_address);
  if(result < 0) {
    goto complete;
  }

  state = session_record_get_state(record);
  if(!state) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  if(session_state_has_unacknowledged_pre_key_message(state) == 1) {
    session_state_store_ek_dirty(cipher->global_context, state, &ek);
  }

  result = dec_result;

 complete:
  SIGNAL_UNREF(record);
  if(result >= 0) {
    *plaintext = result_buf;
  } else {
    signal_buffer_free(result_buf);
  }
  signal_unlock(cipher->global_context);
  memset(&ek, 0, sizeof(ek));
  return result;
}
