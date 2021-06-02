/*
 * Copyright (C) 2018-2021, HardenedVault Limited (https://hardenedvault.net)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "idake.h"
#include "hkdf.h"
#include "signal_internal_types.h"
#include "rsig_signal_helper.h"
#include "hasher_signal.h"
#include "vpool.h"

#include "pbdumper.h"

void* signal_context_get_user_data(const signal_context* gctx)
{
  return gctx->user_data;
}

void IdakeAuthClear(IdakeAuthInfo* auth)
{
  //clear all member.
  auth->authstate = IDAKE_AUTHSTATE_NONE;
  SIGNAL_UNREF(auth->our_ek_pair);
  SIGNAL_UNREF(auth->their_ek_pub);
  SIGNAL_UNREF(auth->our_ik_pair);
  SIGNAL_UNREF(auth->their_ik_pub);
  {
    signal_buffer_free(auth->hash_their_ek);
    auth->hash_their_ek = 0;
  }
  memset(&auth->sharedsec, 0, sizeof(auth->sharedsec));
  memset(&auth->derivedkeys, 0, sizeof(auth->derivedkeys));
  memset(&auth->assoctag, 0, sizeof(auth->assoctag));
  auth->initiated = 0;
  auth->isalice = 0;
  {
    signal_buffer_free(auth->lastauthmsg);
    auth->lastauthmsg = 0;
    auth->hash_their_ek = 0;
  }
  auth->commit_sent_time = 0;
}

void IdakeAuthInfo_destroy(signal_type_base* sig_rc_obj)
{
  IdakeAuthInfo* auth = (IdakeAuthInfo*)sig_rc_obj;
  IdakeAuthClear(auth);
  free(auth);
}

int IdakeAuthInfo_create(IdakeAuthInfo** newauth)
{
  int result = 0;
  IdakeAuthInfo* auth = (IdakeAuthInfo*)malloc(sizeof(IdakeAuthInfo));
  if(!auth) {
    result = SG_ERR_NOMEM;
    goto complete;
  }
  memset(auth, 0, sizeof(IdakeAuthInfo));
  SIGNAL_INIT(auth, IdakeAuthInfo_destroy);
  complete:
  if(result < 0) {
    if(auth) {
      SIGNAL_UNREF(auth);
    }
  }
  else {
    *newauth = auth;
  }
  return result;
}

static int signal_sha512_digest_1blob(signal_context *gctx,
				      const uint8_t* blob, size_t len,
				      signal_buffer **dgst)
{
  void* dgstctx = 0;
  int result = signal_sha512_digest_init(gctx, &dgstctx);

  if(result < 0) {
    goto complete;
  }

  result = signal_sha512_digest_update(gctx, dgstctx, blob, len);
  if(result < 0) {
    goto complete;
  }

  result = signal_sha512_digest_final(gctx, dgstctx, dgst);

 complete:
  if(dgstctx) {
    signal_sha512_digest_cleanup(gctx, dgstctx);
  }
  return result;
}

int Idake_pack_authmsg(signal_buffer** ser_authmsg,
		       const Signaldakez__IdakeMessage* authmsg)
{
  int result = 0;
  size_t len = signaldakez__idake_message__get_packed_size(authmsg);
  signal_buffer* msg = signal_buffer_alloc(len);
  if(!msg) {
    result = SG_ERR_NOMEM;
    goto complete;
  }
  size_t plen = signaldakez__idake_message__pack(authmsg,
						 signal_buffer_data(msg));
  if(plen != len) {
    signal_buffer_free(msg);
    result = SG_ERR_INVALID_PROTO_BUF;
    msg = 0;
    goto complete;
  }
 complete:
  if(result >=0) {
    *ser_authmsg = msg;
  }
  return result;
}

int IdakeAuthStart(IdakeAuthInfo* auth, signal_context *gctx, ec_key_pair* our_ik_pair)
{
  int result = 0;
  signal_buffer* ek_p_buf = 0;
  signal_buffer* ek_p_dgst = 0;

  signal_buffer* msg = 0;
  Signaldakez__IdakeKeyDigestMessage record = SIGNALDAKEZ__IDAKE_KEY_DIGEST_MESSAGE__INIT;
  Signaldakez__IdakeMessage authmsg = SIGNALDAKEZ__IDAKE_MESSAGE__INIT;

  IdakeAuthClear(auth);
  auth->initiated = 1;
  SIGNAL_UNREF(auth->our_ik_pair);
  auth->our_ik_pair = our_ik_pair;
  SIGNAL_REF(auth->our_ik_pair);

  result = curve_generate_key_pair(gctx, &auth->our_ek_pair);
  if (result < 0) {
    goto complete;
  }

  result = ec_public_key_serialize(&ek_p_buf, ec_key_pair_get_public(auth->our_ek_pair));
  if(result < 0) {
    goto complete;
  }

  result = signal_sha512_digest_1blob(gctx,
				      signal_buffer_data(ek_p_buf),
				      signal_buffer_len(ek_p_buf),
				      &ek_p_dgst);
  if(result < 0) {
    goto complete;
  }

  record.has_digest = 1;
  record.digest.data = signal_buffer_data(ek_p_dgst);
  record.digest.len = signal_buffer_len(ek_p_dgst);

  authmsg.message_case = SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_KD;
  authmsg.kd = &record;
  result = Idake_pack_authmsg(&msg, &authmsg);

#ifdef DUMPMSG
  {
    int dump_ret = 0;
    const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
    if (dumper && pbdumper_is_valid(dumper)) {
      dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			 "IdakeKeyDigestMessage", "to send",
			 dumper->kd2str((const ProtobufCMessage*)&record));
    }
    if (dump_ret < 0)
      result = dump_ret;
  }
#endif

 complete:
  signal_buffer_free(ek_p_buf);
  signal_buffer_free(ek_p_dgst);
  if(result >=0) {
    signal_buffer_free(auth->lastauthmsg);
    auth->lastauthmsg = msg;
    auth->authstate = IDAKE_AUTHSTATE_AWAITING_PREKEY;
  }
  return result;
}

static int Idake_create_keymsg(signal_context *gctx, IdakeAuthInfo* auth)
{
  int result = 0;
  signal_buffer* ek_p_buf = 0;

  signal_buffer* msg = 0;
  Signaldakez__IdakePreKeyMessage record = SIGNALDAKEZ__IDAKE_PRE_KEY_MESSAGE__INIT;
  Signaldakez__IdakeMessage authmsg = SIGNALDAKEZ__IDAKE_MESSAGE__INIT;
  
  result = curve_generate_key_pair(gctx, &auth->our_ek_pair);
  if (result < 0) {
    goto complete;
  }

  result = ec_public_key_serialize(&ek_p_buf, ec_key_pair_get_public(auth->our_ek_pair));
  if(result < 0) {
    goto complete;
  }

  record.has_prekey = 1;
  record.prekey.data = signal_buffer_data(ek_p_buf);
  record.prekey.len = signal_buffer_len(ek_p_buf);

  authmsg.message_case = SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_PK;
  authmsg.pk = &record;
  result = Idake_pack_authmsg(&msg, &authmsg);

#ifdef DUMPMSG
  {
    int dump_ret = 0;
    const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
    if (dumper && pbdumper_is_valid(dumper)) {
      dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			 "IdakePreKeyMessage", "to send",
			 dumper->pk2str((const ProtobufCMessage*)&record));
    }
    if (dump_ret < 0)
      result = dump_ret;
  }
#endif

 complete:
  signal_buffer_free(ek_p_buf);
  if(result >=0) {
    signal_buffer_free(auth->lastauthmsg);
    auth->lastauthmsg = msg;
  }
  return result;
}

int Idake_handle_kdgstmsg(IdakeAuthInfo* auth, signal_context *gctx,
			  const Signaldakez__IdakeMessage* kdgstmsg,
			  ec_key_pair* our_ik_pair)
{
  int result = 0;
  const Signaldakez__IdakeKeyDigestMessage* record;
  signal_buffer* hash_their_ek = 0;
  if(kdgstmsg->message_case != SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_KD) {
    result = SG_ERR_INVALID_PROTO_BUF;
    goto complete;
  }
  record = kdgstmsg->kd;

#ifdef DUMPMSG
  {
    int dump_ret = 0;
    const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
    if (dumper && pbdumper_is_valid(dumper)) {
      dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			 "IdakeMessage", "received",
			 dumper->idake2str(dumper, kdgstmsg));
    }
    if (dump_ret < 0) {
      result = dump_ret;
      goto complete;
    }
  }
#endif

  if(!record->has_digest) {
    result = SG_ERR_INVALID_KEY;
    goto complete;
  }

  hash_their_ek = signal_buffer_create(record->digest.data, record->digest.len);
  if(!hash_their_ek) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  switch(auth->authstate) {
  case IDAKE_AUTHSTATE_NONE:
  case IDAKE_AUTHSTATE_AWAITING_ERSIDK:
  case IDAKE_AUTHSTATE_AWAITING_ERSIG:
    // Store the incoming information
    IdakeAuthClear(auth);

    SIGNAL_UNREF(auth->our_ik_pair);
    auth->our_ik_pair = our_ik_pair;
    SIGNAL_REF(auth->our_ik_pair);

    auth->hash_their_ek = hash_their_ek;
    hash_their_ek = 0;

    // Create an IdakePreKeyMessage
    result = Idake_create_keymsg(gctx, auth);
    if (result < 0) {
      goto complete;
    }
    auth->authstate = IDAKE_AUTHSTATE_AWAITING_IDKEY;
    break;

  case IDAKE_AUTHSTATE_AWAITING_PREKEY:
    // Mimic the behavior of libotr
    if(signal_buffer_compare(auth->hash_their_ek, hash_their_ek) > 0) {
      /* Ours wins.  Ignore the message we received, and just
       * resend the same IdakeKeyDigestMessage again. */
      signal_buffer_free(hash_their_ek);
      hash_their_ek = 0;
    } else {
      /* Ours loses.  Use the incoming parameters instead. */
      IdakeAuthClear(auth);

      auth->hash_their_ek = hash_their_ek;
      hash_their_ek = 0;

      // Create an IdakePreKeyMessage
      result = Idake_create_keymsg(gctx, auth);
      if (result < 0) {
	goto complete;
      }
      auth->authstate = IDAKE_AUTHSTATE_AWAITING_IDKEY;
    }
    break;
  case IDAKE_AUTHSTATE_AWAITING_IDKEY:
    /* Use the incoming parameters, but just retransmit the old
     * IdakePreKeyMessage. */
    signal_buffer_free(auth->hash_their_ek);
    auth->hash_their_ek = hash_their_ek;
    hash_their_ek = 0;
    break;
  }
 complete:
  signal_buffer_free(hash_their_ek);

  return result;
}

static int Idake_compute_ss(const ec_key_pair* our_ek_pair,
			    const ec_public_key* their_ek_pub,
			    symkey* sharedsec)
{
  int result = 0;
  uint8_t* resbuf = 0;
  assert(our_ek_pair);
  assert(their_ek_pub);
  assert(sharedsec);
  const ec_private_key* our_ek_priv = ec_key_pair_get_private(our_ek_pair);
  result = curve_calculate_agreement(&resbuf, their_ek_pub, our_ek_priv);
  if(result < 0) {
    goto complete;
  }
  memcpy(sharedsec, resbuf, sizeof(*sharedsec));
 complete:
  free(resbuf);
  return result;
}

static int Idake_derive_keys(signal_context *gctx,
			     const uint8_t* sharedsec,
			     size_t ss_len,
			     symskey (*derivedkeys)[3])
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
				    (const uint8_t*)kinf_ss, STRLEN_S(kinf_ss),
				    sizeof(*derivedkeys));

  if(result_size != sizeof(*derivedkeys)) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  memcpy(derivedkeys, resbuf, sizeof(*derivedkeys));

 complete:
  free(resbuf);
  SIGNAL_UNREF(kdf);
  return result;
}

/*
 * Handle an incoming Prekey Message.  If no error is returned, and
 * *havemsgp is 1, the message to sent will be left in auth->lastauthmsg.
 */

int Idake_handle_prekeymsg(IdakeAuthInfo* auth, signal_context *gctx,
			   const Signaldakez__IdakeMessage* prekeymsg,
			   uint32_t our_regid, int *havemsgp)
{
  int result = 0;
  Signaldakez__IdakeIdKeyMessage idk = SIGNALDAKEZ__IDAKE_ID_KEY_MESSAGE__INIT;
  Signaldakez__IdakeMessage authmsg = SIGNALDAKEZ__IDAKE_MESSAGE__INIT;
  Signaldakez__IdakeEncryptedIdKeyMessage eidk
    = SIGNALDAKEZ__IDAKE_ENCRYPTED_ID_KEY_MESSAGE__INIT;
  if(prekeymsg->message_case != SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_PK) {
    result = SG_ERR_INVALID_PROTO_BUF;
    goto complete;
  }
  Signaldakez__IdakePreKeyMessage* prekey = prekeymsg->pk;
#ifdef DUMPMSG
  {
    int dump_ret = 0;
    const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
    if (dumper && pbdumper_is_valid(dumper)) {
      dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			 "IdakeMessage", "received",
			 dumper->idake2str(dumper, prekeymsg));
    }
    if (dump_ret < 0) {
      result = dump_ret;
      goto complete;
    }
  }
#endif

  signal_buffer* ser_our_ek_pub = 0;
  signal_buffer* ser_our_ik_pub = 0;
  signal_buffer* enc_idkmsg = 0;

  signal_buffer* msg = 0;
  size_t len = 0;
  size_t plen = 0;
  ec_public_key* their_ek_pub;
  *havemsgp = 0;

  if(!prekey->has_prekey) {
    result = SG_ERR_INVALID_KEY;
    goto complete;
  }

  result = curve_decode_point(&their_ek_pub,
			      prekey->prekey.data,
			      prekey->prekey.len,
			      gctx);
  if(result < 0) {
    goto complete;
  }

  switch(auth->authstate) {
  case IDAKE_AUTHSTATE_AWAITING_PREKEY:
    /* Store the incoming public key */
    SIGNAL_UNREF(auth->their_ek_pub);
    auth->their_ek_pub = their_ek_pub;
    SIGNAL_REF(auth->their_ek_pub);

    /* Compute the encryption and MAC keys */
    result = Idake_compute_ss(auth->our_ek_pair,
			      auth->their_ek_pub,
			      &auth->sharedsec);
    if(result < 0) {
      goto complete;
    }

    result = Idake_derive_keys(gctx, auth->sharedsec.a,
			       sizeof(auth->sharedsec),
			       &auth->derivedkeys);

    if(result < 0) {
      goto complete;
    }

    result = ec_public_key_serialize(&ser_our_ek_pub,
				     ec_key_pair_get_public(auth->our_ek_pair));

    if(result < 0) {
      goto complete;
    }

    result = ec_public_key_serialize(&ser_our_ik_pub,
				     ec_key_pair_get_public(auth->our_ik_pair));

    if(result < 0) {
      goto complete;
    }

    idk.has_idkey = true;
    idk.idkey.data = signal_buffer_data(ser_our_ik_pub);
    idk.idkey.len = signal_buffer_len(ser_our_ik_pub);
    idk.has_regid = true;
    idk.regid = our_regid;

    len = signaldakez__idake_id_key_message__get_packed_size(&idk);
    msg = signal_buffer_alloc(len);
    if(!msg) {
      result = SG_ERR_NOMEM;
      goto complete;
    }

    plen = signaldakez__idake_id_key_message__pack(&idk, signal_buffer_data(msg));
    if(plen != len) {
      signal_buffer_free(msg);
      result = SG_ERR_INVALID_PROTO_BUF;
      msg = 0;
      goto complete;
    }

    result = signal_encrypt(gctx, &enc_idkmsg, SG_CIPHER_AES_CBC_PKCS5,
			    auth->derivedkeys[0].key.a, sizeof(auth->derivedkeys[0].key),
			    auth->derivedkeys[0].iv.a, sizeof(auth->derivedkeys[0].iv),
			    signal_buffer_data(msg),
			    signal_buffer_len(msg));
    if(result < 0) {
      goto complete;
    }
    signal_buffer_free(msg);

    eidk.has_prekey = 1;
    eidk.prekey.data = signal_buffer_data(ser_our_ek_pub);
    eidk.prekey.len = signal_buffer_len(ser_our_ek_pub);
    eidk.has_encidkey = 1;
    eidk.encidkey.data = signal_buffer_data(enc_idkmsg);
    eidk.encidkey.len = signal_buffer_len(enc_idkmsg);

    authmsg.message_case = SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_EIK;
    authmsg.eik = &eidk;
    result = Idake_pack_authmsg(&msg, &authmsg);
    if(result < 0) {
      goto complete;
    }
    
    signal_buffer_free(auth->lastauthmsg);
    auth->lastauthmsg = msg;
    auth->regids[0] = our_regid;
    msg = 0;
    *havemsgp = 1;
    auth->authstate = IDAKE_AUTHSTATE_AWAITING_ERSIDK;
#ifdef DUMPMSG
    {
      int dump_ret = 0;
      const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
      if (dumper && pbdumper_is_valid(dumper)) {
	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "IdakeIdKeyMessage", "to be encrypted as IdakeEncryptedIdKeyMessage::encidkey",
			   dumper->idk2str((const ProtobufCMessage*)&idk));
	if (dump_ret < 0) {
	  result = dump_ret;
	  break;
	}

	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "IdakeEncryptedIdKeyMessage", "to send",
			   dumper->eidk2str((const ProtobufCMessage*)&eidk));
      }
      if (dump_ret < 0)
	result = dump_ret;
    }
#endif
    break;

  case IDAKE_AUTHSTATE_AWAITING_ERSIDK:
    if(ec_public_key_compare(their_ek_pub, auth->their_ek_pub) == 0) {
      /* Retransmit the id key msg*/
      *havemsgp = 1;
    } else {
      /* Ignore this message */
      *havemsgp = 0;
    }
    break;
  case IDAKE_AUTHSTATE_NONE:
  case IDAKE_AUTHSTATE_AWAITING_IDKEY:
  case IDAKE_AUTHSTATE_AWAITING_ERSIG:

    *havemsgp = 0;
    break;
  }

 complete:
  signal_buffer_bzero_free(ser_our_ek_pub);
  signal_buffer_bzero_free(ser_our_ik_pub);
  signal_buffer_bzero_free(enc_idkmsg);
  signal_buffer_free(msg);
  SIGNAL_UNREF(their_ek_pub);
  return result;
}

int dake_compute_assoctag(signal_context *gctx,
			  const ec_public_key* a_ik_pub,
			  const ec_public_key* b_ik_pub,
			  symkey* assoctag)
{
  hkdf_context* kdf = 0;
  int result = 0;
  uint8_t* resbuf = 0;
  ssize_t result_size = 0;
  signal_buffer* ser_a_ik_pub = 0;
  signal_buffer* ser_b_ik_pub = 0;
  struct vpool vp;

  vpool_init(&vp, 0, 0);

  result = hkdf_create(&kdf, 3, gctx);
  if(result < 0) {
    goto complete;
  }

  result = ec_public_key_serialize(&ser_a_ik_pub,
				   a_ik_pub);

  if(result < 0) {
    goto complete;
  }

  if(!vpool_insert(&vp, vpool_get_length(&vp),
		   signal_buffer_data(ser_a_ik_pub),
		   signal_buffer_len(ser_a_ik_pub))) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  result = ec_public_key_serialize(&ser_b_ik_pub,
				   b_ik_pub);

  if(result < 0) {
    goto complete;
  }

  if(!vpool_insert(&vp, vpool_get_length(&vp),
		   signal_buffer_data(ser_b_ik_pub),
		   signal_buffer_len(ser_b_ik_pub))) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  if(vpool_is_empty(&vp)) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  result_size = hkdf_derive_secrets(kdf, &resbuf,
				    vpool_get_buf(&vp),
				    vpool_get_length(&vp),
				    empty_salt, sizeof(empty_salt),
				    (const uint8_t*)kinf_tag, STRLEN_S(kinf_tag),
				    sizeof(*assoctag));

  if(result_size != sizeof(*assoctag)) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  memcpy(assoctag, resbuf, sizeof(*assoctag));

 complete:
  vpool_final(&vp);
  signal_buffer_free(ser_a_ik_pub);
  signal_buffer_free(ser_b_ik_pub);
  free(resbuf);
  SIGNAL_UNREF(kdf);
  return result;
}

typedef union beint32 {
  uint8_t a[sizeof(uint32_t)/sizeof(uint8_t)];
  uint32_t i;
} beint32;
static inline void ser32(beint32* ser, uint32_t i)
{
  ser->a[3] = (uint8_t)(i);
  ser->a[2] = (uint8_t)(i >> 8);
  ser->a[1] = (uint8_t)(i >> 16);
  ser->a[0] = (uint8_t)(i >> 24);
}

/*
 * assemble the payload (C[4]||"alice"||"bob"||g^E[a]||g^E[b])
 * or (C[5]||i||"alice"||"bob"||g^E[a]||g^E[b,i])
 * used by both idake and odake.
 */
int dake_concat_sign_payload(signal_buffer** sign_payload,
			     int isalice,
			     uint32_t a_regid,
			     uint32_t b_regid,
			     const ec_public_key* a_ek_pub,
			     const ec_public_key* b_ek_pub,
			     const uint32_t* b_ek_pub_idx)
{
  int result = 0;
  signal_buffer* ser_a_ek_pub = 0;
  signal_buffer* ser_b_ek_pub = 0;
  signal_buffer* concat = 0;
  const char* salt = 0;
  beint32 be_idx;
  beint32 be_a_regid;
  beint32 be_b_regid;
  struct vpool vp;
  vpool_init(&vp, 0, UINT16_MAX);

  result = ec_public_key_serialize(&ser_a_ek_pub,
				   a_ek_pub);

  if(result < 0) {
    goto complete;
  }

  result = ec_public_key_serialize(&ser_b_ek_pub,
				   b_ek_pub);

  if(result < 0) {
    goto complete;
  }

  if(isalice || b_ek_pub_idx) {
    salt = kinf_rsig_a;
  } else {
    salt = kinf_rsig_b;
  }

  if(!vpool_insert(&vp, vpool_get_length(&vp),
		   (void*)salt, STRLEN_S(kinf_rsig_a))) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  if(b_ek_pub_idx) {
    ser32(&be_idx, *b_ek_pub_idx);

    if(!vpool_insert(&vp, vpool_get_length(&vp),
		     &be_idx, sizeof(be_idx))) {
      result = SG_ERR_NOMEM;
      goto complete;
    }
  }

  ser32(&be_a_regid, a_regid);
  if(!vpool_insert(&vp, vpool_get_length(&vp),
		   &be_a_regid, sizeof(be_a_regid))) {
    result = SG_ERR_NOMEM;
    goto complete;
  }
  ser32(&be_b_regid, b_regid);
  if(!vpool_insert(&vp, vpool_get_length(&vp),
		   &be_b_regid, sizeof(be_b_regid))) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  if(!vpool_insert(&vp, vpool_get_length(&vp),
		   signal_buffer_data(ser_a_ek_pub),
		   signal_buffer_len(ser_a_ek_pub))) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  if(!vpool_insert(&vp, vpool_get_length(&vp),
		   signal_buffer_data(ser_b_ek_pub),
		   signal_buffer_len(ser_b_ek_pub))) {
    result = SG_ERR_NOMEM;
    goto complete;
  }

  if(vpool_is_empty(&vp)) {
    result = SG_ERR_UNKNOWN;
    goto complete;
  }

  concat = signal_buffer_create(vpool_get_buf(&vp), vpool_get_length(&vp));
  *sign_payload = concat;

 complete:
  vpool_final(&vp);
  signal_buffer_free(ser_a_ek_pub);
  signal_buffer_free(ser_b_ek_pub);
  return result;
}

int dake_rsign(signal_context* gctx, rsig* proof,
	       const ec_public_key* ika, const ec_public_key* ikb,
	       const ec_public_key* ek, const ec_private_key* sk,
	       const unsigned char* message, size_t msgLen,
	       const unsigned char* associatedData, size_t adLen,
	       const unsigned char* implHashTag, size_t ihtLen)
{
  int result = 0;
  hasher_imp hi;
  hasher h;
  keybytes random;

  copy_imp_signal(&hi, &(gctx->crypto_provider));
  hasher_init(&h, &hi, copy_userdata_signal(&(gctx->crypto_provider)));

  do {
    result = signal_crypto_random(gctx, (uint8_t*)&random, sizeof(random));
    if(result < 0) {
      break;
    }

    result = rsign_xed25519(&h, ec_key_get_bytes((const ec_key*)ika),
			    ec_key_get_bytes((const ec_key*)ikb),
			    ec_key_get_bytes((const ec_key*)ek),
			    ec_key_get_bytes((const ec_key*)sk),
			    message, msgLen, associatedData, adLen,
			    implHashTag, ihtLen, (const uint8_t*)&random,
			    sizeof(random), proof);
    if(result != 0) {
      result = SG_ERR_UNKNOWN;
    }
  } while (0);

  return result;
}

//negative return indicates error, otherwise return boolean.
int dake_rvrf(signal_context* gctx, const rsig* proof,
	      const ec_public_key* ika,
	      const ec_public_key* ikb,
	      const ec_public_key* ek,
	      const unsigned char* message, size_t msgLen,
	      const unsigned char* associatedData, size_t adLen,
	      const unsigned char* implHashTag, size_t ihtLen)
{
  int result = 0;
  hasher_imp hi;
  hasher h;

  copy_imp_signal(&hi, &(gctx->crypto_provider));
  hasher_init(&h, &hi, copy_userdata_signal(&(gctx->crypto_provider)));

  return rvrf_xed25519(&h, ec_key_get_bytes((const ec_key*)ika),
		       ec_key_get_bytes((const ec_key*)ikb),
		       ec_key_get_bytes((const ec_key*)ek),
		       proof, message, msgLen, associatedData, adLen,
		       implHashTag, ihtLen);
}

int dake_mac_sign_payload(signal_context* gctx,
			  signal_buffer** mac,
			  const uint8_t* mackey, size_t mkLen,
			  const uint8_t* message, size_t msgLen,
			  const uint8_t* associatedData, size_t adLen,
			  const uint8_t* implHashTag, size_t ihtLen)
{
  assert(gctx);
  int result = 0;
  void *hmac_context;
  signal_buffer *result_buf = 0;

  result = signal_hmac_sha256_init(gctx,
				   &hmac_context,
				   mackey, mkLen);
  if(result < 0) {
    goto complete;
  }

  result = signal_hmac_sha256_update(gctx, hmac_context,
				     implHashTag, ihtLen);
  if(result < 0) {
    goto complete;
  }

  result = signal_hmac_sha256_update(gctx, hmac_context,
				     message, msgLen);
  if(result < 0) {
    goto complete;
  }

  result = signal_hmac_sha256_update(gctx, hmac_context,
				     associatedData, adLen);
  if(result < 0) {
    goto complete;
  }

  result = signal_hmac_sha256_final(gctx,
				    hmac_context, &result_buf);
  if(result < 0 || signal_buffer_len(result_buf) < SIGNAL_MESSAGE_MAC_LENGTH) {
    if(result >= 0) {
      result = SG_ERR_UNKNOWN;
    }
    goto complete;
  }

  complete:
  signal_hmac_sha256_cleanup(gctx, hmac_context);
  if (result >= 0) {
    *mac = result_buf;
  } else {
    signal_buffer_free(result_buf);
  }

  return result;
}

int Idake_handle_idkeymsg(IdakeAuthInfo* auth, signal_context *gctx,
			  uint32_t our_regid,
			  const Signaldakez__IdakeMessage* idkeymsg,
			  int *havemsgp)
{
  int result = 0;
  Signaldakez__IdakeIdKeyMessage* idk = 0;
  if(idkeymsg->message_case != SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_EIK) {
    result = SG_ERR_INVALID_PROTO_BUF;
    goto complete;
  }
  Signaldakez__IdakeEncryptedIdKeyMessage* eidk = idkeymsg->eik;
  Signaldakez__IdakeRsignedIdKeyMessage rsidk
    = SIGNALDAKEZ__IDAKE_RSIGNED_ID_KEY_MESSAGE__INIT;
  Signaldakez__IdakeEncryptedRsIdKMessage ersidk
    = SIGNALDAKEZ__IDAKE_ENCRYPTED_RS_ID_KMESSAGE__INIT;
  Signaldakez__IdakeMessage authmsg
    = SIGNALDAKEZ__IDAKE_MESSAGE__INIT;

  signal_buffer* dgst = 0;
  signal_buffer* ser_idk = 0;
  signal_buffer* ser_our_ik_pub = 0;
  signal_buffer* sign_payload = 0;
  rsig sig;
  signal_buffer* imsg = 0;
  signal_buffer* emsg = 0;
  signal_buffer* msg = 0;
  size_t len = 0;
  size_t plen = 0;
  ec_public_key* their_ek_pub = 0;

#ifdef DUMPMSG
  {
    int dump_ret = 0;
    const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
    if (dumper && pbdumper_is_valid(dumper)) {
      dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			 "IdakeMessage", "received",
			 dumper->idake2str(dumper, idkeymsg));
    }
    if (dump_ret < 0) {
      result = dump_ret;
      goto complete;
    }
  }
#endif
  
  *havemsgp = 0;

  if(!eidk->has_prekey || !eidk->has_encidkey) {
    result = SG_ERR_INVALID_KEY;
    goto complete;
  }

  result = curve_decode_point(&their_ek_pub,
			      eidk->prekey.data,
			      eidk->prekey.len,
			      gctx);

  if(result < 0) {
    goto complete;
  }

  switch(auth->authstate) {
  case IDAKE_AUTHSTATE_AWAITING_IDKEY:
    result = signal_sha512_digest_1blob(gctx, eidk->prekey.data,
					eidk->prekey.len,
					&dgst);

    if(result < 0) {
      goto complete;
    }

    if(0 !=  signal_buffer_compare(dgst, auth->hash_their_ek)){
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    /* The incoming public key is valid, store it.*/
    SIGNAL_UNREF(auth->their_ek_pub);
    auth->their_ek_pub = their_ek_pub;
    SIGNAL_REF(auth->their_ek_pub);

    result = Idake_compute_ss(auth->our_ek_pair,
			      auth->their_ek_pub,
			      &auth->sharedsec);
    if(result < 0) {
      goto complete;
    }

    result = Idake_derive_keys(gctx, auth->sharedsec.a,
			       sizeof(auth->sharedsec),
			       &auth->derivedkeys);

    if(result < 0) {
      goto complete;
    }

    result = signal_decrypt(gctx, &ser_idk, SG_CIPHER_AES_CBC_PKCS5,
			    auth->derivedkeys[0].key.a, sizeof(auth->derivedkeys[0].key),
			    auth->derivedkeys[0].iv.a, sizeof(auth->derivedkeys[0].iv),
			    eidk->encidkey.data, eidk->encidkey.len);

    if(result < 0) {
      goto complete;
    }

    idk = signaldakez__idake_id_key_message__unpack(0, signal_buffer_len(ser_idk),
						    signal_buffer_data(ser_idk));

    if(!idk) {
      result = SG_ERR_INVALID_PROTO_BUF;
      goto complete;
    }

    if(!idk->has_regid || !idk->has_idkey) {
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    SIGNAL_UNREF(auth->their_ik_pub);
    result = curve_decode_point(&auth->their_ik_pub,
				idk->idkey.data,
				idk->idkey.len,
				gctx);

    if(result < 0) {
      goto complete;
    }

    result = dake_compute_assoctag(gctx, auth->their_ik_pub,
				   ec_key_pair_get_public(auth->our_ik_pair),
				   &auth->assoctag);

    if(result < 0) {
      goto complete;
    }

    result = dake_concat_sign_payload(&sign_payload, false,
				      idk->regid, our_regid,
				      auth->their_ek_pub,
				      ec_key_pair_get_public(auth->our_ek_pair),
				      NULL);
    if(result < 0) {
      goto complete;
    }

    result = dake_rsign(gctx, &sig,
			auth->their_ik_pub,
			ec_key_pair_get_public(auth->our_ik_pair),
			auth->their_ek_pub,
			ec_key_pair_get_private(auth->our_ik_pair),
			signal_buffer_data(sign_payload),
			signal_buffer_len(sign_payload),
			(const uint8_t*)&auth->assoctag,
			sizeof(auth->assoctag),
			(const uint8_t*)kinf_iht,
			STRLEN_S(kinf_iht));
    if(result < 0) {
      goto complete;
    }

    result = ec_public_key_serialize(&ser_our_ik_pub,
				     ec_key_pair_get_public(auth->our_ik_pair));
    if(result < 0) {
      goto complete;
    }

    rsidk.has_idkey = true;
    rsidk.idkey.data = signal_buffer_data(ser_our_ik_pub);
    rsidk.idkey.len = signal_buffer_len(ser_our_ik_pub);
    rsidk.has_regid = true;
    rsidk.regid = our_regid;
    rsidk.has_rsig = true;
    rsidk.rsig.data = (uint8_t*)&sig;
    rsidk.rsig.len = sizeof(sig);

    len = signaldakez__idake_rsigned_id_key_message__get_packed_size(&rsidk);
    imsg = signal_buffer_alloc(len);
    if(!imsg) {
      result = SG_ERR_NOMEM;
      goto complete;
    }

    plen = signaldakez__idake_rsigned_id_key_message__pack(&rsidk,
							   signal_buffer_data(imsg));

    if(plen != len) {
      result = SG_ERR_INVALID_PROTO_BUF;
      goto complete;
    }

    result = signal_encrypt(gctx, &emsg, SG_CIPHER_AES_CBC_PKCS5,
			    auth->derivedkeys[1].key.a, sizeof(auth->derivedkeys[1].key),
			    auth->derivedkeys[1].iv.a, sizeof(auth->derivedkeys[1].iv),
			    signal_buffer_data(imsg),
			    signal_buffer_len(imsg));
    if(result < 0) {
      goto complete;
    }

    ersidk.has_encrsidkeymsg = true;
    ersidk.encrsidkeymsg.data = signal_buffer_data(emsg);
    ersidk.encrsidkeymsg.len = signal_buffer_len(emsg);

    authmsg.message_case = SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERIK;
    authmsg.erik = &ersidk;
    result = Idake_pack_authmsg(&msg, &authmsg);
    if(result < 0) {
      goto complete;
    }
    
    signal_buffer_free(auth->lastauthmsg);
    auth->lastauthmsg = msg;
    auth->regids[0] = our_regid;
    auth->regids[1] = idk->regid;
    msg = 0;
    *havemsgp = 1;
    auth->authstate = IDAKE_AUTHSTATE_AWAITING_ERSIG;
#ifdef DUMPMSG
    {
      int dump_ret = 0;
      const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
      if (dumper && pbdumper_is_valid(dumper)) {
	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "IdakeIdKeyMessage", "decrypted",
			   dumper->idk2str((const ProtobufCMessage*)idk));

	if (dump_ret < 0) {
	  result = dump_ret;
	  break;
	}

	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "IdakeIdKeyMessage", "to be encrypted as IdakeEncryptedIdKeyMessage::encrsidkeymsg",
			   dumper->rsidk2str((const ProtobufCMessage*)&rsidk));

	if (dump_ret < 0) {
	  result = dump_ret;
	  break;
	}

	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "IdakeEncryptedIdKeyMessage", "to send",
			   dumper->ersidk2str((const ProtobufCMessage*)&ersidk));
      }
      if (dump_ret < 0)
	result = dump_ret;
    }
#endif
    break;
  case IDAKE_AUTHSTATE_NONE:
  case IDAKE_AUTHSTATE_AWAITING_PREKEY:
  case IDAKE_AUTHSTATE_AWAITING_ERSIDK:
  case IDAKE_AUTHSTATE_AWAITING_ERSIG:
    *havemsgp = 0;
    break;
  }
 complete:
  signal_buffer_free(dgst);
  signal_buffer_free(ser_our_ik_pub);
  signal_buffer_free(imsg);
  signal_buffer_free(emsg);
  signal_buffer_free(msg);
  SIGNAL_UNREF(their_ek_pub);

  return result;
}

int Idake_handle_ersidkmsg(IdakeAuthInfo* auth, signal_context *gctx,
			   const Signaldakez__IdakeMessage* ersidkmsg,
			   int *havemsgp, auth_succeeded_ft* auth_succeeded,
			   void* asdata)
{
  int result = 0;
  Signaldakez__IdakeEncryptedRsIdKMessage* ersidk = 0;
  Signaldakez__IdakeRsignedIdKeyMessage* rsidk = 0;
  Signaldakez__IdakeEncryptedRsigMessage ersig
    = SIGNALDAKEZ__IDAKE_ENCRYPTED_RSIG_MESSAGE__INIT;
  Signaldakez__IdakeMessage authmsg = SIGNALDAKEZ__IDAKE_MESSAGE__INIT;

  signal_buffer* rsidkmsg = 0;
  signal_buffer* sign_payload = 0;
  rsig oursig;
  signal_buffer* esig = 0;
  symkey assoctag;
  const rsig* theirsig = 0;
  signal_buffer* msg = 0;
  size_t len = 0;
  size_t plen = 0;
  ec_public_key* their_ik_pub = 0;

#ifdef DUMPMSG
  {
    int dump_ret = 0;
    const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
    if (dumper && pbdumper_is_valid(dumper)) {
      dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			 "IdakeMessage", "received",
			 dumper->idake2str(dumper, ersidkmsg));
    }
    if (dump_ret < 0) {
      result = dump_ret;
      goto complete;
    }
  }
#endif

  *havemsgp = 0;

  if(ersidkmsg->message_case != SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERIK) {
    result = SG_ERR_INVALID_PROTO_BUF;
    goto complete;
  }
  ersidk = ersidkmsg->erik;

  if(!ersidk || !ersidk->has_encrsidkeymsg ) {
    result = SG_ERR_INVALID_PROTO_BUF;
    goto complete;
  }
  switch(auth->authstate) {
  case IDAKE_AUTHSTATE_AWAITING_ERSIDK:
    result = signal_decrypt(gctx, &rsidkmsg, SG_CIPHER_AES_CBC_PKCS5,
			    auth->derivedkeys[1].key.a, sizeof(auth->derivedkeys[1].key),
			    auth->derivedkeys[1].iv.a, sizeof(auth->derivedkeys[1].iv),
			    ersidk->encrsidkeymsg.data, ersidk->encrsidkeymsg.len);

    if(result < 0) {
      goto complete;
    }

    rsidk
      = signaldakez__idake_rsigned_id_key_message__unpack(0,
							  signal_buffer_len(rsidkmsg),
							  signal_buffer_data(rsidkmsg));
    if(!rsidk) {
      result = SG_ERR_INVALID_PROTO_BUF;
      goto complete;
    }

    if(!rsidk->has_idkey || !rsidk->has_regid || !rsidk->has_rsig || (rsidk->rsig.len != sizeof(rsig))) {
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    result = curve_decode_point(&their_ik_pub,
				rsidk->idkey.data,
				rsidk->idkey.len,
				gctx);

    if(result < 0) {
      goto complete;
    }

    theirsig = (const rsig*)rsidk->rsig.data;

    result = dake_concat_sign_payload(&sign_payload, false,
				      auth->regids[0], rsidk->regid,
				      ec_key_pair_get_public(auth->our_ek_pair),
				      auth->their_ek_pub,
				      NULL);

    if(result < 0) {
      goto complete;
    }

    result = dake_compute_assoctag(gctx, ec_key_pair_get_public(auth->our_ik_pair),
				   their_ik_pub,
				   &assoctag);
    if(result < 0) {
      goto complete;
    }

    result = dake_rvrf(gctx, theirsig,
		       ec_key_pair_get_public(auth->our_ik_pair),
		       their_ik_pub,
		       ec_key_pair_get_public(auth->our_ek_pair),
		       signal_buffer_data(sign_payload),
		       signal_buffer_len(sign_payload),
		       (const uint8_t*)&assoctag, sizeof(assoctag),
		       (const uint8_t*)kinf_iht,
		       STRLEN_S(kinf_iht));
    if(result < 0) {
      result = SG_ERR_UNKNOWN;
      goto complete;
    } else if(result == false) {
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    //theirsig verified! accept incoming data.
    SIGNAL_UNREF(auth->their_ik_pub);
    auth->their_ik_pub = their_ik_pub;
    SIGNAL_REF(auth->their_ik_pub);

    memcpy(&auth->assoctag, &assoctag, sizeof(assoctag));

    //calculate oursig.
    signal_buffer_free(sign_payload);
    result = dake_concat_sign_payload(&sign_payload, true,
				      auth->regids[0], rsidk->regid,
				      ec_key_pair_get_public(auth->our_ek_pair),
				      auth->their_ek_pub,
				      NULL);
    if(result < 0) {
      goto complete;
    }

    result = dake_rsign(gctx, &oursig,
			ec_key_pair_get_public(auth->our_ik_pair),
			auth->their_ik_pub,
			auth->their_ek_pub,
			ec_key_pair_get_private(auth->our_ik_pair),
			signal_buffer_data(sign_payload),
			signal_buffer_len(sign_payload),
			(const uint8_t*)&auth->assoctag,
			sizeof(auth->assoctag),
			(const uint8_t*)kinf_iht,
			STRLEN_S(kinf_iht));
    if(result < 0) {
      goto complete;
    }

    result = signal_encrypt(gctx, &esig, SG_CIPHER_AES_CBC_PKCS5,
			    auth->derivedkeys[2].key.a, sizeof(auth->derivedkeys[2].key),
			    auth->derivedkeys[2].iv.a, sizeof(auth->derivedkeys[2].iv),
			    (const uint8_t*)&oursig, sizeof(oursig));

    ersig.has_encrsig = true;
    ersig.encrsig.data = signal_buffer_data(esig);
    ersig.encrsig.len = signal_buffer_len(esig);

    authmsg.message_case = SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERSIG;
    authmsg.ersig = &ersig;
    result = Idake_pack_authmsg(&msg, &authmsg);
    if(result < 0) {
      goto complete;
    }

    signal_buffer_free(auth->lastauthmsg);
    auth->lastauthmsg = msg;
    msg = 0;

    /* No error?  Then we've completed our end of the
     * authentication. */
    auth->isalice = true;
    auth->regids[1] = rsidk->regid;
    if (auth_succeeded) {
      result = auth_succeeded(auth, asdata);
    }
    *havemsgp = 1;
    auth->authstate = IDAKE_AUTHSTATE_NONE;
#ifdef DUMPMSG
    {
      int dump_ret = 0;
      const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
      if (dumper && pbdumper_is_valid(dumper)) {
	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "IdakeIdKeyMessage", "decrypted",
			   dumper->rsidk2str((const ProtobufCMessage*)rsidk));
	if (dump_ret < 0) {
	  result = dump_ret;
	  break;
	}
	dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			   "IdakeEncryptedRsigMessage", "to send",
			   dumper->ersig2str((const ProtobufCMessage*)&ersig));
      }
      if (dump_ret < 0)
	result = dump_ret;
    }
#endif
    break;
  case IDAKE_AUTHSTATE_NONE:
  case IDAKE_AUTHSTATE_AWAITING_PREKEY:
  case IDAKE_AUTHSTATE_AWAITING_IDKEY:
  case IDAKE_AUTHSTATE_AWAITING_ERSIG:
    *havemsgp = 0;
    break;
  }
 complete:
  signaldakez__idake_rsigned_id_key_message__free_unpacked(rsidk, 0);
  signal_buffer_free(rsidkmsg);
  signal_buffer_free(sign_payload);
  signal_buffer_free(msg);
  SIGNAL_UNREF(their_ik_pub);
  return result;
}

int Idake_handle_ersigmsg(IdakeAuthInfo* auth, signal_context *gctx,
			  const Signaldakez__IdakeMessage* ersigmsg,
			  int *havemsgp, auth_succeeded_ft* auth_succeeded,
			  void* asdata)
{
  int result = 0;
  Signaldakez__IdakeEncryptedRsigMessage* ersig = 0;
  signal_buffer* sign_payload = 0;
  signal_buffer* theirsig = 0;
#ifdef DUMPMSG
  {
    int dump_ret = 0;
    const pbdumper* dumper = user_data_get_dumper(signal_context_get_user_data(gctx));
    if (dumper && pbdumper_is_valid(dumper)) {
      dump_ret = dump_pb(gctx, dumper, __FILE__, __LINE__, __func__,
			 "IdakeMessage", "received",
			 dumper->idake2str(dumper, ersigmsg));
    }
    if (dump_ret < 0) {
      result = dump_ret;
      goto complete;
    }
  }
#endif
  *havemsgp = 0;

  if(ersigmsg->message_case != SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERSIG) {
    result = SG_ERR_INVALID_PROTO_BUF;
    goto complete;
  }
  ersig = ersigmsg->ersig;

  if(!ersig->has_encrsig) {
    result = SG_ERR_INVALID_KEY;
    goto complete;
  }

  switch(auth->authstate) {
  case IDAKE_AUTHSTATE_AWAITING_ERSIG:
    result = signal_decrypt(gctx, &theirsig, SG_CIPHER_AES_CBC_PKCS5,
			    auth->derivedkeys[2].key.a, sizeof(auth->derivedkeys[2].key),
			    auth->derivedkeys[2].iv.a, sizeof(auth->derivedkeys[2].iv),
			    ersig->encrsig.data, ersig->encrsig.len);
    if(result < 0) {
      goto complete;
    }

    if(signal_buffer_len(theirsig) != sizeof(rsig)) {
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    result = dake_concat_sign_payload(&sign_payload, true,
				      auth->regids[1], auth->regids[0],
				      auth->their_ek_pub,
				      ec_key_pair_get_public(auth->our_ek_pair),
				      NULL);
    if(result < 0) {
      goto complete;
    }

    result = dake_rvrf(gctx, (const rsig*)signal_buffer_data(theirsig),
		       auth->their_ik_pub,
		       ec_key_pair_get_public(auth->our_ik_pair),
		       ec_key_pair_get_public(auth->our_ek_pair),
		       signal_buffer_data(sign_payload),
		       signal_buffer_len(sign_payload),
		       (const uint8_t*)&auth->assoctag, sizeof(auth->assoctag),
		       (const uint8_t*)kinf_iht,
		       STRLEN_S(kinf_iht));
    if(result < 0) {
      result = SG_ERR_UNKNOWN;
      goto complete;
    } else if(result == false) {
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }
    /* No error?  Then we've completed our end of the
     * authentication. */
    auth->isalice = false;
    if (auth_succeeded) {
      result = auth_succeeded(auth, asdata);
    }
    signal_buffer_free(auth->lastauthmsg);
    auth->lastauthmsg = 0;
    *havemsgp = 0;
    auth->authstate = IDAKE_AUTHSTATE_NONE;
    break;
  case IDAKE_AUTHSTATE_NONE:
  case IDAKE_AUTHSTATE_AWAITING_PREKEY:
  case IDAKE_AUTHSTATE_AWAITING_IDKEY:
  case IDAKE_AUTHSTATE_AWAITING_ERSIDK:
    *havemsgp = 0;
    break;
  }
 complete:
  signal_buffer_free(sign_payload);
  signal_buffer_free(theirsig);

  return result;
}


/*
 * Initialize a double ratchet session,
 * using one shared secret, a local DHE pair,
 * and an optional remote DHE public prekey if session
 * is initialized aas alice, otherwise
 * it should be NULL.
 */
int session_state_init_session(signal_context* gctx,
			       session_state* state,
			       const uint8_t* shared_secret,
			       size_t ss_len,
			       ec_public_key* their_rk_pub,
			       ec_key_pair* our_rk_pair)
{
  int result = 0;
  ratchet_root_key *derived_root = 0;
  ratchet_chain_key *derived_chain = 0;
  ratchet_root_key *sending_chain_root = 0;
  ratchet_chain_key *sending_chain_key = 0;

  assert(state);
  assert(gctx);

  result = ratcheting_session_calculate_derived_keys(&derived_root,
						     &derived_chain,
						     (uint8_t*)shared_secret,
						     ss_len,
						     gctx);

  if(result < 0) {
    goto complete;
  }
  if (their_rk_pub) {
    result
      = ratchet_root_key_create_chain(derived_root,
				      &sending_chain_root,
				      &sending_chain_key,
				      their_rk_pub,
				      ec_key_pair_get_private(our_rk_pair));
    if(result < 0) {
      goto complete;
    }

    result = session_state_add_receiver_chain(state,
					      their_rk_pub,
					      derived_chain);
    if(result < 0) {
      goto complete;
    }

    session_state_set_sender_chain(state, our_rk_pair, sending_chain_key);
    session_state_set_root_key(state, sending_chain_root);
  } else {
    session_state_set_sender_chain(state, our_rk_pair, derived_chain);
    session_state_set_root_key(state, derived_root);
  }

 complete:
  SIGNAL_UNREF(derived_root);
  SIGNAL_UNREF(derived_chain);
  SIGNAL_UNREF(sending_chain_root);
  SIGNAL_UNREF(sending_chain_key);

  return result;
}


int Idake_init_session(IdakeAuthInfo* auth,
		       session_state* state,
		       signal_context* gctx)
{
  int result = 0;
  ec_key_pair* newrk = NULL;
  assert(auth);
  assert(auth->our_ek_pair);
  assert(auth->their_ek_pub);
  assert(auth->our_ik_pair);
  assert(auth->their_ik_pub);
  assert(state);
  assert(gctx);

  if (auth->isalice) {
    result = curve_generate_key_pair(gctx, &newrk);
    if (result < 0) {
      goto complete;
    }
    
    result = session_state_init_session(gctx, state,
					auth->sharedsec.a,
					sizeof(auth->sharedsec),
					auth->their_ek_pub,
					newrk);
  } else {
    result = session_state_init_session(gctx, state,
					auth->sharedsec.a,
					sizeof(auth->sharedsec),
					NULL,
					auth->our_ek_pair);
  }

  if(result < 0) {
    goto complete;
  }

  session_state_set_session_version(state, CIPHERTEXT_CURRENT_VERSION);
  session_state_set_remote_identity_key(state, auth->their_ik_pub);
  session_state_set_local_identity_key(state, ec_key_pair_get_public(auth->our_ik_pair));
  session_state_set_local_registration_id(state, auth->regids[0]);
  session_state_set_remote_registration_id(state, auth->regids[1]);
  session_state_set_alice_base_key(state,
				   (auth->isalice)?
				   ec_key_pair_get_public(auth->our_ek_pair):
				   auth->their_ek_pub);

  //TODO: replace it with our own magic number.
  session_state_set_session_version(state, CIPHERTEXT_CURRENT_VERSION);

 complete:
  SIGNAL_UNREF(newrk);
  return result;
}
