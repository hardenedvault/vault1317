/*
 * Copyright (C) 2018-2024, HardenedVault (https://hardenedvault.net)
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

#include <string.h>
#include "axc_helper.h"
#include "idake2session.h"
#include "odake.h"

int axc_context_dake_create(axc_context_dake ** ctx_pp) {
  if (!ctx_pp) {
    return -1;
  }

  axc_context_dake * ctx_p = (void *) 0;
  ctx_p = malloc(sizeof(axc_context_dake));
  if (!ctx_p) {
    return -2;
  }
  memset(ctx_p, 0, sizeof(axc_context_dake));

  ctx_p->base.log_level = -1;

  *ctx_pp = ctx_p;
  return 0;
}

void axc_context_dake_destroy_all(axc_context * ctx_p) {
  if (ctx_p) {
    axc_context_dake* ctx_dake = (axc_context_dake*)ctx_p;
    while (ctx_dake->l_authinfo) {
      auth_node_free(CL_CONTAINER_OF(cl_unlink_node(ctx_dake->l_authinfo), auth_node, cl));
    }
    axc_context_destroy_all(&(ctx_dake->base));
  }
}

int axc_init_with_imp(axc_context* ctx_p,
		      const signal_protocol_session_store* session_store_tmpl,
		      const signal_protocol_pre_key_store* pre_key_store_tmpl,
		      const signal_protocol_signed_pre_key_store* spk_store_tmpl,
		      const signal_protocol_identity_key_store* idk_store_tmpl,
		      const signal_crypto_provider* crypto_provider_tmpl)
{
  axc_log(ctx_p, AXC_LOG_INFO, "%s: initializing axolotl client", __func__);
  const char * err_msg = " ";
  int ret_val = 0;

  axc_mutexes * mutexes_p = (void *) 0;
  signal_protocol_store_context * store_context_p = (void *) 0;

  signal_protocol_session_store session_store = *session_store_tmpl;
  session_store.user_data = ctx_p;
  signal_protocol_pre_key_store pre_key_store = *pre_key_store_tmpl;
  pre_key_store.user_data = ctx_p;
  signal_protocol_signed_pre_key_store signed_pre_key_store = *spk_store_tmpl;
  signed_pre_key_store.user_data = ctx_p;
  signal_protocol_identity_key_store identity_key_store = *idk_store_tmpl;
  identity_key_store.user_data = ctx_p;

  // init mutexes
  ret_val = axc_mutexes_create_and_init(&mutexes_p);
  if (ret_val) {
    err_msg = "failed to create or init mutexes";
    goto cleanup;
  }
  ctx_p->mutexes_p = mutexes_p;

  // axolotl lib init
  // 1. create global context
  if (signal_context_create(&(ctx_p->axolotl_global_context_p), ctx_p)) {
    err_msg = "failed to create global axolotl context";
    ret_val = -1;
    goto cleanup;
  }
  axc_log(ctx_p, AXC_LOG_DEBUG, "%s: created and set axolotl context", __func__);

  // 2. init and set crypto provider
  signal_crypto_provider crypto_provider = *crypto_provider_tmpl;
  crypto_provider.user_data = ctx_p;

  if (signal_context_set_crypto_provider(ctx_p->axolotl_global_context_p, &crypto_provider)) {
    err_msg = "failed to set crypto provider";
    ret_val = -1;
    goto cleanup;
  }
  axc_log(ctx_p, AXC_LOG_DEBUG, "%s: set axolotl crypto provider", __func__);

  // 3. set locking functions
#ifndef NO_THREADS
  if (signal_context_set_locking_functions(ctx_p->axolotl_global_context_p, recursive_mutex_lock, recursive_mutex_unlock)) {
    err_msg = "failed to set locking functions";
    ret_val = -1;
    goto cleanup;
  }
  axc_log(ctx_p, AXC_LOG_DEBUG, "%s: set locking functions", __func__);
#endif

  // init store context

  if (signal_protocol_store_context_create(&store_context_p, ctx_p->axolotl_global_context_p)) {
    err_msg = "failed to create store context";
    ret_val = -1;
    goto cleanup;
  }

  axc_log(ctx_p, AXC_LOG_DEBUG, "%s: created store context", __func__);

  if (signal_protocol_store_context_set_session_store(store_context_p, &session_store)) {
    err_msg = "failed to create session store";
    ret_val = -1;
    goto cleanup;
  }

  if (signal_protocol_store_context_set_pre_key_store(store_context_p, &pre_key_store)) {
    err_msg = "failed to set pre key store";
    ret_val = -1;
    goto cleanup;
  }

  if (signal_protocol_store_context_set_signed_pre_key_store(store_context_p, &signed_pre_key_store)) {
    err_msg = "failed to set signed pre key store";
    ret_val = -1;
    goto cleanup;
  }

  if (signal_protocol_store_context_set_identity_key_store(store_context_p, &identity_key_store)) {
    err_msg = "failed to set identity key store";
    ret_val = -1;
    goto cleanup;
  }

  ctx_p->axolotl_store_context_p = store_context_p;
  axc_log(ctx_p, AXC_LOG_DEBUG, "%s: set store context", __func__);

  if (signal_context_set_log_function(ctx_p->axolotl_global_context_p, ctx_p->log_func)) {
    err_msg = "failed to set log function for axolotl_global_context";
    ret_val = -1;
    goto cleanup;
  }

cleanup:
  if (ret_val < 0) {
    //FIXME: this frees inited context, make this more fine-grained
    axc_cleanup(ctx_p);
    axc_log(ctx_p, AXC_LOG_ERROR, "%s: %s", __func__, err_msg);
  } else {
    axc_log(ctx_p, AXC_LOG_INFO, "%s: done initializing axc", __func__);
  }
  return ret_val;
}

int axc_msg_enc_and_ser_dake(axc_buf * msg_p,
			     const axc_address * recipient_addr_p,
			     axc_context * ctx_p,
			     axc_buf ** ciphertext_pp)
{
  const char * err_msg = "";
  int ret_val = 0;

  session_cipher * cipher_p = (void *) 0;
  ciphertext_message * cipher_msg_p = (void *) 0;
  signal_buffer * cipher_msg_data_p = (void *) 0;
  axc_buf * cipher_msg_data_cpy_p = (void *) 0;
  axc_address rr_addr = *recipient_addr_p;

  if (!ctx_p) {
    fprintf(stderr, "%s: axc ctx is null!\n", __func__);
    return -1;
  }

  if (!msg_p) {
    err_msg = "could not encrypt because msg pointer is null";
    ret_val = -1;
    goto cleanup;
  }
  if (!recipient_addr_p) {
    err_msg = "could not encrypt because recipient addr pointer is null";
    ret_val = -1;
    goto cleanup;
  }
  if (!ciphertext_pp) {
    err_msg = "could not encrypt because ciphertext pointer is null";
    ret_val = -1;
    goto cleanup;
  }

  ret_val = axc_context_dake_get_real_regid((axc_context_dake*)ctx_p, recipient_addr_p,
					    &rr_addr.device_id);

  if (ret_val < 0) {
    err_msg = "failed to get real recipient device id";
    goto cleanup;
  }

  ret_val = session_cipher_create(&cipher_p, ctx_p->axolotl_store_context_p, &rr_addr, ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to create session cipher";
    goto cleanup;
  }

  ret_val = session_cipher_encrypt_odake_wrapper(cipher_p, axc_buf_get_data(msg_p), axc_buf_get_len(msg_p), &cipher_msg_p);
  if (ret_val) {
    err_msg = "failed to encrypt the message";
    goto cleanup;
  }

  cipher_msg_data_p = ciphertext_message_get_serialized(cipher_msg_p);
  cipher_msg_data_cpy_p = signal_buffer_copy(cipher_msg_data_p);

  if (!cipher_msg_data_cpy_p) {
    err_msg = "failed to copy cipher msg data";
    ret_val = -1;
    goto cleanup;
  }

  *ciphertext_pp = cipher_msg_data_cpy_p;

cleanup:
  if (ret_val < 0) {
    axc_log(ctx_p, AXC_LOG_ERROR, "%s: %s", __func__, err_msg);
    axc_buf_free(cipher_msg_data_cpy_p);
  }

  session_cipher_free(cipher_p);
  SIGNAL_UNREF(cipher_msg_p);

  return ret_val;
}

int axc_message_dec_from_ser_dake (axc_buf * msg_p,
				   const axc_address * sender_addr_p,
				   axc_context * ctx_p,
				   axc_buf ** plaintext_pp)
{
  char * err_msg = "";
  int ret_val = 0;

  //TODO: add session_cipher_set_decryption_callback maybe?
  //FIXME: check message type

  signal_message * ciphertext_p = (void *) 0;
  session_cipher * cipher_p = (void *) 0;
  axc_buf * plaintext_buf_p = (void *) 0;
  axc_address rs_addr = *sender_addr_p;

  if (!ctx_p) {
    fprintf(stderr, "%s: axc ctx is null!\n", __func__);
    return -1;
  }

  if (!msg_p) {
    err_msg = "could not decrypt because message pointer is null";
    ret_val = -1;
    goto cleanup;
  }
  if (!sender_addr_p) {
    err_msg = "could not decrypt because sender address pointer is null";
    ret_val = -1;
    goto cleanup;
  }
  if (!plaintext_pp) {
    err_msg = "could not decrypt because plaintext pointer is null";
    ret_val = -1;
    goto cleanup;
  }

  ret_val = axc_context_dake_get_real_regid((axc_context_dake*)ctx_p, sender_addr_p,
					    &rs_addr.device_id);

  if (ret_val < 0) {
    err_msg = "failed to get real sender device id";
    goto cleanup;
  }
  ret_val = session_cipher_create(&cipher_p, ctx_p->axolotl_store_context_p, &rs_addr, ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to create session cipher";
    goto cleanup;
  }

  ret_val = signal_message_deserialize(&ciphertext_p, axc_buf_get_data(msg_p), axc_buf_get_len(msg_p), ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to deserialize whisper msg";
    goto cleanup;
  }
  ret_val = session_cipher_decrypt_signal_message_wrapper(cipher_p, ciphertext_p, (void *) 0, &plaintext_buf_p);
  if (ret_val) {
    err_msg = "failed to decrypt cipher message";
    goto cleanup;
  }

  *plaintext_pp = plaintext_buf_p;

cleanup:
  if (ret_val < 0) {
    axc_log(ctx_p, AXC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  session_cipher_free(cipher_p);
  SIGNAL_UNREF(ciphertext_p);

  return ret_val;
}

int axc_session_from_bundle_dake(uint32_t pre_key_id,
				 axc_buf * pre_key_public_serialized_p,
				 uint32_t signed_pre_key_id,
				 axc_buf * signed_pre_key_public_serialized_p,
				 axc_buf * signed_pre_key_signature_p,
				 axc_buf * identity_key_public_serialized_p,
				 const axc_address * remote_address_p,
				 axc_context * ctx_p)
{
  const char * err_msg = "";
  int ret_val = 0;

  ec_public_key * pre_key_public_p = (void *) 0;
  ec_public_key * signed_pre_key_public_p = (void *) 0;
  session_pre_key_bundle * bundle_p = (void *) 0;
  session_builder * session_builder_p = (void *) 0;

  ret_val = curve_decode_point(&pre_key_public_p,
                               axc_buf_get_data(pre_key_public_serialized_p),
                               axc_buf_get_len(pre_key_public_serialized_p),
                               ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to deserialize public pre key";
    goto cleanup;
  }


  ret_val = curve_decode_point(&signed_pre_key_public_p,
                               axc_buf_get_data(signed_pre_key_public_serialized_p),
                               axc_buf_get_len(signed_pre_key_public_serialized_p),
                               ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to deserialize signed public pre key";
    goto cleanup;
  }

  ret_val = session_pre_key_bundle_create(&bundle_p,
                                          remote_address_p->device_id,
                                          remote_address_p->device_id, // this value is ignored
                                          pre_key_id,
                                          pre_key_public_p,
                                          signed_pre_key_id,
                                          signed_pre_key_public_p,
                                          axc_buf_get_data(signed_pre_key_signature_p),
                                          axc_buf_get_len(signed_pre_key_signature_p),
                                          NULL);
  if (ret_val) {
    err_msg = "failed to assemble bundle";
    goto cleanup;
  }

  ret_val = session_builder_create(&session_builder_p, ctx_p->axolotl_store_context_p, remote_address_p, ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to create session builder";
    goto cleanup;
  }

  ret_val = session_builder_process_pre_key_bundle_odake(session_builder_p, bundle_p);
  if (ret_val) {
    err_msg = "failed to process pre key bundle";
    goto cleanup;
  }

cleanup:
  if (ret_val) {
    axc_log(ctx_p, AXC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  SIGNAL_UNREF(pre_key_public_p);
  SIGNAL_UNREF(signed_pre_key_public_p);
  SIGNAL_UNREF(bundle_p);
  session_builder_free(session_builder_p);

  return ret_val;
}

int axc_pre_key_message_process_dake(axc_buf * pre_key_msg_serialized_p,
				     const axc_address * remote_address_p,
				     axc_context * ctx_p,
				     axc_buf ** plaintext_pp)
{
  const char * err_msg = "";
  int ret_val = 0;
  axc_address rr_addr = *remote_address_p;
  session_builder * session_builder_p = (void *) 0;
  pre_key_odake_message * pre_key_msg_p = (void *) 0;
  uint32_t new_id = 0;
  uint32_t pre_key_id = 0;
  session_cipher * session_cipher_p = (void *) 0;
  axc_buf * plaintext_p = (void *) 0;
  signal_protocol_key_helper_pre_key_list_node * key_l_p = (void *) 0;


  ret_val = session_builder_create(&session_builder_p, ctx_p->axolotl_store_context_p, remote_address_p, ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to create session builder";
    goto cleanup;
  }


  ret_val = pre_key_odake_message_pre_deserialize(&pre_key_msg_p,
						  axc_buf_get_data(pre_key_msg_serialized_p),
						  axc_buf_get_len(pre_key_msg_serialized_p),
						  ctx_p->axolotl_global_context_p);
  if (ret_val == SG_ERR_INVALID_PROTO_BUF) {
    err_msg = "not a pre key msg";
    ret_val = AXC_ERR_NOT_A_PREKEY_MSG;
    goto cleanup;
  } else if (ret_val == SG_ERR_INVALID_KEY_ID) {
    ret_val = AXC_ERR_INVALID_KEY_ID;
    goto cleanup;
  } else if (ret_val) {
    err_msg = "failed to deserialize pre key message";
    goto cleanup;
  }

  ret_val = axc_db_pre_key_get_max_id(ctx_p, &new_id);
  if (ret_val) {
    err_msg = "failed to retrieve max pre key id";
    goto cleanup;
  }


  do {
    ret_val = signal_protocol_key_helper_generate_pre_keys(&key_l_p, new_id, 1, ctx_p->axolotl_global_context_p);
    if (ret_val) {
      err_msg = "failed to generate a new key";
      goto cleanup;
    }

    new_id++;

  } while (signal_protocol_pre_key_contains_key(ctx_p->axolotl_store_context_p, session_pre_key_get_id(signal_protocol_key_helper_key_list_element(key_l_p))));

  {
    axc_context_dake* dakectx_p = (axc_context_dake*)ctx_p;
    bob_signal_protocol_parameters* bob_param = NULL;
    uint32_t l_regid = 0;
    axc_buf* ss = NULL;
    session_record* record = NULL;
    signal_lock(ctx_p->axolotl_global_context_p);
    do {
      ret_val = signal_protocol_identity_get_local_registration_id(ctx_p->axolotl_store_context_p,
								   &l_regid);
      if (ret_val < 0) break;
      ret_val = bob_parameters_from_pre_key_msg(ctx_p->axolotl_store_context_p,
						pre_key_msg_p, &bob_param);
      if (ret_val < 0) break;
      ret_val = pre_key_odake_message_handshake(ctx_p->axolotl_global_context_p,
						pre_key_msg_p, bob_param, l_regid,
						&ss);
      if (ret_val < 0) break;
      ret_val = axc_context_dake_set_real_regid(dakectx_p, remote_address_p, pre_key_msg_p->registration_id);
      if (ret_val < 0) break;
      rr_addr.device_id = pre_key_msg_p->registration_id;

      ret_val = signal_protocol_session_load_session(ctx_p->axolotl_store_context_p, &record,
						       &rr_addr);
      if (ret_val < 0) break;
      if(!session_record_is_fresh(record)) {
	ret_val = session_record_archive_current_state(record);
	if(ret_val < 0) break;
      }
      ret_val = pre_key_odake_message_init_session(pre_key_msg_p, bob_param, l_regid, ss,
						   session_record_get_state(record),
						   ctx_p->axolotl_global_context_p);
      if(ret_val < 0) break;
      ret_val = signal_protocol_session_store_session(ctx_p->axolotl_store_context_p,
						     &rr_addr,
						     record);
    } while(0);
    signal_unlock(ctx_p->axolotl_global_context_p);
    SIGNAL_UNREF(bob_param);
    SIGNAL_UNREF(record);
    signal_buffer_bzero_free(ss);
    if (ret_val < 0) {
      err_msg = "failed to initialize session";
      goto cleanup;
    }
  }
  ret_val = session_cipher_create(&session_cipher_p, ctx_p->axolotl_store_context_p, &rr_addr, ctx_p->axolotl_global_context_p);
  if (ret_val) {
    err_msg = "failed to create session cipher";
    goto cleanup;
  }

  //FIXME: find a way to retain the key (for MAM catchup)
  ret_val = session_cipher_decrypt_pre_key_odake_message_wrapper(session_cipher_p, pre_key_msg_p, (void *) 0, &plaintext_p);
  if (ret_val) {
    err_msg = "failed to decrypt message";
    goto cleanup;
  }

  ret_val = signal_protocol_pre_key_store_key(ctx_p->axolotl_store_context_p, signal_protocol_key_helper_key_list_element(key_l_p));
  if (ret_val) {
    err_msg = "failed to store new key";
    goto cleanup;
  }

  *plaintext_pp = plaintext_p;

cleanup:
  if (ret_val < 0) {
    axc_log(ctx_p, AXC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  SIGNAL_UNREF(pre_key_msg_p);
  session_cipher_free(session_cipher_p);
  session_builder_free(session_builder_p);
  signal_protocol_key_helper_key_list_free(key_l_p);

  return ret_val;
}

// Private methods are enemy of reusing.

/**
 * Logs the error message and closes the db connection.
 * If the error message is an empty string, only cleans up.
 * Both the database and statement can be NULL, then only the error message is logged.
 *
 * @param db_p Database connetion to close.
 * @param pstmt_p Prepared statement to finalize.
 * @param msg Error message to log.
 */
static void db_conn_cleanup(sqlite3 * db_p, sqlite3_stmt * pstmt_p, const char * err_msg, const char * func_name, axc_context * ctx_p) {
  if (err_msg) {
    axc_log(ctx_p, AXC_LOG_ERROR, "%s: %s (sqlite err: %s)\n", func_name, err_msg, sqlite3_errmsg(db_p));
  }

  (void) sqlite3_finalize(pstmt_p);
  (void) sqlite3_close(db_p);
}

/**
 * Convenience function for opening a db "connection" and at the same time preparing a statement.
 *
 * @param db_pp Will be set to the db connection pointer.
 * @param pstmt_pp Will be set to the pointer of the prepared statement
 * @param stmt The SQL statement.
 * @param user_data_p Optional. The user_data as received from the axolotl interface, will be used to set the database name.
 * @return 0 on success, negative on failure
 */
static int db_conn_open(sqlite3 ** db_pp, sqlite3_stmt ** pstmt_pp, const char stmt[], void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;

  int ret_val = 0;
  char * err_msg = (void *) 0;

  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;

  if (!stmt) {
    ret_val = -1;
    err_msg = "stmt is null";
    goto cleanup;
  }


  ret_val = sqlite3_open(axc_context_get_db_fn(axc_ctx_p), &db_p);
  if (ret_val) {
    err_msg = "Failed to open db_p";
    goto cleanup;
  }


  if (sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0)) {
    ret_val = -2;
    err_msg = "Failed to prepare statement";
    goto cleanup;
  }

  *db_pp = db_p;
  *pstmt_pp = pstmt_p;

cleanup:
  if (ret_val) {
    db_conn_cleanup(db_p, (void *) 0, err_msg, __func__, axc_ctx_p);
  }

  return ret_val;
}

#define IDENTITY_KEY_STORE_TABLE_NAME "identity_key_store"
#define IDENTITY_KEY_STORE_NAME_NAME "name"
#define IDENTITY_KEY_STORE_DEVICE_ID_NAME "device_id"

int axc_query_identity_dake(const signal_protocol_address * addr_p,
			    uint8_t * key_data, size_t key_len,
			    void * user_data)
{
  static const char stmt[] =
    "SELECT * FROM " IDENTITY_KEY_STORE_TABLE_NAME
    " WHERE " IDENTITY_KEY_STORE_NAME_NAME
    " IS ?1 AND " IDENTITY_KEY_STORE_DEVICE_ID_NAME " IS ?2;";
  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  int step_result = 0;
  size_t record_len = 0;

  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, addr_p->name, -1, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  if (sqlite3_bind_int(pstmt_p, 2, addr_p->device_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -25;
  }

  step_result = sqlite3_step(pstmt_p);
  if (step_result == SQLITE_DONE) {
    // no entry
    db_conn_cleanup(db_p, pstmt_p, "No match entry found", __func__, axc_ctx_p);
    return 0;
  } else if (step_result == SQLITE_ROW) {
    record_len = sqlite3_column_int(pstmt_p, 2);
    if (record_len != key_len) {
      db_conn_cleanup(db_p, pstmt_p, "Key length does not match", __func__, axc_ctx_p);
      return 0;
    }

    memcpy(key_data, sqlite3_column_blob(pstmt_p, 1), key_len);
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return 1;
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed executing SQL statement", __func__, axc_ctx_p);
    return -32;
  }
}

int axc_db_get_devid_list_by_name(signal_int_list ** l_devid, const char * name, size_t name_len, void * user_data) {
  static const char stmt[] = "SELECT * FROM " IDENTITY_KEY_STORE_TABLE_NAME
    " WHERE " IDENTITY_KEY_STORE_NAME_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  signal_int_list * devid_list_p = (void *) 0;
  char * err_msg = (void *) 0;
  int ret_val = 0;

  if (sqlite3_bind_text(pstmt_p, 1, name, -1, SQLITE_TRANSIENT)) {
    err_msg = "Failed to bind name when trying to find devids";
    ret_val = -21;
    goto cleanup;
  }

  devid_list_p = signal_int_list_alloc();

  int step_result = sqlite3_step(pstmt_p);
  while (step_result == SQLITE_ROW) {
    signal_int_list_push_back(devid_list_p, sqlite3_column_int(pstmt_p, 4));

    step_result = sqlite3_step(pstmt_p);
  }

  if (step_result != SQLITE_DONE) {
    err_msg = "Error while retrieving result rows";
    ret_val = -3;
    goto cleanup;
  }

  (void) name_len;

  *l_devid = devid_list_p;
  ret_val = signal_int_list_size(*l_devid);

cleanup:
  if (ret_val < 0) {
    if (devid_list_p) {
      signal_int_list_free(devid_list_p);
    }
  }
  db_conn_cleanup(db_p, pstmt_p, err_msg, __func__, axc_ctx_p);
  return ret_val;
}

int axc_db_identity_is_trusted_wrapper(const signal_protocol_address * addr_p,
				       uint8_t * key_data,
				       size_t key_len,
				       void * user_data)
{
  switch(key_len) {
  case COMPATIBILITY:
    if (!key_data && !addr_p)
      return 0;
    else
      return SG_ERR_INVAL;
  case KEYDATA:
    return axc_query_identity_dake(addr_p, key_data, SIG_PUBKEY_LEN, user_data);
  case ID_LIST:
    return axc_db_get_devid_list_by_name((signal_int_list**)key_data,
					 addr_p->name, addr_p->name_len,
					 user_data);
  default:
    return axc_db_identity_is_trusted(addr_p, key_data, key_len, user_data);
  }
}

int axc_get_devid_list_by_name(signal_protocol_store_context *context,
			       signal_int_list **l_devid,
			       const char *name, size_t name_len)
{
  int ret = 0;
  assert(context);
  assert(context->identity_key_store.is_trusted_identity);

  ret = context->identity_key_store.is_trusted_identity(NULL, NULL, COMPATIBILITY,
							context->identity_key_store.user_data);
  if (ret < 0)
    return ret;

  signal_protocol_address addr = { name, name_len, 0 };
  return context->identity_key_store.is_trusted_identity(&addr, (uint8_t*)l_devid, ID_LIST,
							context->identity_key_store.user_data);
}

extern int db_exec_single_change(sqlite3 * db_p,
				 sqlite3_stmt * pstmt_p,
				 axc_context * axc_ctx_p);

int axc_db_identity_save_or_trust(const signal_protocol_address * addr_p,
				  uint8_t * key_data,
				  size_t key_len,
				  void * user_data)
{
  // 1 - name ("public" or "private" for own keys, name for contacts)
  // 2 - key blob
  // 3 - length of the key
  // 4 - trusted (1 for true, 0 for false)
  // 5 - device_id
  static const char save_stmt[] = "INSERT OR REPLACE INTO " IDENTITY_KEY_STORE_TABLE_NAME " VALUES (?1, ?2, ?3, ?4, ?5);";
  static const char del_stmt[] = "DELETE FROM " IDENTITY_KEY_STORE_TABLE_NAME " WHERE " IDENTITY_KEY_STORE_NAME_NAME " IS ?1 AND " IDENTITY_KEY_STORE_DEVICE_ID_NAME " IS ?2;";
  const char * stmt = (void *) 0;
  bool key_is_trusted = false;

  if (key_data) {
    stmt = save_stmt;
  } else {
    stmt = del_stmt;
  }

  if (key_len == TRUST_LEVEL) {
    key_len = SIG_PUBKEY_LEN;
    key_is_trusted = true;
  }

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, addr_p->name, -1, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  if (key_data) {
    if (sqlite3_bind_blob(pstmt_p, 2, key_data, key_len, SQLITE_TRANSIENT)) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -22;
    }
    if(sqlite3_bind_int(pstmt_p, 3, key_len)) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -23;
    }
    if(sqlite3_bind_int(pstmt_p, 4, key_is_trusted)) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -24;
    }
    if(sqlite3_bind_int(pstmt_p, 5, addr_p->device_id)) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -25;
    }
  } else if (sqlite3_bind_int(pstmt_p, 2, addr_p->device_id)) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -25;
  }

  if (db_exec_single_change(db_p, pstmt_p, axc_ctx_p)) return -3;

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

int axc_db_set_identity_trusted_dake(const signal_protocol_address * addr_p,
				     bool trusted,
				     void* user_data)
{
  uint8_t idkey_data[SIG_PUBKEY_LEN];
  int ret = axc_query_identity_dake(addr_p, idkey_data, sizeof(idkey_data), user_data);
  if (ret < 0)
    return ret;
  return axc_db_identity_save_or_trust(addr_p, idkey_data,
				       trusted?TRUST_LEVEL:SIG_PUBKEY_LEN,
				       user_data);
}

int axc_get_devid_from_sig_dake(signal_protocol_store_context *sctx,
				const char* name, size_t name_len, ec_public_key* r_spk,
				const uint8_t* sig, size_t sig_len, int32_t* r_devid_p,
				ec_public_key** r_idkey_pp)
{
  int ret = 0;
  signal_int_list* l_devid = NULL;

  ret = axc_get_devid_list_by_name(sctx, &l_devid, name, name_len);

  if (ret < 0)
    goto cleanup;

  {
    int id_num = ret;
    int i = 0;
    for(; i < id_num; i++) {
      ec_public_key* r_idkey = NULL;
      int32_t devid = signal_int_list_at(l_devid, i);
      signal_protocol_address addr = { name, name_len, devid };
      ret = sig_ext_query_idkey(sctx, &addr, &r_idkey);
      if (ret < 0) break;
      ret = Odake_verify_signed_pre_key(r_idkey, r_spk, sig, sig_len);
      if (ret > 0) {
        *r_devid_p = devid;
	if (r_idkey_pp) {
	  *r_idkey_pp = r_idkey;
         SIGNAL_REF(*r_idkey_pp);
	}
      }
      SIGNAL_UNREF(r_idkey);
      if (ret == 0) continue;
      else break;
    }
  }
 cleanup:
  signal_int_list_free(l_devid);
  return ret;
}

int axc_session_from_bundle_dake_noidkey(uint32_t pre_key_id,
					 axc_buf * pre_key_public_serialized_p,
					 uint32_t signed_pre_key_id,
					 axc_buf * signed_pre_key_public_serialized_p,
					 axc_buf * signed_pre_key_signature_p,
					 const axc_address * remote_address_p,
					 axc_context * ctx_p)
{
  const char * err_msg = "";
  axc_address rr_addr = *remote_address_p;
  ec_public_key * signed_pre_key_public_p = (void *) 0;
  ec_public_key * identity_key_public_p = (void *) 0;
  axc_buf * identity_key_public_serialized_p = (void *) 0;
  int ret = curve_decode_point(&signed_pre_key_public_p,
                               axc_buf_get_data(signed_pre_key_public_serialized_p),
                               axc_buf_get_len(signed_pre_key_public_serialized_p),
                               ctx_p->axolotl_global_context_p);
  if (ret) {
    err_msg = "failed to deserialize signed public pre key";
    goto cleanup;
  }
  ret = axc_get_devid_from_sig_dake(ctx_p->axolotl_store_context_p, remote_address_p->name,
				    remote_address_p->name_len, signed_pre_key_public_p,
				    axc_buf_get_data(signed_pre_key_signature_p),
				    axc_buf_get_len(signed_pre_key_signature_p),
				    &rr_addr.device_id, &identity_key_public_p);
  if (ret < 0) {
    err_msg = "failed to query remote identity key";
    goto cleanup;
  } else if (ret == 0) {
    err_msg = "no match remote identity key found";
    goto cleanup;
  }

  ret = axc_context_dake_set_real_regid((axc_context_dake*)ctx_p, remote_address_p,
					rr_addr.device_id);

  if (ret < 0) {
    err_msg = "failed to set real device id";
    goto cleanup;
  }

  ret = ec_public_key_serialize(&identity_key_public_serialized_p,
				identity_key_public_p);
  if (ret) {
    err_msg = "failed to serialize remote identity key";
    goto cleanup;
  }

  ret = axc_session_from_bundle_dake(pre_key_id, pre_key_public_serialized_p,
				     signed_pre_key_id, signed_pre_key_public_serialized_p,
				     signed_pre_key_signature_p, identity_key_public_serialized_p,
				     &rr_addr, ctx_p);
 cleanup:
  SIGNAL_UNREF(signed_pre_key_public_p);
  SIGNAL_UNREF(identity_key_public_p);
  axc_buf_free(identity_key_public_serialized_p);
  if (ret < 0) {
    axc_log(ctx_p, AXC_LOG_ERROR, "%s: %s", __func__, err_msg);
  }

  return ret;
}


int axc_Idake_start_for_addr(axc_context_dake* dctx_p,
			     const signal_protocol_address* addr,
			     const signal_buffer** kdmsg)
{
  return Idake_start_for_addr(dctx_p->base.axolotl_store_context_p,
			      addr, kdmsg, &dctx_p->l_authinfo);
}

int axc_Idake_handle_msg(axc_context_dake* dctx_p,
			 const Signaldakez__IdakeMessage* msg,
			 const signal_protocol_address* addr,
			 const signal_buffer** lastauthmsg)
{
  return Idake_handle_msg(dctx_p->base.axolotl_store_context_p,
			  msg, addr, lastauthmsg,
			  &dctx_p->l_authinfo);
}

const pbdumper* axc_context_dake_get_dumper(const axc_context_dake* dctx_p)
{
  return dctx_p->dumper;
}
void axc_context_dake_set_dumper(axc_context_dake* dctx_p, const pbdumper* dumper)
{
  dctx_p->dumper = dumper;
}

int axc_context_dake_get_real_regid(axc_context_dake* dctx_p,
				    const signal_protocol_address* r_addr,
				    uint32_t* r_real_regid_p)
{
  auth_node* anode = auth_node_find_by_addr(&dctx_p->l_authinfo, r_addr);
  if (!anode) {
    return SG_ERR_NO_SESSION;
  }

  *r_real_regid_p = auth_node_get_auth(anode)->regids[1];
  return 0;
}

int axc_context_dake_set_real_regid(axc_context_dake* dctx_p,
				    const signal_protocol_address* r_addr,
				    uint32_t r_real_regid)
{
  int ret = 0;
  IdakeAuthInfo* auth = NULL;
  auth_node* anode = auth_node_find_by_addr(&dctx_p->l_authinfo, r_addr);
  if (!anode) {
    ret = IdakeAuthInfo_create(&auth);
    if (ret < 0)
      goto cleanup;

    anode = auth_node_create_on_list(&dctx_p->l_authinfo, auth, r_addr);
    SIGNAL_UNREF(auth);
    if (!anode) {
      ret = SG_ERR_NOMEM;
      goto cleanup;
    }
  }
  auth = auth_node_get_auth(anode);
  auth->regids[1] = r_real_regid;
 cleanup:
  return ret;
}

int axc_dake_session_exists_initiated(const axc_address * addr_p, axc_context_dake * dctx_p)
{
  axc_address real_addr = *addr_p;
  int ret = axc_context_dake_get_real_regid(dctx_p, addr_p, (uint32_t*)&real_addr.device_id);
  if (ret < 0) return ret;
  return axc_session_exists_initiated(&real_addr, &dctx_p->base);
}

int axc_dake_terminate_session(const axc_address * addr_p, axc_context_dake * dctx_p)
{
  axc_address real_addr = *addr_p;
  int ret = axc_context_dake_get_real_regid(dctx_p, addr_p, (uint32_t*)&real_addr.device_id);
  if (ret < 0) return ret;
  auth_node* node = auth_node_find_by_addr(&dctx_p->l_authinfo, addr_p);
  if (node) {
    cl_unlink_node(&node->cl);
    auth_node_free(node);
  }
  return signal_protocol_session_delete_session(dctx_p->base.axolotl_store_context_p,
						&real_addr);
}

const signal_protocol_identity_key_store axc_dakes_identity_key_store_tmpl = {
    .get_identity_key_pair = axc_db_identity_get_key_pair,
    .get_local_registration_id = axc_db_identity_get_local_registration_id,
    .save_identity = axc_db_identity_save_or_trust,
    .is_trusted_identity = axc_db_identity_is_trusted_wrapper,
    .destroy_func = axc_db_identity_destroy_ctx,
    .user_data = (void *) 0
};
