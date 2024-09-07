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

#include "signal_query_id.h"

struct signal_protocol_store_context {
    signal_context *global_context;
    signal_protocol_session_store session_store;
    signal_protocol_pre_key_store pre_key_store;
    signal_protocol_signed_pre_key_store signed_pre_key_store;
    signal_protocol_identity_key_store identity_key_store;
    signal_protocol_sender_key_store sender_key_store;
};

int sig_ext_query_idkey(signal_protocol_store_context* sctx,
			const signal_protocol_address* addr,
			ec_public_key** idkey)
{
  int result = 0;
  uint8_t idkeybuf[SIG_PUBKEY_LEN];
  
  assert(sctx);
  assert(sctx->identity_key_store.save_identity);

  signal_query_idkey_ft* query_idkey_imp
    = sctx->identity_key_store.is_trusted_identity;

  //Query whether the idkey store supports query existing idkeys.
  result = query_idkey_imp(NULL,
			   NULL,
			   COMPATIBILITY,
			   sctx->identity_key_store.user_data);
  if (result < 0) { // maybe SG_ERR_INVAL
    signal_log(sctx->global_context, SG_LOG_INFO,
	       "Store context does not support query idkeys.");
    goto complete;
  }

  //The idkey store seems to support query existing idkeys, so we proceed.
  result = query_idkey_imp(addr, idkeybuf, KEYDATA,
			   sctx->identity_key_store.user_data);
  
  if (result < 0) { // maybe SG_ERR_INVAL
    signal_log(sctx->global_context, SG_LOG_ERROR,
	       "Internal error within Store context.");
    goto complete;
  } else if (result == 0) { //no idkey found
    signal_log(sctx->global_context, SG_LOG_INFO,
	       "IdKey for account %s is not found.", addr->name);
    goto complete;
  }

  //idkey found, deserialize it.

  
  result = curve_decode_point(idkey, idkeybuf, sizeof(idkeybuf), sctx->global_context);
 complete:
  return result;
}
