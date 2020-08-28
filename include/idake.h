#ifndef _IDAKE_H_
#define _IDAKE_H_

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "rsig.h"

#include "curve.h"
#include "session_state.h"
#include "ratchet.h"

#include "DakesProtocol.pb-c.h"
#include "signal_protocol_types.h"
#include "signal_protocol_internal.h"
#include "key_helper.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

typedef enum{
    IDAKE_AUTHSTATE_NONE,
    IDAKE_AUTHSTATE_AWAITING_PREKEY,
    IDAKE_AUTHSTATE_AWAITING_IDKEY,
    IDAKE_AUTHSTATE_AWAITING_ERSIDK,
    IDAKE_AUTHSTATE_AWAITING_ERSIG,
} IdakeAuthState;

typedef struct symkey {
  keybytes a;
} symkey;

typedef struct aesiv {
  uint8_t a[16];
} aesiv;

typedef struct symskey {
  symkey key;
  aesiv iv;
} symskey;

typedef struct IdakeAuthInfo {
  signal_type_base base;//it may have to be a signal reference-counting type.

  IdakeAuthState authstate;

  ec_key_pair* our_ek_pair;//E[a]

  signal_buffer* hash_their_ek;//D[a]

  ec_public_key* their_ek_pub;//g^E[b]

  ec_key_pair* our_ik_pair;//I[a]
  ec_public_key* their_ik_pub;//g^I[b]

  symkey sharedsec;//S

  symskey derivedkeys[3];//k

  symkey assoctag;//T

  int initiated;
  int isalice;
  uint32_t regids[2]; //[0] for our; [1] for their

  signal_buffer* lastauthmsg;
  time_t commit_sent_time;

} IdakeAuthInfo;

#define DF_auth_succeeded(f) int (f)(IdakeAuthInfo* auth, void* asdata)
typedef DF_auth_succeeded(auth_succeeded_ft);

/*
 * Get length of a static-allocated string constant
 * sstr must be an array of char, uint8_t, etc.
 */
#define STRLEN_S(sstr) (sizeof(sstr) - 1)

static const char kinf_ss[] = "DakeSSkey";//C[0]
static const char kinf_tag[] = "DakeTagKey";//C[3]
static const char kinf_rsig_a[] = "DakeRsigKeyA";//C[4]
static const char kinf_rsig_b[] = "DakeRsigKeyB";//C[5]
static const char kinf_iht[] = "DakeIht";//implHashTag
static const char kinf_odake_ek[] = "OdakeEk";//C[6]
static const char kinf_odake_mk[] = "OdakeMk";//C[7]

static const keybytes empty_salt;

void* signal_context_get_user_data(const signal_context* gctx);

void IdakeAuthClear(IdakeAuthInfo* auth);

//for signal reference-counting API
void IdakeAuthInfo_destroy(signal_type_base* sig_rc_obj);
int IdakeAuthInfo_create(IdakeAuthInfo** newauth);

int IdakeAuthStart(IdakeAuthInfo* auth, signal_context *gctx, ec_key_pair* our_ik_pair);

int Idake_handle_kdgstmsg(IdakeAuthInfo* auth, signal_context *gctx,
			  const Signaldakez__IdakeMessage* kdgstmsg,
			  ec_key_pair* our_ik_pair);

int Idake_handle_prekeymsg(IdakeAuthInfo* auth, signal_context *gctx,
			   const Signaldakez__IdakeMessage* prekeymsg,
			   uint32_t our_regid, int *havemsgp);

int Idake_handle_idkeymsg(IdakeAuthInfo* auth, signal_context *gctx,
			  uint32_t our_regid,
			  const Signaldakez__IdakeMessage* idkeymsg,
			  int *havemsgp);

int Idake_handle_ersidkmsg(IdakeAuthInfo* auth, signal_context *gctx,
			   const Signaldakez__IdakeMessage* ersidkmsg,
			   int *havemsgp, auth_succeeded_ft* auth_succeeded,
			   void* asdata);

int Idake_handle_ersigmsg(IdakeAuthInfo* auth, signal_context *gctx,
			  const Signaldakez__IdakeMessage* ersigmsg,
			  int *havemsgp, auth_succeeded_ft* auth_succeeded,
			  void* asdata);

int Idake_pack_authmsg(signal_buffer** ser_authmsg,
		       const Signaldakez__IdakeMessage* authmsg);

/*
 * Theoretically, a double ratchet session could just be initialized
 * with using one shared secret, a local DHE pair, and a remote DHE
 * public prekey, and providing these material is the responsibility
 * of the AKE protocol (including X3DH, but can also be achieved with
 * OTRv3-like protocols).
 * As an exception, their_rk_pub could be omitted when processing pre-key
 * messages, since it is carried by the appended signal-message.
 */
int session_state_init_session(signal_context* gctx,
			       session_state* state,
			       const uint8_t* shared_secret,
			       size_t ss_len,
			       ec_public_key* their_rk_pub,
			       ec_key_pair* our_rk_pair);

int Idake_init_session(IdakeAuthInfo* auth,
		       session_state* state,
		       signal_context* gctx);

//T=KDF(C[3]||g^I[a]||g^I[b]);
int dake_compute_assoctag(signal_context *gctx,
			  const ec_public_key* a_ik_pub,
			  const ec_public_key* b_ik_pub,
			  symkey* assoctag);


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
			     const uint32_t* b_ek_pub_idx);

//M=Mac(k[1], (C[5]||i||ID[a]||ID[b]||g^E[a,0]||g^E[b,i]||T))
int dake_mac_sign_payload(signal_context* gctx,
			  signal_buffer** mac,
			  const uint8_t* mackey, size_t mkLen,
			  const uint8_t* message, size_t msgLen,
			  const uint8_t* associatedData, size_t adLen,
			  const uint8_t* implHashTag, size_t ihtLen);

int dake_rsign(signal_context* gctx, rsig* proof,
	       const ec_public_key* ika, const ec_public_key* ikb,
	       const ec_public_key* ek, const ec_private_key* sk,
	       const unsigned char* message, size_t msgLen,
	       const unsigned char* associatedData, size_t adLen,
	       const unsigned char* implHashTag, size_t ihtLen);

//negative return indicates error, otherwise return boolean.
int dake_rvrf(signal_context* gctx, const rsig* proof,
	      const ec_public_key* ika,
	      const ec_public_key* ikb,
	      const ec_public_key* ek,
	      const unsigned char* message, size_t msgLen,
	      const unsigned char* associatedData, size_t adLen,
	      const unsigned char* implHashTag, size_t ihtLen);
#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
