#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_verify_32.h"
#include "zeroize.h"

#include "sc_arith.h"
#include "rsig.h"

typedef struct cr_bytes {
    keybytes c;
    keybytes r;
} cr_bytes;

typedef union rsig_internal {
  struct {
    cr_bytes bcrs[3];
  };
  unsigned char bytes[3 * sizeof(cr_bytes)];
} rsig_internal;

static void sc_kb_reduce(keybytes* b)
{
  sc_kb_mul(b, &sc_one, b);
}

static void bcr_cmov(cr_bytes* T, const cr_bytes* S, unsigned int cond)
{
  sc_cmov(T->c, S->c, cond);
  sc_cmov(T->r, S->r, cond);
}

// Check whether p1 and p2 represent the same point
static int ge_p3_isveq(const ge_p3* p1, const ge_p3* p2)
{
  keybytes kb1, kb2;
  ge_p3_tobytes(kb1, p1);
  ge_p3_tobytes(kb2, p2);
  return (crypto_verify_32(kb1, kb2) == 0);
}

static void ge_p2_to_p3(ge_p3* h, const ge_p2* p)
{
  fe invZ;
  fe XY;
  fe_copy(h->X, p->X);
  fe_copy(h->Y, p->Y);
  fe_copy(h->Z, p->Z);
  fe_invert(invZ, p->Z);
  fe_mul(XY, p->X, p->Y);
  fe_mul(h->T, XY, invZ);
}

static void rsig_ed25519_calcT(ge_p3* T, const cr_bytes* cr, const ge_p3* pk)
{
  ge_p2 T_p2;
  ge_double_scalarmult_vartime(&T_p2, cr->c, pk, cr->r);
  ge_p2_to_p3(T, &T_p2);
}

static int hasher_update_ge_p3(hasher* h, void* ctx,
			       const ge_p3* P)
{
  keybytes P_keybytes;
  ge_p3_tobytes(P_keybytes, P);
  return hasher_update(h, ctx, P_keybytes, sizeof(P_keybytes));
}


//used inside do{...}while(0)
#define RSIG_MUST(C, V)				\
  if((C) != (V)) { break; }			\

#define RSIG_MUST_NOT(C, V)			\
  if((C) == (V)) { break; }			\

static int rsig_simple_kdf(hasher* h, const keybytes* sk,
			   const unsigned char* message, size_t msgLen,
			   const unsigned char* random, size_t rdLen,
			   keybytes* nonce)
{
  void* hash_ctx = NULL;
  signal_buffer* buf = NULL;
  do {
    RSIG_MUST(hasher_ctx_init(h, &hash_ctx), 0);
    RSIG_MUST(hasher_update(h, hash_ctx, *sk, sizeof(keybytes)), 0);
    RSIG_MUST(hasher_update(h, hash_ctx, message, msgLen), 0);
    RSIG_MUST(hasher_update(h, hash_ctx, random, rdLen), 0);
    RSIG_MUST(hasher_final(h, hash_ctx, &buf), 0);
    assert(signal_buffer_len(buf) >= sizeof(keybytes));
    memcpy(*nonce, signal_buffer_data(buf), sizeof(keybytes));
    hasher_ctx_cleanup(h, hash_ctx);
    signal_buffer_bzero_free(buf);
    return 0;
  } while(0);
  if(hash_ctx){
    hasher_ctx_cleanup(h, hash_ctx);
  }
  signal_buffer_bzero_free(buf);
  return -1;
}

static int rsig_hashC(hasher* h, const ge_p3 pk[3], const ge_p3 T[3],
		      const unsigned char* message, size_t msgLen,
		      const unsigned char* associatedData, size_t adLen,
		      const unsigned char* implHashTag, size_t ihtLen,
		      keybytes* out)
{
  void* hash_ctx = NULL;
  signal_buffer* buf = NULL;
  do {
    RSIG_MUST(hasher_ctx_init(h, &hash_ctx), 0);
    RSIG_MUST(hasher_update(h, hash_ctx, implHashTag, ihtLen), 0);
    RSIG_MUST(hasher_update_ge_p3(h, hash_ctx, &pk[0]), 0);
    RSIG_MUST(hasher_update_ge_p3(h, hash_ctx, &pk[1]), 0);
    RSIG_MUST(hasher_update_ge_p3(h, hash_ctx, &pk[2]), 0);
    RSIG_MUST(hasher_update_ge_p3(h, hash_ctx, &T[0]), 0);
    RSIG_MUST(hasher_update_ge_p3(h, hash_ctx, &T[1]), 0);
    RSIG_MUST(hasher_update_ge_p3(h, hash_ctx, &T[2]), 0);
    RSIG_MUST(hasher_update(h, hash_ctx, message, msgLen), 0);
    if(adLen > 0) {
      RSIG_MUST(hasher_update(h, hash_ctx, associatedData, adLen), 0);
    }
    RSIG_MUST(hasher_final(h, hash_ctx, &buf), 0);
    assert(signal_buffer_len(buf) >= sizeof(keybytes));
    memcpy(*out, signal_buffer_data(buf), sizeof(keybytes));
    hasher_ctx_cleanup(h, hash_ctx);
    signal_buffer_bzero_free(buf);
    return 0;
  } while(0);
  if(hash_ctx){
    hasher_ctx_cleanup(h, hash_ctx);
  }
  signal_buffer_bzero_free(buf);
  return -1;
}

int rsign_ed25519(hasher* h,
		  const ge_p3 pk[3], const keybytes* sk,
		  const unsigned char* message, size_t msgLen,
		  const unsigned char* associatedData, size_t adLen,
		  const unsigned char* implHashTag, size_t ihtLen,
		  const unsigned char* random, size_t rdLen,
		  rsig* proof)
{
  int i;
  ge_p3 pk_sk;
  ge_scalarmult_base(&pk_sk, *sk);
  //check which pk corresponds to sk
  // Create selection bits
  unsigned char sel[5] = {0, 0, 0, 0, 0};
  for(i = 0; i < 3; i++) {
    sel[i] = ge_p3_isveq(&pk[i], &pk_sk);
  }
  if(sel[0] + sel[1] + sel[2] != 1){
    /* none or more than one (unlikely) pk
       corresponds to sk. */
    return -1;
  }
  sel[3] = 1 - sel[0];
  sel[4] = 1 - sel[2];

  cr_bytes bcrx, bcry, bcrz;
  keybytes tx, c;
  ge_p3 Tx, Ty, Tz, Ay, Az;
  ge_p3 T[3];

  do {
    RSIG_MUST(rsig_simple_kdf(h, sk,
			      message, msgLen,
			      random, rdLen,
			      &bcry.c), 0);

    RSIG_MUST(rsig_simple_kdf(h, &bcry.c,
			      message, msgLen,
			      random, rdLen,
			      &bcry.r), 0);

    RSIG_MUST(rsig_simple_kdf(h, &bcry.r,
			      message, msgLen,
			      random, rdLen,
			      &bcrz.c), 0);

    RSIG_MUST(rsig_simple_kdf(h, &bcrz.c,
			      message, msgLen,
			      random, rdLen,
			      &bcrz.r), 0);

    RSIG_MUST(rsig_simple_kdf(h, &bcrz.r,
			      message, msgLen,
			      random, rdLen,
			      &tx), 0);

    sc_kb_reduce(&bcry.c);
    sc_kb_reduce(&bcry.r);
    sc_kb_reduce(&bcrz.c);
    sc_kb_reduce(&bcrz.r);
    sc_kb_reduce(&tx);

    ge_scalarmult_base(&Tx, tx);

    // Conditional move into Ay, Az
    //   If sel[0]: Ay = pk[1], Az = pk[2]
    //   If sel[1]: Ay = pk[0], Az = pk[2]
    //   If sel[2]: Ay = pk[0], Az = pk[1]
    //   So Ay = (sel[0]?pk[1]:pk[0]);
    //      Az = (sel[2]?pk[1]:pk[2]).
    ge_p3_cmov(&Ay, &pk[1], sel[0]);
    ge_p3_cmov(&Ay, &pk[0], sel[3]);
    ge_p3_cmov(&Az, &pk[2], sel[4]);
    ge_p3_cmov(&Az, &pk[1], sel[2]);

    // Compute Ty, Tz
    rsig_ed25519_calcT(&Ty, &bcry, &Ay);
    rsig_ed25519_calcT(&Tz, &bcrz, &Az);

    // Conditional move into T[0], T[1], T[2]
    //   If sel[0]: T[0] = Tx, T[1] = Ty, T[2] = Tz
    //   If sel[1]: T[0] = Ty, T[1] = Tx, T[2] = Tz
    //   If sel[2]: T[0] = Ty, T[1] = Tz, T[2] = Tx
    ge_p3_cmov(&T[0], &Tx, sel[0]);
    ge_p3_cmov(&T[0], &Ty, sel[3]);
    ge_p3_cmov(&T[1], &Ty, sel[0]);
    ge_p3_cmov(&T[1], &Tx, sel[1]);
    ge_p3_cmov(&T[1], &Tz, sel[2]);
    ge_p3_cmov(&T[2], &Tz, sel[4]);
    ge_p3_cmov(&T[2], &Tx, sel[2]);

    RSIG_MUST(rsig_hashC(h, pk, T, message, msgLen,
			 associatedData, adLen,
			 implHashTag, ihtLen,
			 &c), 0);

    // bcrx.c = (c - bcry.c - bcrz.c) mod l
    // bcrx.r = (tx - sk * bcrx.c) mod l
    sc_kb_add(&bcrx.c, &bcry.c, &bcrz.c);
    sc_kb_sub(&bcrx.c, &c, &bcrx.c);
    sc_kb_mul(&bcrx.r, sk, &bcrx.c);
    sc_kb_sub(&bcrx.r, &tx, &bcrx.r);
    
    rsig_internal* prf = (rsig_internal*)proof;
    // Conditional swap into prf->bcrs[0], prf->bcrs[1], prf->bcrs[2]
    //   If sel[0]: bcrs[0] = bcrx, bcrs[1] = bcry, bcrs[2] = bcrz
    //   If sel[1]: bcrs[0] = bcry, bcrs[1] = bcrx, bcrs[2] = bcrz
    //   If sel[2]: bcrs[0] = bcry, bcrs[1] = bcrz, bcrs[2] = bcrx
    bcr_cmov(&prf->bcrs[0], &bcrx, sel[0]);
    bcr_cmov(&prf->bcrs[0], &bcry, sel[3]);
    bcr_cmov(&prf->bcrs[1], &bcry, sel[0]);
    bcr_cmov(&prf->bcrs[1], &bcrx, sel[1]);
    bcr_cmov(&prf->bcrs[1], &bcrz, sel[2]);
    bcr_cmov(&prf->bcrs[2], &bcrz, sel[4]);
    bcr_cmov(&prf->bcrs[2], &bcrx, sel[2]);

    return 0;
  }while(0);
  return -1;
}

int rvrf_ed25519(hasher* h,
		 const ge_p3 pk[3], const rsig* proof,
		 const unsigned char* message, size_t msgLen,
		 const unsigned char* associatedData, size_t adLen,
		 const unsigned char* implHashTag, size_t ihtLen)
{
  ge_p3 T[3];
  keybytes buf, c, diff;
  const rsig_internal* prf = (const rsig_internal*)proof;

  do {
    rsig_ed25519_calcT(&T[0], &prf->bcrs[0], &pk[0]);
    rsig_ed25519_calcT(&T[1], &prf->bcrs[1], &pk[1]);
    rsig_ed25519_calcT(&T[2], &prf->bcrs[2], &pk[2]);

    RSIG_MUST(rsig_hashC(h, pk, T, message, msgLen,
			 associatedData, adLen,
			 implHashTag, ihtLen,
			 &buf), 0);

    // c = (bcrs[0].c + bcrs[1].c + bcrs[2].c) mod l
    // compare whether (c == buf) mod l
    sc_kb_add(&c, &prf->bcrs[0].c, &prf->bcrs[1].c);
    sc_kb_add(&c, &c, &prf->bcrs[2].c);
    sc_kb_sub(&diff, &c, &buf);
    
    return (crypto_verify_32(diff, sc_zero) == 0);
  } while(0);
  return -1;
}

int rsign_xed25519(hasher* h,
		   const keybytes* pk1, const keybytes* pk2,
		   const keybytes* pk3, const keybytes* sk,
		   const unsigned char* message, size_t msgLen,
		   const unsigned char* associatedData, size_t adLen,
		   const unsigned char* implHashTag, size_t ihtLen,
		   const unsigned char* random, size_t rdlen,
		   rsig* proof)
{
  ge_p3 ge_p3_pk[3];
  keybytes ed_sk;
  int ret;
  do {
  RSIG_MUST(xed25519_conv_pubkey(&ge_p3_pk[0], pk1), 0);
  RSIG_MUST(xed25519_conv_pubkey(&ge_p3_pk[1], pk2), 0);
  RSIG_MUST(xed25519_conv_pubkey(&ge_p3_pk[2], pk3), 0);
  xed25519_conv_privkey(&ed_sk, NULL, sk);
  ret = rsign_ed25519(h, ge_p3_pk, &ed_sk,
		      message, msgLen,
		      associatedData, adLen,
		      implHashTag, ihtLen,
		      random, rdlen,
		      proof);
  zeroize(ed_sk, sizeof(ed_sk));
  return ret;
  } while(0);
  return -1;
}

int rvrf_xed25519(hasher* h,
		  const keybytes* pk1, const keybytes* pk2,
		  const keybytes* pk3, const rsig* proof,
		  const unsigned char* message, size_t msgLen,
		  const unsigned char* associatedData, size_t adLen,
		  const unsigned char* implHashTag, size_t ihtLen)
{
  ge_p3 ge_p3_pk[3];
  do {
  RSIG_MUST(xed25519_conv_pubkey(&ge_p3_pk[0], pk1), 0);
  RSIG_MUST(xed25519_conv_pubkey(&ge_p3_pk[1], pk2), 0);
  RSIG_MUST(xed25519_conv_pubkey(&ge_p3_pk[2], pk3), 0);
  return rvrf_ed25519(h, ge_p3_pk, proof,
		      message, msgLen,
		      associatedData, adLen,
		      implHashTag, ihtLen);
  } while(0);
  return -1;
}
