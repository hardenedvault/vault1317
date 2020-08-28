#ifndef _KEYMAP_H_
#define _KEYMAP_H_

#include "crypto_additions.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

typedef unsigned char keybytes[32];

/* Convert a Curve25519 pubkey to a positive point on ed25519 in ge_p3 form */
int xed25519_conv_pubkey(ge_p3 *ed_pubkey_point, const keybytes *mont_pubkey);

int ge_p3_isnegative(const ge_p3 *p);

void ge_p3_copy(ge_p3 *r, const ge_p3 *p);

/*
Replace (r,p) with (p,p) if c == 1;
replace (r,p) with (r,p) if c == 0.

Preconditions: c in {0,1}.
*/
void ge_p3_cmov(ge_p3* r, const ge_p3 *p, unsigned int c);

/*
  if(b == 1) r = -p; else r = p;
  Preconditions: b in {0,1}.
*/
void ge_p3_cneg(ge_p3 *r, const ge_p3 *p, unsigned char b);

/* Convert a Curve25519 privkey to an ed25519 privkey
   conforming xeddsa's request, whether the converted
   privkey is negated is returned. The corresponding
   ed25519 pubkey could be output in the same time if
   ed_pubkey_point is not NULL*/
unsigned char xed25519_conv_privkey(keybytes *ed_privkey,
				    ge_p3 *ed_pubkey_point,
				    const keybytes *mont_privkey);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
