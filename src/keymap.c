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

#include "keymap.h"
#include "zeroize.h"
#include "sc_arith.h"
#include <string.h>

/* Convert a Curve25519 pubkey to a positive point on ed25519 in ge_p3 form */
int xed25519_conv_pubkey(ge_p3* ed_pubkey_point, const keybytes* mont_pubkey)
{
  fe u;
  if (!fe_isreduced(*mont_pubkey))
      return -1;
  fe_frombytes(u, *mont_pubkey);
  ge_montx_to_p3(ed_pubkey_point, u, 0);
  return 0;
}

int ge_p3_isnegative(const ge_p3* p)
{
  keybytes kp;
  ge_p3_tobytes(kp, p);
  return (kp[31] & 0x80) >> 7;
}

void ge_p3_copy(ge_p3* r, const ge_p3* p)
{
  fe_copy(r->X, p->X);
  fe_copy(r->Y, p->Y);
  fe_copy(r->Z, p->Z);
  fe_copy(r->T, p->T);
}

/*
Replace (r,p) with (p,p) if c == 1;
replace (r,p) with (r,p) if c == 0.

Preconditions: c in {0,1}.
*/
void ge_p3_cmov(ge_p3* r, const ge_p3* p, unsigned int c)
{
  fe_cmov(r->X, p->X, c);
  fe_cmov(r->Y, p->Y, c);
  fe_cmov(r->Z, p->Z, c);
  fe_cmov(r->T, p->T, c);
}

/*
  if(b == 1) r = -p; else r = p;
  Preconditions: b in {0,1}.
*/
void ge_p3_cneg(ge_p3* r, const ge_p3* p, unsigned char b)
{
  ge_neg(r, p);
  fe_cmov(r->X, p->X, !(b));
  fe_cmov(r->T, p->T, !(b));
}

/* Convert a Curve25519 privkey to an ed25519 privkey
   conforming xeddsa's request, whether the converted
   privkey is negated is returned. The corresponding
   ed25519 pubkey could be output in the same time if
   ed_pubkey_point is not NULL*/
unsigned char xed25519_conv_privkey(keybytes *ed_privkey,
				    ge_p3 *ed_pubkey_point,
				    const keybytes *mont_privkey)
{
  ge_p3 img;
  keybytes a, aneg;
  unsigned char sign_bit = 0;
  memcpy(&a, mont_privkey, 32);
  sc_kb_neg(&aneg, &a);
  
  ge_scalarmult_base(&img, *mont_privkey);
  sign_bit = ge_p3_isnegative(&img);
  
  sc_cmov(a, aneg, sign_bit);//if(sign_bit) a = aneg
  memcpy(ed_privkey, &a, sizeof(keybytes));

  if(ed_pubkey_point) {
    ge_p3_cneg(ed_pubkey_point, &img, sign_bit);
  }
  
  zeroize(a, sizeof(keybytes));
  zeroize(aneg, sizeof(keybytes));
  zeroize_stack();
  return sign_bit;
}
