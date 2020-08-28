#ifndef _SC_ARITH_H_
#define _SC_ARITH_H_

#include "keymap.h"
#include "sc.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

static const keybytes sc_zero;
static const keybytes sc_one = {1};
static const keybytes sc_lminus1 = {
  0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

// s = (a*b+c) mod l
static inline void sc_kb_muladd(keybytes* s,
				const keybytes* a,
				const keybytes* b,
				const keybytes* c)
{
  sc_muladd(*s, *a, *b, *c);
}

// c = (a+b) mod l
static inline void sc_kb_add(keybytes* c, const keybytes* a, const keybytes* b)
{
  sc_kb_muladd(c, &sc_one, a, b);
}

// c = (a-b) mod l
static inline void sc_kb_sub(keybytes* c, const keybytes* a, const keybytes* b)
{
  sc_kb_muladd(c, &sc_lminus1, b, a);
}

// c = (a*b) mod l
static inline void sc_kb_mul(keybytes* c, const keybytes* a, const keybytes* b)
{
  sc_kb_muladd(c, a, b, &sc_zero);
}

// b = (-a) mod l
static inline void sc_kb_neg(keybytes* b, const keybytes* a)
{
  sc_kb_muladd(b, &sc_lminus1, a, &sc_zero);
}

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
