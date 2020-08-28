#ifndef _RSIG_H_
#define _RSIG_H_

#include "crypto_additions.h"

#include "hasher.h"
#include "keymap.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

typedef struct rsig {
  unsigned char bytes[6 * sizeof(keybytes)];
} rsig;

int rsign_ed25519(hasher* h,
		  const ge_p3 pk[3], const keybytes* sk,
		  const unsigned char* message, size_t msgLen,
		  const unsigned char* associatedData, size_t adLen,
		  const unsigned char* implHashTag, size_t ihtLen,
		  const unsigned char* random, size_t rdlen,
		  rsig* proof);

int rvrf_ed25519(hasher* h,
		 const ge_p3 pk[3], const rsig* proof,
		 const unsigned char* message, size_t msgLen,
		 const unsigned char* associatedData, size_t adLen,
		 const unsigned char* implHashTag, size_t ihtLen);
int rsign_xed25519(hasher* h,
		   const keybytes* pk1, const keybytes* pk2,
		   const keybytes* pk3, const keybytes* sk,
		   const unsigned char* message, size_t msgLen,
		   const unsigned char* associatedData, size_t adLen,
		   const unsigned char* implHashTag, size_t ihtLen,
		   const unsigned char* random, size_t rdlen,
		   rsig* proof);

int rvrf_xed25519(hasher* h,
		  const keybytes* pk1, const keybytes* pk2,
		  const keybytes* pk3, const rsig* proof,
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
