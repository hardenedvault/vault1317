#ifndef _SIDH_HELPER_H_
#define _SIDH_HELPER_H_

#include <gmp.h>
#include "pqkem.h"

void sidh_get_random_mpz_extrng(mpz_t x, rng_ft* extrng, void* user_data);

void sidh_private_key_generate_extseed(private_key_t private_key,
				       const public_params_t params,
				       const mpz_t seed);

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
