#include "sidh_helper.h"

#define NUM_BYTES 20

void sidh_get_random_mpz_extrng(mpz_t x, rng_ft* extrng, void* user_data)
{
  uint8_t a[NUM_BYTES] = {0};

  if (0 > extrng(a, sizeof(a), user_data)) {
    return;
  }

  mpz_import(x, NUM_BYTES, 1, sizeof (char), 0, 0, a);
}

void sidh_private_key_generate_extseed(private_key_t private_key,
				       const public_params_t params,
				       const mpz_t seed) {
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);
    gmp_randseed(randstate, seed);

    while (1) {
        mpz_urandomm(private_key->m, randstate, params->le);
        mpz_urandomm(private_key->n, randstate, params->le);

        if (!mpz_divisible_ui_p(private_key->m, params->l))
            break;

        if (!mpz_divisible_ui_p(private_key->n, params->l)) {
            mpz_swap(private_key->m, private_key->n);
            break;
        }
    }

    gmp_randclear(randstate);
}
