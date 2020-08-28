#include "pqkem.h"

const pqkem_impl pqkem_sidh;

static DF_pqkem_ctx_init(sidh_ctx_init)
{
  pqkem_ctx_base* ctx = (pqkem_ctx_base*)malloc(sizeof(*ctx));
  if (ctx) {
    ctx->impl = pqkem_sidh;
  }
  return ctx;
}

static DF_pqkem_genI(sidh_genI)
{
  return true;
}

static DF_pqkem_genR(sidh_genR)
{
  return true;
}

static DF_pqkem_keyI(sidh_keyI)
{
  return true;
}

static DF_pqkem_ctx_free(sidh_ctx_free)
{
  free(ctx);
}

const pqkem_impl pqkem_sidh
= {
   .name = "sidh",
   .sz_pqI = 0,
   .sz_sqI = 0,
   .sz_qR = 0,
   .sz_key = 0,
   .sz_scratch = 0,
   .off_p8 = 0,
   .off_p16 = 0,
   .off_p24 = 0,
   .ctx_init = sidh_ctx_init,
   .genI = sidh_genI,
   .genR = sidh_genR,
   .keyI = sidh_keyI,
   .ctx_free = sidh_ctx_free,
};
