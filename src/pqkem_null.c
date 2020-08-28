#include "pqkem.h"

const pqkem_impl pqkem_null;

static DF_pqkem_ctx_init(null_ctx_init)
{
  pqkem_ctx_base* ctx = (pqkem_ctx_base*)malloc(sizeof(*ctx));
  if (ctx) {
    ctx->impl = pqkem_null;
    ctx->rng = rng;
  }
  return ctx;
}

static DF_pqkem_genI(null_genI)
{
  return true;
}

static DF_pqkem_genR(null_genR)
{
  return true;
}

static DF_pqkem_keyI(null_keyI)
{
  return true;
}

static DF_pqkem_ctx_free(null_ctx_free)
{
  free(ctx);
}

const pqkem_impl pqkem_null
= {
   .name = "null",
   .sz_pqI = 0,
   .sz_sqI = 0,
   .sz_qR = 0,
   .sz_key = 0,
   .sz_scratch = 0,
   .off_p8 = 0,
   .off_p16 = 0,
   .off_p24 = 0,
   .ctx_init = null_ctx_init,
   .genI = null_genI,
   .genR = null_genR,
   .keyI = null_keyI,
   .ctx_free = null_ctx_free,
};
