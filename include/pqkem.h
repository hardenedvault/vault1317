#ifndef _PQKEM_H_
#define _PQKEM_H_

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct pqkem_ctx_base_st pqkem_ctx_base;
typedef struct pqkem_impl_st pqkem_impl;

#define DF_RNG(func) int (func)(uint8_t* data, size_t len, void* user_data)
typedef DF_RNG(rng_ft);

#define DF_pqkem_ctx_init(f) pqkem_ctx_base* (f)(rng_ft* rng)
typedef DF_pqkem_ctx_init(pqkem_ctx_init_ft);

#define DF_pqkem_genI(f) bool (f)(pqkem_ctx_base* ctx,			\
				  uint8_t* pqI,				\
				  uint8_t* sqI,				\
				  uint8_t* scratch)
typedef DF_pqkem_genI(pqkem_genI_ft);

#define DF_pqkem_genR(f) bool (f)(pqkem_ctx_base* ctx,			\
				  const uint8_t* pqI,			\
				  uint8_t* qR,				\
				  uint8_t* key, 			\
				  uint8_t* scratch)
typedef DF_pqkem_genR(pqkem_genR_ft);

#define DF_pqkem_keyI(f) bool (f)(pqkem_ctx_base* ctx,			\
				  const uint8_t* sqI,			\
				  const uint8_t* qR,			\
				  uint8_t* key, 			\
				  uint8_t* scratch)
typedef DF_pqkem_keyI(pqkem_keyI_ft);

#define DF_pqkem_ctx_free(f) void (f)(pqkem_ctx_base* ctx)
typedef DF_pqkem_ctx_free(pqkem_ctx_free_ft);

struct pqkem_impl_st {
  const char* name;
  
  size_t sz_pqI;
  size_t sz_sqI;
  size_t sz_qR;
  size_t sz_key;
  size_t sz_scratch;
  size_t off_p8;  //Alignment offset for pointers where (p % 32) == 8
  size_t off_p16; //Alignment offset for pointers where (p % 32) == 16
  size_t off_p24; //Alignment offset for pointers where (p % 32) == 24

  pqkem_ctx_init_ft* ctx_init;
  pqkem_genI_ft* genI;
  pqkem_genR_ft* genR;
  pqkem_keyI_ft* keyI;
  pqkem_ctx_free_ft* ctx_free;
  
};

struct pqkem_ctx_base_st {
  const pqkem_impl* impl;
  rng_ft* rng;
};

static inline pqkem_ctx_base* pqkem_ctx_init(const pqkem_impl* impl, rng_ft* rng)
{
  return (impl)?(impl->init(rng)):NULL;
}

static inline DF_pqkem_genI(pqkem_genI)
{
  return (impl)?(impl->genI(ctx, pqI, sqI, scratch)):false;
}

static inline DF_pqkem_genR(pqkem_genR)
{
  return (impl)?(impl->genR(ctx, pqI, qR, key, scratch)):false;
}

static inline DF_pqkem_genR(pqkem_genR)
{
  return (impl)?(impl->keyI(ctx, sqI, qR, key, scratch)):false;
}

static inline DF_pqkem_ctx_free(pqkem_ctx_free)
{
  impl->free(ctx);
}

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
