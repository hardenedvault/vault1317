#ifndef _PBDUMPER_SEXP_H_
#define _PBDUMPER_SEXP_H_

#include "pbdumper.h"
#include "sexp.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define DF_ProtobufCMessage2sexp(x)					\
  gcry_error_t (x)(gcry_sexp_t* retsexp,				\
		   const ProtobufCMessage* pbmsg)
typedef DF_ProtobufCMessage2sexp(ProtobufCMessage2sexp_ft);

#define DF_pre_key_bundle2sexp(x)			\
  gcry_error_t (x)(gcry_sexp_t* retsexp,		\
		   const session_pre_key_bundle *bundle)
typedef DF_pre_key_bundle2sexp(pre_key_bundle2sexp_ft);

extern pbdumper pbdumper_sexp;

#if 0
{
#endif
#ifdef __cplusplus
}
#endif
#endif
