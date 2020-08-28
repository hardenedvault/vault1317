#ifndef _SEXP_H_
#define _SEXP_H_

#include <gcrypt.h>
#include <string.h>
#include "axc.h"
#include "session_pre_key.h"
#include "sigaddr_holder.h"

#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif
#if 0
}
#endif

static const char sfmt_prekey_bundle[] =
  "(prekey_bundle"
  "  (regid %u)"
  "  (devid %d)"
  "  (spk %u %b)"
  "  (spksig %b)"
  "  %S)";

/*
 * The last %S is the variable-length list of
 * onetime_prekeys in the format of
 * "(opks
 *    (%u %b)
 *    (%u %b)
 *    ...)" and assembled with sexp_sarray2lst()
 * below.
 */

static const char sfmt_onetime_prekey[] =
  "(%u %b)";

static const char sfmt_sigaddr[] =
  "(signal_address"
  "  (name %s)"
  "  (devid %d)"
  "  %S)";//extension, allowed to be NULL

static const char sfmt_sockaddr[] =
  "(socket"
  "  (af_unix_path %s)"
  "  (instance %S %S)" // address and bundle
  "  %S)"; //extension, allowed to be NULL

// The last %S could be used to append other info

// Convert an array of gcry_sexp_t into a tag-prefixed gcry_sexp_t
gcry_error_t sexp_sarray2lst(gcry_sexp_t* retsexp, size_t* erridx,
			     const char* tag, gcry_sexp_t sarray[],
			     size_t sarr_num);

gcry_error_t axc_prekeylst2sexp(gcry_sexp_t* retsexp, size_t* erridx,
				axc_buf_list_item* prekey_head_p);

gcry_error_t axc_prekeybundle2sexp(gcry_sexp_t* retsexp, size_t* erridx,
				   int devid, axc_bundle* bundle_p);

// return the count of prekeys in the list
uint32_t s_prekeylst_get_count(const gcry_sexp_t s_prekeylst);

gcry_error_t axc_s_prekeylst_get_key_with_index(const gcry_sexp_t s_prekeylst,
						int idx, uint32_t* prekey_id_p,
						uint8_t** key_buf_p,
						size_t* key_len_p);

gcry_error_t axc_s_prekeylst_get_rand_key(const gcry_sexp_t s_prekeylst,
					  uint32_t* prekey_id_p,
					  uint8_t** key_buf_p,
					  size_t* key_len_p);

int axc_sexp2prekeybundle(gcry_error_t* gcry_err, signal_context* gctx,
			  gcry_sexp_t s_bundle, session_pre_key_bundle **bundle);

gcry_error_t axc_sigaddr2sexp(gcry_sexp_t* retsexp, size_t* erroff,
			      const signal_protocol_address* addr,
			      const gcry_sexp_t extension);

gcry_error_t axc_sexp2sigaddr(gcry_sexp_t s_sigaddr,
			      sigaddr_holder* h,
			      gcry_sexp_t* extension);

gcry_error_t axc_sockaddr2sexp(gcry_sexp_t* retsexp, size_t* erroff,
			       const char* af_unix_path,
			       gcry_sexp_t s_sigaddr,
			       gcry_sexp_t s_bundle,
			       gcry_sexp_t extension);

gcry_error_t axc_sexp2sockaddr(gcry_sexp_t s_sockaddr,
			       char** af_unix_path,
			       gcry_sexp_t* s_sigaddr,
			       gcry_sexp_t* s_bundle,
			       gcry_sexp_t* extension);

gcry_error_t axc_file2sexp(gcry_sexp_t* retsexp, const char* path);
gcry_error_t axc_sexp2str(gcry_sexp_t sexp, axc_buf** resbuf);
gcry_error_t axc_sexp2fp(gcry_sexp_t sexp, FILE* f);
gcry_error_t axc_sexp2file(gcry_sexp_t sexp, const char* path);
#if 0
{
#endif
#ifdef __cplusplus
}
#endif
#endif
