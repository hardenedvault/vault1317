#include <float.h>
#include "sexp.h"
#include "axc_internal_types.h"
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>


gcry_error_t sexp_sarray2lst(gcry_sexp_t* retsexp, size_t* erridx,
			     const char* tag, gcry_sexp_t sarray[],
			     size_t sarr_num)
{
  gcry_error_t err = 0;
  size_t erroff = 0;
  //sfmt_arr is in the form of "(<tag> %S %S...)"
  size_t taglen = strlen(tag);
  size_t sfmt_size =
    sizeof('(') + taglen + 3 * sarr_num + sizeof(')') + sizeof('\0');
  char* sfmt_arr = (char*)malloc(sfmt_size);
  if (!sfmt_arr) {
    err = gcry_err_code_from_errno(errno);
    goto complete;
  }

  //assemble the format string
  {
    sfmt_arr[0] = '(';
    size_t sarr_idx = 0;
    char* finger = &sfmt_arr[1];
    strncpy(finger, tag, taglen);
    finger += taglen;
    for(; sarr_idx < sarr_num; sarr_idx++) {
      memcpy(finger, " %S", 3);
      finger += 3;
    }
    finger[0] = ')';
    finger[1] = '\0';
  }
  gcry_sexp_t** aarr = (gcry_sexp_t**)calloc(sarr_num, sizeof(gcry_sexp_t*));
  {
    size_t i = 0;
    for(; i < sarr_num; i++) {
      aarr[i] = &sarray[i];
    }
  }
  err = gcry_sexp_build_array(retsexp, &erroff, sfmt_arr, (void**)aarr);
  if (err) {
    //calculate erridx from erroff
    if (erridx)
      *erridx = (erroff - (sizeof('(') + taglen)) / 3;
    goto complete;
  }

 complete:
  if (err) {
    gcry_sexp_release(*retsexp);
    *retsexp = NULL;
  }
  free(aarr);
  return err;
}

gcry_error_t axc_prekeylst2sexp(gcry_sexp_t* retsexp, size_t* erridx,
				axc_buf_list_item* prekey_head_p)
{
  gcry_error_t err = 0;
  size_t key_count = 0;
  axc_buf_list_item * next = prekey_head_p;
  while (next) {
    key_count++;
    next = next->next_p;
  }
  gcry_sexp_t* sarr = (gcry_sexp_t*)calloc(key_count, sizeof(gcry_sexp_t));
  if (!sarr) {
    err = gcry_err_code_from_errno(errno);
    goto complete;
  }
  size_t i = 0;
  next = prekey_head_p;
  while (next) {
    err = gcry_sexp_build(&sarr[i++], NULL,
			  sfmt_onetime_prekey,
			  axc_buf_list_item_get_id(next),
			  axc_buf_get_len(axc_buf_list_item_get_buf(next)),
			  axc_buf_get_data(axc_buf_list_item_get_buf(next)));
    if (err)
      goto complete;
    next = next->next_p;
  }

  err = sexp_sarray2lst(retsexp, erridx, "opks", sarr, key_count);

 complete:
  if (err) {
    gcry_sexp_release(*retsexp);
    *retsexp = NULL;
  }
  for (i = 0; i < key_count; i++) {
    gcry_sexp_release(sarr[i]);
  }
  free(sarr);
  return err;
}

gcry_error_t axc_prekeybundle2sexp(gcry_sexp_t* retsexp, size_t* erridx,
				   int devid, axc_bundle* bundle_p)
{
   gcry_error_t err = 0;
   gcry_sexp_t s_prekeylst = NULL;
   axc_buf_list_item* prekeylst = axc_bundle_get_pre_key_list(bundle_p);
   axc_buf* signed_prekey = axc_bundle_get_signed_pre_key(bundle_p);
   axc_buf* signature = axc_bundle_get_signature(bundle_p);
   axc_buf* idkey = axc_bundle_get_identity_key(bundle_p);

   err = axc_prekeylst2sexp(&s_prekeylst, erridx, prekeylst);
   if (err)
     goto complete;

   err = gcry_sexp_build(retsexp, NULL, sfmt_prekey_bundle,
			 axc_bundle_get_reg_id(bundle_p),
			 devid,
			 axc_bundle_get_signed_pre_key_id(bundle_p),
			 axc_buf_get_len(signed_prekey),
			 axc_buf_get_data(signed_prekey),
			 axc_buf_get_len(signature),
			 axc_buf_get_data(signature),
			 s_prekeylst);
   if (err)
     goto complete;

 complete:
   if (err) {
     gcry_sexp_release(*retsexp);
     *retsexp = NULL;
   }
   gcry_sexp_release(s_prekeylst);
   return err;
}

uint32_t s_prekeylst_get_count(const gcry_sexp_t s_prekeylst)
{
  uint32_t l_length = gcry_sexp_length(s_prekeylst);
  if (l_length)
    l_length--; //exclude the car, which is the token.
  return l_length;
}

gcry_error_t axc_s_prekeylst_get_key_with_index(const gcry_sexp_t s_prekeylst,
						int idx, uint32_t* prekey_id_p,
						uint8_t** key_buf_p,
						size_t* key_len_p)
{
  gcry_error_t err = 0;
  size_t key_len = 0;
  uint8_t* key_buf = NULL;
  char* strvalue = NULL;
  union { int d; unsigned int u; } ivalue = {0};
  // the 0th element is the token "opks".
  gcry_sexp_t s_opk = gcry_sexp_nth(s_prekeylst, idx + 1);
  if (!s_opk) {
    // not found, which usually means index exceed
    err = gcry_error(GPG_ERR_NOTHING_FOUND);
    goto complete;
  }

  strvalue = gcry_sexp_nth_string(s_opk, 0);
  if (!strvalue) {
    err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
    goto complete;
  }
  if (1 != sscanf(strvalue, "%u", &ivalue.u)) {
    err = gcry_err_code_from_errno(errno);
    goto complete;
  }

  key_buf = (uint8_t*)gcry_sexp_nth_buffer(s_opk, 1, &key_len);
  if (!key_buf) {
    err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
    goto complete;
  }

 complete:
  if (!err) {
    *prekey_id_p = ivalue.u;
    *key_buf_p = key_buf;
    *key_len_p = key_len;
  }
  gcry_sexp_release(s_opk);
  gcry_free(strvalue);

  return err;
}

static uint32_t rand_in_range(uint32_t dist)
{
#define FACTOR (1.0l / (1ll << 32))
  uint32_t rand = 0;
  gcry_create_nonce(&rand, sizeof(rand));
  return rand * (FACTOR + FACTOR * FACTOR) * dist;
#undef FACTOR
}


gcry_error_t axc_s_prekeylst_get_rand_key(const gcry_sexp_t s_prekeylst,
					  uint32_t* prekey_id_p,
					  uint8_t** key_buf_p,
					  size_t* key_len_p)
{
  uint32_t key_count = s_prekeylst_get_count(s_prekeylst);
  uint32_t rindex = rand_in_range(key_count);
  return axc_s_prekeylst_get_key_with_index(s_prekeylst, rindex,
					    prekey_id_p, key_buf_p,
					    key_len_p);
}

int axc_sexp2prekeybundle(gcry_error_t* gcry_err, signal_context* gctx,
			  gcry_sexp_t s_bundle, session_pre_key_bundle **bundle)
{
  int result = 0;
  session_pre_key_bundle* result_bundle = NULL;
  gcry_error_t err = 0;
  uint32_t regid = 0;
  int devid = 0;
  uint32_t opkid = 0;
  uint32_t spkid = 0;
  ec_public_key* opk = NULL;
  ec_public_key* spk = NULL;
  gcry_sexp_t sublst = NULL;
  union { uint8_t* buf; char* str; const char* ptr; } data = {NULL};
  size_t datalen = 0;
  union { int d; unsigned int u; } ivalue = {0};

  {
    sublst = gcry_sexp_find_token(s_bundle, "opks", 0);
    if (!sublst) {
      err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    err = axc_s_prekeylst_get_rand_key(sublst, &opkid, &data.buf, &datalen);
    if (err) {
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    result = curve_decode_point(&opk, data.buf, datalen, gctx);
    if (result < 0) {
      goto complete;
    }
    gcry_sexp_release(sublst);
    gcry_free(data.buf);
    data.buf = NULL;
  }

  {
    sublst = gcry_sexp_find_token(s_bundle, "regid", 0);
    if (!sublst) {
      err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    data.str = gcry_sexp_nth_string(sublst, 1);
    if (!data.str) {
      err = gcry_error(GPG_ERR_UNEXPECTED_MSG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    if (1 != sscanf(data.str, "%u", &ivalue.u)) {
      result = SG_ERR_INVALID_MESSAGE;
      goto complete;
    }

    regid = ivalue.u;

    gcry_sexp_release(sublst);
    gcry_free(data.buf);
    data.buf = NULL;
  }

  {
    sublst = gcry_sexp_find_token(s_bundle, "devid", 0);
    if (!sublst) {
      err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    data.str = gcry_sexp_nth_string(sublst, 1);
    if (!data.str) {
      err = gcry_error(GPG_ERR_UNEXPECTED_MSG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    if (1 != sscanf(data.str,"%d", &ivalue.d)) {
      result = SG_ERR_INVALID_MESSAGE;
      goto complete;
    }

    devid = ivalue.d;

    gcry_sexp_release(sublst);
    gcry_free(data.str);
    data.buf = NULL;
  }

  {
    sublst = gcry_sexp_find_token(s_bundle, "spk", 0);
    if (!sublst) {
      err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    data.str = gcry_sexp_nth_string(sublst, 1);
    if (!data.str) {
      err = gcry_error(GPG_ERR_UNEXPECTED_MSG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    if (1 != sscanf(data.str,"%u", &ivalue.u)) {
      result = SG_ERR_INVALID_MESSAGE;
      goto complete;
    }

    spkid = ivalue.u;
    gcry_free(data.str);

    data.ptr = gcry_sexp_nth_data(sublst, 2, &datalen);
    if (!data.ptr) {
      err = gcry_error(GPG_ERR_UNEXPECTED_MSG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    result = curve_decode_point(&spk, data.ptr, datalen, gctx);
    if (result < 0) {
      goto complete;
    }

    gcry_sexp_release(sublst);
    data.ptr = NULL;
  }

  {
    sublst = gcry_sexp_find_token(s_bundle, "spksig", 0);
    if (!sublst) {
      err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }

    data.ptr = gcry_sexp_nth_data(sublst, 1, &datalen);
    if (!data.ptr) {
      err = gcry_error(GPG_ERR_UNEXPECTED_MSG);
      result = SG_ERR_INVALID_KEY;
      goto complete;
    }
  }

  result = session_pre_key_bundle_create(&result_bundle, regid, devid, opkid, opk,
					 spkid, spk, data.ptr, datalen, NULL);
  data.ptr = NULL;

 complete:
  if (err || (result < 0)) {
    SIGNAL_UNREF(result_bundle);
  } else {
    *bundle = result_bundle;
  }
  SIGNAL_UNREF(opk);
  SIGNAL_UNREF(spk);
  gcry_sexp_release(sublst);
  gcry_free(data.buf);
  if (gcry_err)
    *gcry_err = err;
  return result;
}

gcry_error_t axc_sigaddr2sexp(gcry_sexp_t* retsexp, size_t* erroff,
			      const signal_protocol_address* addr,
			      const gcry_sexp_t extension)
{
  return gcry_sexp_build(retsexp, erroff, sfmt_sigaddr,
			 addr->name, addr->device_id,
			 extension);
}

gcry_error_t axc_sexp2sigaddr(gcry_sexp_t s_sigaddr,
			      sigaddr_holder* h,
			      gcry_sexp_t* extension)
{
  gcry_error_t err = 0;
  gcry_sexp_t sublst = NULL;
  char* data = NULL;
  size_t datalen = 0;
  int devid = 0;

  {
    sublst = gcry_sexp_find_token(s_sigaddr, "devid", 0);
    if (!sublst) {
      err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
      goto complete;
    }

    data = gcry_sexp_nth_string(sublst, 1);

    if (!data || (1 != sscanf(data, "%d", &devid))) {
      err = gcry_error(GPG_ERR_UNEXPECTED_MSG);
      goto complete;
    }

    gcry_sexp_release(sublst);
    gcry_free(data);
    data = NULL;
  }

  {
    sublst = gcry_sexp_find_token(s_sigaddr, "name", 0);
    if (!sublst) {
      err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
      goto complete;
    }

    data = gcry_sexp_nth_string(sublst, 1);
    if (!data) {
      err = gcry_error(GPG_ERR_UNEXPECTED_MSG);
      goto complete;
    }

    datalen = strlen(data);
  }

 complete:
  if (!err) {
    if(extension)
      *extension = gcry_sexp_nth(s_sigaddr, 3);
    if(SG_ERR_NOMEM == sigaddr_holder_reassemble(h, data, datalen, devid))
      err = gcry_err_code_from_errno(errno);
  }
  gcry_sexp_release(sublst);
  gcry_free(data);
  return err;
}

gcry_error_t axc_sockaddr2sexp(gcry_sexp_t* retsexp, size_t* erroff,
			       const char* af_unix_path,
			       gcry_sexp_t s_sigaddr,
			       gcry_sexp_t s_bundle,
			       gcry_sexp_t extension)
{
  return gcry_sexp_build(retsexp, erroff, sfmt_sockaddr,
			 af_unix_path, s_sigaddr,
			 s_bundle, extension);
}

gcry_error_t axc_sexp2sockaddr(gcry_sexp_t s_sockaddr,
			       char** af_unix_path,
			       gcry_sexp_t* s_sigaddr,
			       gcry_sexp_t* s_bundle,
			       gcry_sexp_t* extension)
{
  gcry_error_t err = 0;
  gcry_sexp_t sublst = NULL;

  {
    sublst = gcry_sexp_find_token(s_sockaddr, "af_unix_path", 0);
    if (!sublst) {
      err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
      goto complete;
    }

    if (af_unix_path) *af_unix_path = gcry_sexp_nth_string(sublst, 1);

    gcry_sexp_release(sublst);
    sublst = gcry_sexp_find_token(s_sockaddr, "instance", 0);
    if (!sublst) {
      err = gcry_error(GPG_ERR_UNEXPECTED_TAG);
      goto complete;
    }

    if (s_sigaddr) *s_sigaddr = gcry_sexp_nth(sublst, 1);
    if (s_bundle) *s_bundle = gcry_sexp_nth(sublst, 2);
    if (extension) *extension = gcry_sexp_nth(s_sockaddr, 3);
  }
 complete:
  gcry_sexp_release(sublst);
  return err;
}

gcry_error_t axc_file2sexp(gcry_sexp_t* retsexp, const char* path)
{
  gcry_error_t gcret = 0;
  struct stat s;
  FILE* f = NULL;
  axc_buf* buf = NULL;
  if (-1 == stat(path, &s)) {
    gcret = gcry_err_code_from_errno(errno);
    goto complete;
  }

  f = fopen(path, "rb");
  if (!f) {
    gcret = gcry_err_code_from_errno(errno);
    goto complete;
  }

  buf = signal_buffer_alloc(s.st_size);
  if (!buf) {
    gcret = gcry_err_code_from_errno(errno);
    goto complete;
  }

  if(1 != fread(axc_buf_get_data(buf), axc_buf_get_len(buf), 1, f)) {
    gcret = gcry_err_code_from_errno(errno);
    goto complete;
  }

  gcret = gcry_sexp_new(retsexp, axc_buf_get_data(buf),
			axc_buf_get_len(buf), 0);
 complete:
  {
    axc_buf_free(buf);
    if (f)
      fclose(f);
  }
  return gcret;
}

gcry_error_t axc_sexp2str(gcry_sexp_t sexp, axc_buf** resbuf)
{
  axc_buf* buf = signal_buffer_alloc(gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0));
  if (buf == NULL)
    return gcry_error(GPG_ERR_ENOMEM);

  gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, axc_buf_get_data(buf), axc_buf_get_len(buf));
  *resbuf = buf;
  return gcry_error(GPG_ERR_NO_ERROR);
}

gcry_error_t axc_sexp2fp(gcry_sexp_t sexp, FILE* f)
{
  axc_buf* buf = NULL;
  gcry_error_t ret = gcry_error(GPG_ERR_NO_ERROR);
  do {
    ret = axc_sexp2str(sexp, &buf);
    if (ret != gcry_error(GPG_ERR_NO_ERROR))
      break;
    fprintf(f, "%.*s", axc_buf_get_len(buf), (const char*)axc_buf_get_data(buf));
  } while (0);
  axc_buf_free(buf);
  return ret;
}

gcry_error_t axc_sexp2file(gcry_sexp_t sexp, const char* path)
{
  FILE* f = NULL;
  gcry_error_t ret = gcry_error(GPG_ERR_NO_ERROR);

  f = fopen(path, "w+b");
  if (!f)
    return gcry_error_from_errno(errno);

  ret = axc_sexp2fp(sexp, f);
  fclose(f);
  return ret;  
}
