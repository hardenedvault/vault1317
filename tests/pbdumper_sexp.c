#include "pbdumper_sexp.h"
#include "axc.h"

DF_ProtobufCMessage2sexp(kd2sexp)
{
  return gcry_sexp_build(retsexp, NULL,
			 "(IdakeKeyDigestMessage (digest %b))",
			 ((const Signaldakez__IdakeKeyDigestMessage*)pbmsg)->digest.len,
			 ((const Signaldakez__IdakeKeyDigestMessage*)pbmsg)->digest.data);

}

DF_ProtobufCMessage2sexp(pk2sexp)
{
  return gcry_sexp_build(retsexp, NULL,
			 "(IdakePreKeyMessage (prekey %b))",
			 ((const Signaldakez__IdakePreKeyMessage*)pbmsg)->prekey.len,
			 ((const Signaldakez__IdakePreKeyMessage*)pbmsg)->prekey.data);
}

DF_ProtobufCMessage2sexp(idk2sexp)
{
  return gcry_sexp_build(retsexp, NULL, "(IdakeIdKeyMessage"
			 " (idkey %b)"
			 " (regid %u))",
			 ((const Signaldakez__IdakeIdKeyMessage*)pbmsg)->idkey.len,
			 ((const Signaldakez__IdakeIdKeyMessage*)pbmsg)->idkey.data,
			 ((const Signaldakez__IdakeIdKeyMessage*)pbmsg)->regid);
}

DF_ProtobufCMessage2sexp(eidk2sexp)
{
  return gcry_sexp_build(retsexp, NULL, "(IdakeEncryptedIdKeyMessage"
			 " (prekey %b)"
			 " (encidkey %b))",
			 ((const Signaldakez__IdakeEncryptedIdKeyMessage*)pbmsg)->prekey.len,
			 ((const Signaldakez__IdakeEncryptedIdKeyMessage*)pbmsg)->prekey.data,
			 ((const Signaldakez__IdakeEncryptedIdKeyMessage*)pbmsg)->encidkey.len,
			 ((const Signaldakez__IdakeEncryptedIdKeyMessage*)pbmsg)->encidkey.data);
}

DF_ProtobufCMessage2sexp(rsidk2sexp)
{
  return gcry_sexp_build(retsexp, NULL, "(dakeRsignedIdKeyMessage"
			 " (idkey %b)"
			 " (regid %u)"
			 " (rsig %b))",
			 ((const Signaldakez__IdakeRsignedIdKeyMessage*)pbmsg)->idkey.len,
			 ((const Signaldakez__IdakeRsignedIdKeyMessage*)pbmsg)->idkey.data,
			 ((const Signaldakez__IdakeRsignedIdKeyMessage*)pbmsg)->regid,
			 ((const Signaldakez__IdakeRsignedIdKeyMessage*)pbmsg)->rsig.len,
			 ((const Signaldakez__IdakeRsignedIdKeyMessage*)pbmsg)->rsig.data);
}

DF_ProtobufCMessage2sexp(ersidk2sexp)
{
  return gcry_sexp_build(retsexp, NULL, "(IdakeEncryptedRsIdKMessage"
			 " (encrsidkeymsg %b))",
			 ((const Signaldakez__IdakeEncryptedRsIdKMessage*)pbmsg)->encrsidkeymsg.len,
			 ((const Signaldakez__IdakeEncryptedRsIdKMessage*)pbmsg)->encrsidkeymsg.data);
}

DF_ProtobufCMessage2sexp(ersig2sexp)
{
  return gcry_sexp_build(retsexp, NULL, "(IdakeEncryptedRsigMessage"
			 " (encrsig %b))",
			 ((const Signaldakez__IdakeEncryptedRsigMessage*)pbmsg)->encrsig.len,
			 ((const Signaldakez__IdakeEncryptedRsigMessage*)pbmsg)->encrsig.data);
}

DF_pre_key_bundle2sexp(bundle2sexp)
{
  signal_buffer* spksig = session_pre_key_bundle_get_signed_pre_key_signature(bundle);
  return gcry_sexp_build(retsexp, NULL, "(session_pre_key_bundle"
			 " (registration_id %u)"
			 " (device_id %d)"
			 " (pre_key %u %b)"
			 " (signed_pre_key %u %b"
			 "  (signed_pre_key_signature %b)))",
			 session_pre_key_bundle_get_registration_id(bundle),
			 session_pre_key_bundle_get_device_id(bundle),
			 session_pre_key_bundle_get_pre_key_id(bundle),
			 sizeof(keybytes),
			 *ec_key_get_bytes((ec_key*)session_pre_key_bundle_get_pre_key(bundle)),
			 session_pre_key_bundle_get_signed_pre_key_id(bundle),
			 sizeof(keybytes),
			 *ec_key_get_bytes((ec_key*)
					   session_pre_key_bundle_get_signed_pre_key(bundle)),
			 signal_buffer_len(spksig),
			 signal_buffer_data(spksig));
}

DF_ProtobufCMessage2sexp(oid2sexp)
{
  return gcry_sexp_build(retsexp, NULL, "(OdakeIdMessage"
			 " (idkey %b)"
			 " (regid %u)"
			 " (mac %b)"
			 " (rsig %b))",
			 ((const Signaldakez__OdakeIdMessage*)pbmsg)->idkey.len,
			 ((const Signaldakez__OdakeIdMessage*)pbmsg)->idkey.data,
			 ((const Signaldakez__OdakeIdMessage*)pbmsg)->regid,
			 ((const Signaldakez__OdakeIdMessage*)pbmsg)->mac.len,
			 ((const Signaldakez__OdakeIdMessage*)pbmsg)->mac.data,
			 ((const Signaldakez__OdakeIdMessage*)pbmsg)->rsig.len,
			 ((const Signaldakez__OdakeIdMessage*)pbmsg)->rsig.data);
}

DF_ProtobufCMessage2sexp(opk2sexp)
{
  return gcry_sexp_build(retsexp, NULL, "(OdakePreKeyMessage"
			 " (prekey %u %b)"
			 " (rspkid %u)"
			 " (encidmsg %b)"
			 " (payload %b))",
			 ((const Signaldakez__OdakePreKeyMessage*)pbmsg)->rpkid,
			 ((const Signaldakez__OdakePreKeyMessage*)pbmsg)->prekey.len,
			 ((const Signaldakez__OdakePreKeyMessage*)pbmsg)->prekey.data,
			 ((const Signaldakez__OdakePreKeyMessage*)pbmsg)->rspkid,
			 ((const Signaldakez__OdakePreKeyMessage*)pbmsg)->encidmsg.len,
			 ((const Signaldakez__OdakePreKeyMessage*)pbmsg)->encidmsg.data,
			 ((const Signaldakez__OdakePreKeyMessage*)pbmsg)->payload.len,
			 ((const Signaldakez__OdakePreKeyMessage*)pbmsg)->payload.data);
}

static signal_buffer* pb2sexp2str(const ProtobufCMessage* pbmsg,
				  ProtobufCMessage2sexp_ft* pb2sexp)
{
  gcry_error_t ret = gcry_error(GPG_ERR_NO_ERROR);
  gcry_sexp_t sexp = NULL;
  signal_buffer* buf = NULL;
  ret = pb2sexp(&sexp, pbmsg);
  if (ret >= gcry_error(GPG_ERR_SEXP_INV_LEN_SPEC) &&
      ret <= gcry_error(GPG_ERR_SEXP_BAD_OCT_CHAR)) {
    buf = (signal_buffer*)SG_ERR_INVALID_MESSAGE;
    goto complete;
  } else if (ret != gcry_error(GPG_ERR_NO_ERROR)) {
    buf = (signal_buffer*)SG_ERR_UNKNOWN;
    goto complete;
  }
  axc_sexp2str(sexp, &buf);
 complete:
  gcry_sexp_release(sexp);
  return buf;
}

static DF_ProtobufCMessage2str(kd2str){ return pb2sexp2str(pbmsg, kd2sexp); }
static DF_ProtobufCMessage2str(pk2str){ return pb2sexp2str(pbmsg, pk2sexp); }
static DF_ProtobufCMessage2str(idk2str){ return pb2sexp2str(pbmsg, idk2sexp); }
static DF_ProtobufCMessage2str(eidk2str){ return pb2sexp2str(pbmsg, eidk2sexp); }
static DF_ProtobufCMessage2str(rsidk2str){ return pb2sexp2str(pbmsg, rsidk2sexp); }
static DF_ProtobufCMessage2str(ersidk2str){ return pb2sexp2str(pbmsg, ersidk2sexp); }
static DF_ProtobufCMessage2str(ersig2str){ return pb2sexp2str(pbmsg, ersig2sexp); }

static DF_IdakeMessage2str(idake2str)
{
  gcry_error_t ret = gcry_error(GPG_ERR_NO_ERROR);
  gcry_sexp_t sexp = NULL;
  gcry_sexp_t subsexp = NULL;
  signal_buffer* buf = NULL;
  switch (idakemsg->message_case) {
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_KD:
    ret = kd2sexp(&subsexp, (const ProtobufCMessage*)idakemsg->kd);
    break;
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_PK:
    ret = pk2sexp(&subsexp, (const ProtobufCMessage*)idakemsg->pk);
    break;
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_EIK:
    ret = eidk2sexp(&subsexp, (const ProtobufCMessage*)idakemsg->eik);
    break;
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERIK:
    ret = ersidk2sexp(&subsexp, (const ProtobufCMessage*)idakemsg->erik);
    break;
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERSIG:
    ret = ersig2sexp(&subsexp, (const ProtobufCMessage*)idakemsg->ersig);
    break;
  default:
    ret = gcry_error(GPG_ERR_SEXP_BAD_CHARACTER);
    break;
  }
  if (ret >= gcry_error(GPG_ERR_SEXP_INV_LEN_SPEC) &&
      ret <= gcry_error(GPG_ERR_SEXP_BAD_OCT_CHAR)) {
    buf = (signal_buffer*)SG_ERR_INVALID_MESSAGE;
    goto complete;
  } else if (ret != gcry_error(GPG_ERR_NO_ERROR)) {
    buf = (signal_buffer*)SG_ERR_UNKNOWN;
    goto complete;
  }
  gcry_sexp_build(&sexp, NULL, "(IdakeMessage %S)", subsexp);
  axc_sexp2str(sexp, &buf);
 complete:
  gcry_sexp_release(sexp);
  gcry_sexp_release(subsexp);
  return buf;
}

static DF_pre_key_bundle2str(bundle2str)
{
  gcry_error_t ret = gcry_error(GPG_ERR_NO_ERROR);
  gcry_sexp_t sexp = NULL;
  signal_buffer* buf = NULL;
  ret = bundle2sexp(&sexp, bundle);
  if (ret >= gcry_error(GPG_ERR_SEXP_INV_LEN_SPEC) &&
      ret <= gcry_error(GPG_ERR_SEXP_BAD_OCT_CHAR)) {
    buf = (signal_buffer*)SG_ERR_INVALID_MESSAGE;
    goto complete;
  } else if (ret != gcry_error(GPG_ERR_NO_ERROR)) {
    buf = (signal_buffer*)SG_ERR_UNKNOWN;
    goto complete;
  }
  axc_sexp2str(sexp, &buf);
 complete:
  gcry_sexp_release(sexp);
  return buf;
}

static DF_ProtobufCMessage2str(oid2str){ return pb2sexp2str(pbmsg, oid2sexp); }
static DF_ProtobufCMessage2str(opk2str){ return pb2sexp2str(pbmsg, opk2sexp); }

pbdumper pbdumper_sexp = {
  "pbdumper_sexp",
  AXC_LOG_DEBUG,
  kd2str,
  pk2str,
  idk2str,
  eidk2str,
  rsidk2str,
  ersidk2str,
  ersig2str,
  idake2str,
  bundle2str,
  oid2str,
  opk2str,
  (system_logprintf_ft*)axc_log,
};
