#ifndef _PBDUMPER_H_
#define _PBDUMPER_H_

#include "odake.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

typedef struct pbdumper pbdumper;
const pbdumper* user_data_get_dumper(const void* user_data);

/*
 * Client-dependent methods to convert a dake protobuf msg to a string representation,
 * returned as a pointer to an allocated signal_buffer, which should be freed when no
 * longer needed, NULL when memory is run out, (signal_buffer*)SG_ERR_UNKNOWN when the
 * conversion has internal error, and (signal_buffer*)SG_ERR_INVALID_MESSAGE when the
 * dake protobuf msg is invalid.
 */
#define DF_ProtobufCMessage2str(x)					\
  signal_buffer* (x)(const ProtobufCMessage* pbmsg)
typedef DF_ProtobufCMessage2str(ProtobufCMessage2str_ft);

#define DF_IdakeMessage2str(x)					\
  signal_buffer* (x)(const pbdumper* dumper,			\
		     const Signaldakez__IdakeMessage* idakemsg)
typedef DF_IdakeMessage2str(IdakeMessage2str_ft);

IdakeMessage2str_ft default_IdakeMessage2str;

#define DF_pre_key_bundle2str(x)				\
  signal_buffer* (x)(const session_pre_key_bundle *bundle)
typedef DF_pre_key_bundle2str(pre_key_bundle2str_ft);

// signal_log() can output 256 bytes at most, so it cannot be used.
#define DF_system_logprintf(x)					\
  void (x)(void* user_data, int level, const char* format, ...)
typedef DF_system_logprintf(system_logprintf_ft);

struct pbdumper {
  const char* name;
  int msg_dump_log_level;
  ProtobufCMessage2str_ft* kd2str;
  ProtobufCMessage2str_ft* pk2str;
  ProtobufCMessage2str_ft* idk2str;
  ProtobufCMessage2str_ft* eidk2str;
  ProtobufCMessage2str_ft* rsidk2str;
  ProtobufCMessage2str_ft* ersidk2str;
  ProtobufCMessage2str_ft* ersig2str;
  IdakeMessage2str_ft* idake2str;
  pre_key_bundle2str_ft* bundle2str;
  ProtobufCMessage2str_ft* oid2str;
  ProtobufCMessage2str_ft* opk2str;
  system_logprintf_ft* logprintf;
};

static inline bool pbdumper_is_valid(const pbdumper* dumper)
{
  return (dumper->kd2str) &&
    (dumper->pk2str) &&
    (dumper->idk2str) &&
    (dumper->eidk2str) &&
    (dumper->rsidk2str) &&
    (dumper->ersidk2str) &&
    (dumper->ersig2str) &&
    (dumper->idake2str) &&
    (dumper->oid2str) &&
    (dumper->opk2str) &&
    (dumper->logprintf);
}

/*
 * The common part to dump a dake protobuf msg to the log system. The ret_pb2str
 * is designed to hold the returned value of those ...2str() functions above directly,
 * which will be freed inside dump_pb(). Possible error will be returned as error code.
 */
int dump_pb(signal_context* gctx,
	    const pbdumper* dumper,
	    const char* srcfname,
	    size_t linenum,
	    const char* funcname,
	    const char* msgname,
	    const char* comment,
	    signal_buffer* retpb2str);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif
#endif
