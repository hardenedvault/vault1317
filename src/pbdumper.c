/*
 * Copyright (C) 2018-2021, HardenedVault Limited (https://hardenedvault.net)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "pbdumper.h"
#include "axc_helper.h"

const pbdumper* user_data_get_dumper(const void* user_data)
{
  return axc_context_dake_get_dumper((const axc_context_dake*)user_data);
}

DF_IdakeMessage2str(default_IdakeMessage2str)
{
  switch (idakemsg->message_case) {
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_KD:
    return dumper->kd2str((const ProtobufCMessage*)idakemsg->kd);
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_PK:
    return dumper->pk2str((const ProtobufCMessage*)idakemsg->pk);
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_EIK:
    return dumper->eidk2str((const ProtobufCMessage*)idakemsg->eik);
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERIK:
    return dumper->ersidk2str((const ProtobufCMessage*)idakemsg->erik);
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERSIG:
    return dumper->ersig2str((const ProtobufCMessage*)idakemsg->ersig);
  default:
    return (signal_buffer*)SG_ERR_INVALID_MESSAGE;
  }
}

#define FMT_SFNAME_LINE_FUNC			\
  "Function %s, at line %zu of file %s: "
#define FMT_MSGDUMP				\
  "msg %s %s dumped as:\n"				\
  "-----------------------------------------\n"	\
  "%.*s\n"					\
  "-----------------------------------------\n"
int dump_pb(signal_context* gctx,
	    const pbdumper* dumper,
	    const char* srcfname,
	    size_t linenum,
	    const char* funcname,
	    const char* msgname,
	    const char* comment,
	    signal_buffer* retpb2str)
{
  assert(gctx);
  assert(dumper);
  assert(pbdumper_is_valid(dumper));

  int ret = 0;
  if (retpb2str == NULL) {
    signal_log(gctx, SG_LOG_ERROR,
	       FMT_SFNAME_LINE_FUNC"No mem to dump msg!\n",
	       funcname, linenum, srcfname);
    ret = SG_ERR_NOMEM;
    goto complete;
  } else if (retpb2str == (signal_buffer*)SG_ERR_INVALID_MESSAGE) {
    signal_log(gctx, SG_LOG_ERROR,
	       FMT_SFNAME_LINE_FUNC"msg %s is invalid!\n",
	       funcname, linenum, srcfname, msgname);
    retpb2str = NULL;
    ret = SG_ERR_INVALID_MESSAGE;
    goto complete;
  } else if (retpb2str == (signal_buffer*)SG_ERR_UNKNOWN) {
    signal_log(gctx, SG_LOG_ERROR,
	       FMT_SFNAME_LINE_FUNC"\n"
	       "Convert msg %s to string representation encounters internal error!\n",
	       funcname, linenum, srcfname, msgname);
    retpb2str = NULL;
    ret = SG_ERR_UNKNOWN;
    goto complete;
  }

  dumper->logprintf(signal_context_get_user_data(gctx),
		    dumper->msg_dump_log_level,
		    FMT_SFNAME_LINE_FUNC"\n"
		    FMT_MSGDUMP,
		    funcname, linenum, srcfname, msgname, comment,
		    signal_buffer_len(retpb2str),
		    (const char*)signal_buffer_data(retpb2str));
 complete:
  signal_buffer_bzero_free(retpb2str);
  return ret;
}
