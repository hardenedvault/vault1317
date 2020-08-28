#ifndef _SIGADDR_HOLDER_H_
#define _SIGADDR_HOLDER_H_

#include "signal_protocol.h"

#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif
#if 0
}
#endif

typedef struct sigaddr_holder {
  signal_buffer* buf_name;
  signal_protocol_address addr;
} sigaddr_holder;

#define EMPTY_SIGADDR_HOLDER (sigaddr_holder){ 0, { 0, 0, 0 }}

ptrdiff_t sigaddr_compare_name(const signal_protocol_address* a1,
			       const signal_protocol_address* a2);

ptrdiff_t sigaddr_compare_full(const signal_protocol_address* a1,
			       const signal_protocol_address* a2);

bool sigaddr_sane(const signal_protocol_address* addr);

bool sigaddr_holder_sane(const sigaddr_holder* h);

int sigaddr_holder_reassemble(sigaddr_holder* h,
			      const char* name,
			      size_t name_len,
			      uint32_t devid);

int sigaddr_holder_reinit(sigaddr_holder* h,
			  const signal_protocol_address* addr);

const signal_protocol_address*
sigaddr_holder_get_addr(const sigaddr_holder* h);

int sigaddr_holder_copy(sigaddr_holder* h,
			const sigaddr_holder* h_src);

void sigaddr_holder_uninit(sigaddr_holder* h);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif
#endif
