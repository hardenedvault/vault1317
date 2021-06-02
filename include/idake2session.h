#ifndef _IDAKE2SESSION_H_
#define _IDAKE2SESSION_H_

#include "idake.h"
#include "signal_internal_types.h"
#include "clinklst.h"
#include "sigaddr_holder.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

typedef struct auth_node {
  cl_node cl;
  IdakeAuthInfo* auth;
  sigaddr_holder ah;
} auth_node;

// This is seldom used externally, use auth_node_create_on_list() in most cases.
auth_node* auth_node_new(IdakeAuthInfo* auth,
			 const signal_protocol_address* addr);

auth_node* auth_node_create_on_list(cl_node** l_auth_head,
				    IdakeAuthInfo* auth,
				    const signal_protocol_address* addr);

void auth_node_free(auth_node* node);

const signal_protocol_address*
auth_node_get_addr(const auth_node* node);
IdakeAuthInfo* auth_node_get_auth(auth_node* node);

// Possible to find more via &(auth_node::cl.next)
auth_node* auth_node_find_by_addr(cl_node** l_auth_head,
				  const signal_protocol_address* addr);

auth_node* auth_node_find_by_name(cl_node** l_auth_head,
				  const char* name);

int Idake_start_for_addr(signal_protocol_store_context* sctx,
			 const signal_protocol_address* addr,
			 const signal_buffer** kdmsg,
			 cl_node** l_auth_head);

int Idake_handle_msg(signal_protocol_store_context* sctx,
		     const Signaldakez__IdakeMessage* msg,
		     const signal_protocol_address* addr,
		     const signal_buffer** lastauthmsg,
		     cl_node** l_auth_head);



#if 0
{
#endif
#ifdef __cplusplus
}
#endif
#endif
