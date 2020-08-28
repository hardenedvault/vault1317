#include "idake2session.h"

typedef struct a2s_data {
  int idake_complete;
  const signal_protocol_address* addr;
  signal_protocol_store_context* sctx;
} a2s_data;

static DF_auth_succeeded(a2s)
{
  int result = 0;
  a2s_data* adata = (a2s_data*)asdata;
  session_record* record = NULL;
  session_state* state = NULL;
  signal_lock(adata->sctx->global_context);
  result = signal_protocol_session_load_session(adata->sctx, &record,
						adata->addr);
  if (result < 0)
    goto complete;

  if(!session_record_is_fresh(record)) {
    result = session_record_archive_current_state(record);
    if(result < 0)
      goto complete;
  }

  state = session_record_get_state(record);

  result = Idake_init_session(auth, state, adata->sctx->global_context);
  if (result < 0)
    goto complete;

  result = signal_protocol_session_store_session(adata->sctx,
						 adata->addr,
						 record);
  if (result < 0)
    goto complete;

  result = signal_protocol_identity_save_identity(adata->sctx,
						  adata->addr,
						  auth->their_ik_pub);
  adata->idake_complete = true;
 complete:
  SIGNAL_UNREF(record);
  signal_unlock(adata->sctx->global_context);
  return result;
}

auth_node* auth_node_new(IdakeAuthInfo* auth,
			 const signal_protocol_address* addr)
{
  auth_node* new_node = (auth_node*)malloc(sizeof(auth_node));
  if (new_node) {
    memset(new_node, 0, sizeof(auth_node));
    new_node->auth = auth;

    if (SG_SUCCESS != sigaddr_holder_reinit(&new_node->ah, addr)) {
      free(new_node);
      return NULL;
    }

    SIGNAL_REF(new_node->auth);
  }
  return new_node;
}

void auth_node_free(auth_node* node)
{
  if (node) {
    SIGNAL_UNREF(node->auth);
    sigaddr_holder_uninit(&node->ah);
    free(node);
  }
}

const signal_protocol_address*
auth_node_get_addr(const auth_node* node)
{
  return sigaddr_holder_get_addr(&node->ah);
}

IdakeAuthInfo* auth_node_get_auth(auth_node* node)
{
  return node->auth;
}

auth_node* auth_node_find_by_addr(cl_node** l_auth_head,
				  const signal_protocol_address* addr)
{
  cl_node** curp;
  CL_FOREACH(curp, l_auth_head) {
    auth_node* node = CL_CONTAINER_OF((*curp), auth_node, cl);
    if (0 == sigaddr_compare_name(auth_node_get_addr(node), addr))
      return node;
  }
  return NULL;
}

int Idake_start_for_addr(signal_protocol_store_context* sctx,
			 const signal_protocol_address* addr,
			 const signal_buffer** kdmsg,
			 cl_node** l_auth_head)
{
  int result = 0;
  IdakeAuthInfo* auth = NULL;
  ratchet_identity_key_pair* our_ik_pair = NULL;
  auth_node* anode = auth_node_find_by_addr(l_auth_head, addr);
  if (!anode) {
    result = IdakeAuthInfo_create(&auth);
    if (result < 0)
      goto complete;

    anode = auth_node_new(auth, addr);
    SIGNAL_UNREF(auth);
    if (!anode) {
      result = SG_ERR_NOMEM;
      goto complete;
    }

    cl_insert_after(l_auth_head, &anode->cl);
  }
  auth = auth_node_get_auth(anode);

  result = signal_protocol_identity_get_key_pair(sctx, &our_ik_pair);
  if (result < 0)
    goto complete;

  result = IdakeAuthStart(auth, sctx->global_context,
			  (ec_key_pair*)our_ik_pair);
  if (result < 0)
    goto complete;

  *kdmsg = auth->lastauthmsg;

 complete:
  SIGNAL_UNREF(our_ik_pair);
  return result;
}

int Idake_handle_msg(signal_protocol_store_context* sctx,
		     const Signaldakez__IdakeMessage* msg,
		     const signal_protocol_address* addr,
		     const signal_buffer** lastauthmsg,
		     cl_node** l_auth_head)
{
  int result = 0;
  ratchet_identity_key_pair* our_ik_pair = NULL;
  IdakeAuthInfo* auth = NULL;
  auth_node* anode = auth_node_find_by_addr(l_auth_head, addr);
  uint32_t regid = 0;
  int havemsg = false;
  a2s_data adata = (a2s_data){false, addr, sctx};
  if (!anode) {
    result = IdakeAuthInfo_create(&auth);
    if (result < 0)
      goto complete;

    anode = auth_node_new(auth, addr);
    SIGNAL_UNREF(auth);
    if (!anode) {
      result = SG_ERR_NOMEM;
      goto complete;
    }

    cl_insert_after(l_auth_head, &anode->cl);
  }
  auth = auth_node_get_auth(anode);

  switch(msg->message_case) {
  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_KD:
    result = signal_protocol_identity_get_key_pair(sctx, &our_ik_pair);
    if (result < 0)
      goto complete;
    result = Idake_handle_kdgstmsg(auth, sctx->global_context,
				   msg, (ec_key_pair*)our_ik_pair);
    if (result < 0)
      goto complete;

    *lastauthmsg = auth->lastauthmsg;
    break;

  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_PK:
    result = signal_protocol_identity_get_local_registration_id(sctx, &regid);
    if (result < 0)
      goto complete;

    result = Idake_handle_prekeymsg(auth, sctx->global_context,
				    msg, regid, &havemsg);
    if (result < 0)
      goto complete;

    if (havemsg)
      *lastauthmsg = auth->lastauthmsg;
    break;

  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_EIK:
    result = signal_protocol_identity_get_local_registration_id(sctx, &regid);
    if (result < 0)
      goto complete;

    result = Idake_handle_idkeymsg(auth, sctx->global_context,
				   regid, msg, &havemsg);
    if (result < 0)
      goto complete;

    if (havemsg)
      *lastauthmsg = auth->lastauthmsg;
    break;

  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERIK:
    result = Idake_handle_ersidkmsg(auth, sctx->global_context,
				    msg, &havemsg, a2s,
				    (void*)(&adata));
    if (result < 0)
      goto complete;

    if (havemsg)
      *lastauthmsg = auth->lastauthmsg;
    break;

  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE_ERSIG:
    result = Idake_handle_ersigmsg(auth, sctx->global_context,
				   msg, &havemsg, a2s,
				   (void*)(&adata));

    if (result < 0)
      goto complete;

    if (havemsg)
      *lastauthmsg = auth->lastauthmsg;
    break;

  case SIGNALDAKEZ__IDAKE_MESSAGE__MESSAGE__NOT_SET:
  default:
    break;
  }
 complete:
  SIGNAL_UNREF(our_ik_pair);
  return result;
}
