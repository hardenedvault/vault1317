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

#include "cachectx.h"
#include "sigaddr_holder.h"
#include "clinklst.h"
#include <assert.h>


/* hash and comparison function for sigaddr_holder */
static guint sigaddr_hash(gconstpointer key)
{
  const signal_protocol_address* addr = (const signal_protocol_address*)key;
  gint64 product = g_str_hash(addr->name);
  product *= g_int_hash(&addr->device_id);
  return g_int64_hash(&product);
}

static gboolean sigaddr_eq(gconstpointer a, gconstpointer b)
{
  const signal_protocol_address* aa = (const signal_protocol_address*)a;
  const signal_protocol_address* ab = (const signal_protocol_address*)b;
  return (0 == sigaddr_compare_full(aa, ab));
}

signal_protocol_address* sigaddr_heap_dup(const signal_protocol_address* a)
{
  sigaddr_holder* h = (sigaddr_holder*)malloc(sizeof(sigaddr_holder));
  if (!h) return NULL;
  if (SG_SUCCESS != sigaddr_holder_reinit(h, a)) {
    free(h);
    return NULL;
  }
  return &h->addr;
}

void sigaddr_heap_free(signal_protocol_address* a)
{
  sigaddr_holder* h = CL_CONTAINER_OF(a, sigaddr_holder, addr);
  signal_buffer_free(h->buf_name);
  free(h);
}

int cachectx_create(axc_context_dake_cache ** ctx_pp)
{
  if (!ctx_pp) {
    return -1;
  }

  axc_context_dake_cache * ctx_p = (void *) 0;
  ctx_p = malloc(sizeof(axc_context_dake_cache));
  if (!ctx_p) {
    return -2;
  }
  memset(ctx_p, 0, sizeof(axc_context_dake_cache));

  ctx_p->base.base.log_level = -1;

  *ctx_pp = ctx_p;
  return 0;
}

void cachectx_destroy_all(axc_context * ctx_p)
{
  if (ctx_p) {
    axc_context_dake_cache* cachectx = (axc_context_dake_cache*)ctx_p;
    g_hash_table_unref(cachectx->sess_cache);
    axc_context_dake_destroy_all(&(cachectx->base.base));
  }
}

int backend_is_good(const sig_store_backend* backend)
{
  return (backend->sess_tmpl.load_session_func)
    || (backend->sess_tmpl.get_sub_device_sessions_func)
    || (backend->sess_tmpl.store_session_func)
    || (backend->sess_tmpl.contains_session_func)
    || (backend->sess_tmpl.delete_session_func)
    || (backend->sess_tmpl.delete_all_sessions_func)
    || (backend->sess_tmpl.user_data == NULL);
}

int cachectx_has_good_backend(const axc_context_dake_cache* ctx_p)
{
  return backend_is_good(&ctx_p->backend);
}

sess_cache_value* sess_cache_value_new(const uint8_t* rec, size_t rec_len,
				       const uint8_t* urec, size_t urec_len)
{
  sess_cache_value* v = (sess_cache_value*)malloc(sizeof(sess_cache_value));
  if (!v) return NULL;
  v->rec = (rec)?signal_buffer_create(rec, rec_len):NULL;
  v->urec = (urec)?signal_buffer_create(urec, urec_len):NULL;
  return v;
}

void sess_cache_value_free(sess_cache_value* v)
{
  signal_buffer_free(v->rec);
  signal_buffer_free(v->urec);
  free(v);
}

void cachectx_bind_backend(axc_context_dake_cache* ctx_p,
			   const signal_protocol_session_store* sess_tmpl)
{
  ctx_p->backend.sess_tmpl = *sess_tmpl;
  ctx_p->backend.sess_tmpl.user_data = NULL;
  ctx_p->sess_cache = g_hash_table_new_full(sigaddr_hash,
					    sigaddr_eq,
					    (GDestroyNotify)sigaddr_heap_free,
					    (GDestroyNotify)sess_cache_value_free);
}

static int cachectx_load_session(signal_buffer **record,
			  signal_buffer **user_record,
			  const signal_protocol_address *address,
			  void *user_data)
{
  int ret = 0;
  signal_buffer* res_rec = NULL;
  signal_buffer* res_urec = NULL;
  axc_context_dake_cache* ctx_p = (axc_context_dake_cache*)user_data;
  assert(cachectx_has_good_backend(ctx_p));
  sess_cache_value* v
    = (sess_cache_value*)g_hash_table_lookup(ctx_p->sess_cache, address);

  if (v) {
    /* We have found the corresponding value in cache */
    *record = (v->rec)?signal_buffer_copy(v->rec):NULL;
    *user_record = (v->urec)?signal_buffer_copy(v->urec):NULL;
    ret = 1;
  } else {
    ret = ctx_p->backend.sess_tmpl.load_session_func(&res_rec,
						     &res_urec,
						     address,
						     user_data);
    if (ret > 0) {
      /* insert found record into cache */
      signal_protocol_address* k = sigaddr_heap_dup(address);
      v = sess_cache_value_new((res_rec)?signal_buffer_data(res_rec):NULL,
			       (res_rec)?signal_buffer_len(res_rec):0,
			       (res_urec)?signal_buffer_data(res_urec):NULL,
			       (res_urec)?signal_buffer_len(res_urec):0);
      g_hash_table_replace(ctx_p->sess_cache, k, v);

      *record = res_rec;
      *user_record = res_urec;
    }
  }

  return ret;
}

static int cachectx_get_sub_dev_sess(signal_int_list **sessions,
				     const char *name,
				     size_t name_len,
				     void *user_data)
{
  axc_context_dake_cache* ctx_p = (axc_context_dake_cache*)user_data;
  assert(cachectx_has_good_backend(ctx_p));
  int ret = ctx_p->backend.sess_tmpl.get_sub_device_sessions_func(sessions,
								  name,
								  name_len,
								  user_data);
  if (ret >= 0) {
    GHashTableIter iter;
    const signal_protocol_address *addr = NULL;
    gpointer value = NULL;
    if (*sessions == NULL) {
      *sessions = signal_int_list_alloc();
    }
    g_hash_table_iter_init(&iter, ctx_p->sess_cache);
    while (g_hash_table_iter_next(&iter, (gpointer*)&addr, &value)) {
      if (0 == g_strcmp0(name, addr->name)) {
	signal_int_list_push_back(*sessions, addr->device_id);
	ret++;
      }
    }
  }
  return ret;
}

static int cachectx_store_session(const signal_protocol_address *address,
			   uint8_t *record, size_t record_len,
			   uint8_t *user_record, size_t user_record_len,
			   void *user_data)
{
  int ret = 0;
  sess_cache_value* v = NULL;
  axc_context_dake_cache* ctx_p = (axc_context_dake_cache*)user_data;
  assert(cachectx_has_good_backend(ctx_p));

  if (record == (uint8_t*)CACHECTX_COMMIT_RECORD) {
    /* special mode to commit cached record corresponding to the given
     * address
     */

    v = (sess_cache_value*)g_hash_table_lookup(ctx_p->sess_cache, address);
    if (v) {
      ret = ctx_p->backend.sess_tmpl.store_session_func(address,
							signal_buffer_data(v->rec),
							signal_buffer_len(v->rec),
							signal_buffer_data(v->urec),
							signal_buffer_len(v->urec),
							user_data);
    } else {
      /* there is no cached session for the given address */
      ret = SG_ERR_NO_SESSION;
    }
  } else {
    /* store the record in cache */
     signal_protocol_address* k = sigaddr_heap_dup(address);
     v = sess_cache_value_new(record, record_len,
			      user_record, user_record_len);
     g_hash_table_replace(ctx_p->sess_cache, k, v);
  }

  return ret;
}

static int cachectx_have_session(const signal_protocol_address *address, void *user_data)
{
  axc_context_dake_cache* ctx_p = (axc_context_dake_cache*)user_data;
  assert(cachectx_has_good_backend(ctx_p));
  if (g_hash_table_contains(ctx_p->sess_cache, address))
    return true;
  else
    return ctx_p->backend.sess_tmpl.contains_session_func(address,
							  user_data);
}

static int cachectx_delete_session(const signal_protocol_address *address, void *user_data)
{
  axc_context_dake_cache* ctx_p = (axc_context_dake_cache*)user_data;
  assert(cachectx_has_good_backend(ctx_p));
  int ret_top = g_hash_table_remove(ctx_p->sess_cache, address);
  int ret_bottom = ctx_p->backend.sess_tmpl.delete_session_func(address, user_data);
  if (ret_bottom < 0) return ret_bottom;
  else return (ret_top || ret_bottom);
}

static int cachectx_delete_all_sessions(const char *name, size_t name_len, void *user_data)
{
  int ret = 0;
  signal_int_list* sess_lst = NULL;
  axc_context_dake_cache* ctx_p = (axc_context_dake_cache*)user_data;
  assert(cachectx_has_good_backend(ctx_p));

  ret = ctx_p->backend.sess_tmpl.get_sub_device_sessions_func(&sess_lst,
							      name,
							      name_len,
							      user_data);
  if (ret > 0) {
    {
      unsigned int i = 0;
      for(; i < ret; i++) {
	signal_protocol_address addr
	  = {name, name_len, signal_int_list_at(sess_lst, i) };
	g_hash_table_remove(ctx_p->sess_cache, &addr);
      }
    }
    ret = ctx_p->backend.sess_tmpl.delete_all_sessions_func(name,
							    name_len,
							    user_data);
  }

  signal_int_list_free(sess_lst);
  return ret;
}

void cachectx_set_faux_regid(axc_context_dake_cache* ctx_p,
			     uint32_t faux_regid)
{
  ctx_p->faux_regid = faux_regid;
}

uint32_t cachectx_get_faux_regid(const axc_context_dake_cache* ctx_p)
{
  return ctx_p->faux_regid;
}

int cachectx_has_offline_msg(const axc_context_dake_cache* ctx_p)
{
  return ctx_p->has_offline_msg;
}

void cachectx_set_offline_msg_state(axc_context_dake_cache* ctx_p, int state)
{
  ctx_p->has_offline_msg = !!state;
}

static void cachectx_sess_cleanup(void* user_data)
{
  axc_context_dake_cache* ctx_p = (axc_context_dake_cache*)user_data;
  assert(cachectx_has_good_backend(ctx_p));
  g_hash_table_unref(ctx_p->sess_cache);
  ctx_p->sess_cache = NULL;
  ctx_p->backend.sess_tmpl.destroy_func(user_data);
}

const signal_protocol_session_store cachectx_sess_store_tmpl = {
  .load_session_func = cachectx_load_session,
  .get_sub_device_sessions_func = cachectx_get_sub_dev_sess,
  .store_session_func = cachectx_store_session,
  .contains_session_func = cachectx_have_session,
  .delete_session_func = cachectx_delete_session,
  .delete_all_sessions_func = cachectx_delete_all_sessions,
  .destroy_func = cachectx_sess_cleanup,
  NULL,
};
