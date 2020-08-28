#include "testapp_class.h"
#include <fcntl.h>
#include <sys/stat.h>
#ifdef DUMPMSG
#include "pbdumper_sexp.h"
#endif

/*
 * "name:devid" is encoded as "devid@name", which is used in the path of
 * unix domain socket.
 */

int sigaddr_encode(char* buf, size_t buflen,
		   const signal_protocol_address* addr)
{
  return snprintf(buf, buflen, "%u@%.*s", addr->device_id,
		  (int)(addr->name_len), addr->name);
}

void sigaddr_decode(signal_protocol_address* addr, const char* straddr)
{
  char* delim = NULL;
  addr->device_id = (uint32_t)strtoul(straddr, &delim, 10);
  if (errno == ERANGE) {
    addr->device_id = 0;
    addr->name = NULL;
    return;
  }
  addr->name = delim + sizeof(char);
  addr->name_len = strlen(addr->name);
}

const char* basename(const char* path)
{
  const char* b = strrchr(path, '/');
  if (b) return b + sizeof(char);
  else return b;
}

static DF_stlv_found(testapp_stlv_found)
{
  test_application* app = (test_application*)userdata;
  int ret = 0;
  signal_buffer* lastauthmsg = NULL;
  void* hdr_to_send = NULL;
  signal_protocol_address remote_addr = {0, 0, 0};
  axc_buf* msgbuf = NULL;
  axc_buf* plaintext = NULL;
  sigaddr_decode(&remote_addr,
		 basename(((const struct sockaddr_un*)
			  &app->cinst.peer_sa)->sun_path));
  Signaldakez__IdakeMessage* idakemsg
    = signaldakez__idake_message__unpack(0, incoming_len,
					 incoming_data);

  if (idakemsg) {
    // incoming_data contains an idakemsg
    do {
      ret = axc_Idake_handle_msg(app->dctx_p, idakemsg,
				 &remote_addr, (const signal_buffer**)&lastauthmsg);
      if (ret < 0) {
	axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
		"Failed to handle idakemsg with err %d", ret);
	break;
      }

      if (lastauthmsg) {
	hdr_to_send = stlv_make_header(app->tlv_ctx.desc,
				       axc_buf_get_len(lastauthmsg));
	client_instance_send(&app->cinst, hdr_to_send,
			     stlv_header_len(app->tlv_ctx.desc));
	client_instance_send(&app->cinst, axc_buf_get_data(lastauthmsg),
			     axc_buf_get_len(lastauthmsg));
      }
    } while (0);
    signaldakez__idake_message__free_unpacked(idakemsg, 0);
    free(hdr_to_send);
  } else {
    do {
      // incoming_data contains either a pre_key_msg or a regular msg
      msgbuf = axc_buf_create(incoming_data, incoming_len);
      ret = axc_pre_key_message_process_dake(msgbuf,
					     &remote_addr,
					     &app->dctx_p->base, &plaintext);
      if (ret == AXC_ERR_NOT_A_PREKEY_MSG) {
	if (axc_session_exists_initiated(&remote_addr, &app->dctx_p->base)) {
	  ret = axc_message_dec_from_ser_dake(msgbuf,
					      &remote_addr,
					      &app->dctx_p->base, &plaintext);
	} else {
	  axc_log(&app->dctx_p->base, AXC_LOG_INFO,
		  "received a signal message but no session from %d@%.*s exists, ignoring",
		  remote_addr.device_id, (int)remote_addr.name_len, remote_addr.name);
	  break;
	}
      } else if (ret == AXC_ERR_INVALID_KEY_ID) {
	axc_log(&app->dctx_p->base, AXC_LOG_INFO,
		"received an odake prekey msg with an outdated prekey, ignoring");
	break;
      } else if (ret < 0) {
	axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
		"Failed to handle odakemsg with err %d", ret);
	break;
      } else {
	axc_log(&app->dctx_p->base, AXC_LOG_INFO,
		"A new session is created with the odake prekey msg "
		"correctly handled, and a prekey consumed, so update the bundle");
	ret = testapp_Odake_write_bundle(app);
      }

      if (app->ui_meth && app->ui_meth->showmsg)
	app->ui_meth->showmsg(app->ui, axc_buf_get_data(plaintext),
			      axc_buf_get_len(plaintext));
    } while (0);
    axc_buf_free(msgbuf);
    axc_buf_free(plaintext);
  }
}

DF_do_parse(testapp_parse_msg)
{
  test_application* app = (test_application*)parser;
  stlv_parser_feed(&app->tlv_ctx, data, len);
}

DF_parser_log(testapp_log)
{
  test_application* app = (test_application*)parser;
  axc_default_log(AXC_LOG_DEBUG, msg, len, &app->dctx_p->base);
}

const parser_methods pm_testapp = {
  testapp_parse_msg,
  testapp_log,
  testapp_postinit,
  NULL,
  NULL,
};

const stlv_descriptor testapp_tlvdesc = {
  "testapp",
  8,
  testapp_stlv_found,
};

DF_event_callback(sigint_handler)
{
  test_application* app = (test_application*)userdata;
  if (events | EV_SIGNAL) {
    switch (fd) {
    case SIGINT:
    case SIGTERM:
      client_instance_log(&app->cinst, "Terminating...");
      unlink(((const struct sockaddr_un*)&app->cinst.self_sa)->sun_path);
      client_instance_stop(&app->cinst);
      if (app->cinst.pmeth->stop_parser)
	app->cinst.pmeth->stop_parser(app->cinst.parser);
      break;
    }
  }
}

int testapp_send_msg(test_application* app, axc_buf* plain_text)
{
  int result = 0;
  axc_buf* ciphertext = NULL;
  void* hdr_to_send = NULL;
  signal_protocol_address remote_addr = {0, 0, 0};

  sigaddr_decode(&remote_addr,
		 basename(((const struct sockaddr_un*)
			   &app->cinst.peer_sa)->sun_path));

  result = axc_msg_enc_and_ser_dake(plain_text, &remote_addr,
				    &app->dctx_p->base,
				    &ciphertext);

  if (result < 0) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "Failed to encrypt message with err %d", result);
    goto complete;
  }

  {
    hdr_to_send = stlv_make_header(app->tlv_ctx.desc,
				   axc_buf_get_len(ciphertext));
    result = client_instance_send(&app->cinst, hdr_to_send,
				  stlv_header_len(app->tlv_ctx.desc));
    result += client_instance_send(&app->cinst, axc_buf_get_data(ciphertext),
				  axc_buf_get_len(ciphertext));
  }
 complete:
  axc_buf_free(ciphertext);
  free(hdr_to_send);
  return result;
}

DF_parser_postinit(testapp_postinit)
{
  int ret = -1;
  test_application* app = (test_application*)parser;
  struct event_base* evbase = NULL;
  if (app->cinst.bev_to_peer || app->cinst.listener) {
    if (app->cinst.bev_to_peer)
      evbase = bufferevent_get_base(app->cinst.bev_to_peer);
    else
      evbase = evconnlistener_get_base(app->cinst.listener);
    app->evsignal = evsignal_new(evbase, SIGINT, sigint_handler, app);
    ret = event_add(app->evsignal, NULL);
    if (app->ui_meth->online)
      ret = app->ui_meth->online(app->ui, true);
  }
  return ret;
}

int testapp_connect(test_application* app)
{
  int ret = 0;
  do {
    fd_t sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
      axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	      "Failed to obtain socket with errno %d", errno);
      ret = -1;
      break;
    }
    ret = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (ret == -1) {
      break;
    }
    const char* self_sock_path = ((struct sockaddr_un*)
				  &app->cinst.self_sa)->sun_path;
    struct stat info;
    if (0 == stat(self_sock_path, &info) && ((info.st_mode & S_IFMT) == S_IFSOCK)) {
      // Leave other possibilities to the failure of bind()
      axc_log(&app->dctx_p->base, AXC_LOG_WARNING,
	      "Unlinking remaining domain socket file %s", self_sock_path);
      unlink(self_sock_path);
    }
    ret = client_instance_connect(&app->cinst, sock);
  } while (0);
  return ret;
}

int testapp_listen(test_application* app)
{
  const char* self_sock_path = ((struct sockaddr_un*)
				&app->cinst.self_sa)->sun_path;
  struct stat info;
  if (0 == stat(self_sock_path, &info) && ((info.st_mode & S_IFMT) == S_IFSOCK)) {
    // Leave other possibilities to the failure of bind()
    axc_log(&app->dctx_p->base, AXC_LOG_WARNING,
	    "Unlinking remaining domain socket file %s", self_sock_path);
    unlink(self_sock_path);
  }
  return client_instance_listen(&app->cinst);
}

int testapp_set_self_sock_path(test_application* app,
			       const char* self_sock_path)
{
  int result = 0;
  size_t path_len = strlen(self_sock_path);
  //const char* straddr = NULL;
  if (path_len > (UNIX_PATH_MAX - 1)) {
    errno = ERANGE;
    result = -1;
    goto complete;
  }
  //straddr = basename(self_sock_path);
  if (self_sock_path[0] == '/') {
    // self_sock_path is absolute
    strncpy(((struct sockaddr_un*)
	    &app->cinst.self_sa)->sun_path,
	    self_sock_path,
	    UNIX_PATH_MAX);

  } else {
    // self_sock_path is relative
    char cwd[UNIX_PATH_MAX];
    if(NULL == getcwd(cwd, sizeof(cwd))) {
      result = -1;
      goto complete;
    }
    path_len = snprintf(((struct sockaddr_un*)
			&app->cinst.self_sa)->sun_path,
			UNIX_PATH_MAX, "%s/%s", cwd,
			self_sock_path);
  }
  ((struct sockaddr_un*)
   &app->cinst.self_sa)->sun_path[path_len] = '\0';
  ((struct sockaddr_un*)
   &app->cinst.self_sa)->sun_family = AF_UNIX;
   app->cinst.self_sa_size = offsetof(struct sockaddr_un, sun_path) + path_len;
 complete:
  return result;
}


int testapp_set_peer_sock_path(test_application* app,
			       const char* peer_sock_path)
{
  int result = 0;
  size_t path_len = strlen(peer_sock_path);
  //const char* straddr = NULL;
  if (path_len > (UNIX_PATH_MAX - 1)) {
    errno = ERANGE;
    result = -1;
    goto complete;
  }
  //straddr = basename(peer_sock_path);
  if (peer_sock_path[0] == '/') {
    // peer_sock_path is absolute
    strncpy(((struct sockaddr_un*)
	    &app->cinst.peer_sa)->sun_path,
	    peer_sock_path,
	    UNIX_PATH_MAX);

  } else {
    // peer_sock_path is relative
    char cwd[UNIX_PATH_MAX];
    if(NULL == getcwd(cwd, sizeof(cwd))) {
      result = -1;
      goto complete;
    }
    path_len = snprintf(((struct sockaddr_un*)
			&app->cinst.peer_sa)->sun_path,
			UNIX_PATH_MAX, "%s/%s", cwd,
			peer_sock_path);
  }
  ((struct sockaddr_un*)
   &app->cinst.peer_sa)->sun_path[path_len] = '\0';
  ((struct sockaddr_un*)
   &app->cinst.peer_sa)->sun_family = AF_UNIX;
  app->cinst.peer_sa_size = offsetof(struct sockaddr_un, sun_path) + path_len;
 complete:
  return result;
}

int testapp_Idake_start(test_application* app)
{
  int ret = 0;
  signal_protocol_address remote_addr = {0, 0, 0};
  signal_buffer* kdmsg = NULL;
  void* hdr_to_send = NULL;
  if (!app->dctx_p) {
    ret = -1;
    goto complete;
  }
  if (!app->ui_meth || !app->ui || !app->tlv_ctx.desc) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "test app has not initialized!");
    ret = -1;
    goto complete;
  }

  if (!app->cinst.bev_to_peer) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "test app has not connected to peer!");
    ret = -1;
    goto complete;
  }

  sigaddr_decode(&remote_addr,
		 basename(((const struct sockaddr_un*)
			  &app->cinst.peer_sa)->sun_path));
  ret = axc_Idake_start_for_addr(app->dctx_p, &remote_addr, (const signal_buffer**)&kdmsg);
  if (ret < 0)
    goto complete;
  {
    hdr_to_send = stlv_make_header(app->tlv_ctx.desc,
				   axc_buf_get_len(kdmsg));
    ret = client_instance_send(&app->cinst, hdr_to_send,
			       stlv_header_len(app->tlv_ctx.desc));
    ret += client_instance_send(&app->cinst, axc_buf_get_data(kdmsg),
				axc_buf_get_len(kdmsg));
  }
 complete:
  free(hdr_to_send);
  return ret;
}

int testapp_Odake_write_bundle(test_application* app)
{
  axc_bundle* bundle = NULL;
  char bundle_path[UNIX_PATH_MAX];
  gcry_sexp_t s_bundle = NULL;
  size_t erridx = 0;
  int ret = 0;

  ret = axc_bundle_collect(1, &app->dctx_p->base, &bundle);
  if (ret < 0) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "Failed to collect prekey, bundle!");
    goto complete;
  }

  ret = axc_prekeybundle2sexp(&s_bundle, &erridx, axc_bundle_get_reg_id(bundle), bundle);
  if (ret) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "Failed to convert bundle %p to s expression at %z!", bundle, erridx);
    goto complete;
  }

  ret = snprintf(bundle_path, sizeof(bundle_path), "%s.bundle",
		 ((const struct sockaddr_un*)&app->cinst.self_sa)->sun_path);
  if (ret > sizeof(bundle_path)) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "Path for bundle file too long!");
    goto complete;
  }

  ret = axc_sexp2file(s_bundle, bundle_path);
  if (ret)
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "Failed to write bundle to %s!", bundle_path);

 complete:
  axc_bundle_destroy(bundle);
  gcry_sexp_release(s_bundle);
  return ret;
}

int testapp_Odake_start(test_application* app)
{
  int ret = 0;
  gcry_error_t gcret = 0;
  gcry_sexp_t s_bundle = NULL;
  static const char bundle_suffix[] = ".bundle";
  const char* un_path = NULL;
  axc_buf* bundle_path = NULL;
  session_pre_key_bundle* bundle = NULL;
  signal_protocol_address remote_addr = {0, 0, 0};
  axc_buf* b_spk = NULL;
  axc_buf* b_opk = NULL;

  if (!app->dctx_p) {
    ret = -1;
    goto complete;
  }
  if (!app->ui_meth || !app->ui || !app->tlv_ctx.desc) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "test app has not initialized!");
    ret = -1;
    goto complete;
  }

  if (!app->cinst.bev_to_peer) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "test app has not connected to peer!");
    ret = -1;
    goto complete;
  }

  un_path = ((const struct sockaddr_un*)
	     &app->cinst.peer_sa)->sun_path;

  bundle_path = signal_buffer_alloc(strlen(un_path) + sizeof(bundle_suffix));
  ret = snprintf((char*)axc_buf_get_data(bundle_path), axc_buf_get_len(bundle_path),
		 "%s%s", un_path, bundle_suffix);
  if (ret > axc_buf_get_len(bundle_path)) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "Path for bundle file too long!");
    goto complete;
  }
  sigaddr_decode(&remote_addr, basename(un_path));
  gcret = axc_file2sexp(&s_bundle, (const char*)axc_buf_get_data(bundle_path));
  if (gcret) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "failed to read the bundle as sexp: %d", gcret);
    ret = -1;
    goto complete;
  }

  ret = axc_sexp2prekeybundle(&gcret,
			      app->dctx_p->base.axolotl_global_context_p,
			      s_bundle, &bundle);

  if (gcret) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "failed to deserialize the bundle in sexp: %d", gcret);

    goto complete;
  }

  ret = ec_public_key_serialize(&b_spk,
				session_pre_key_bundle_get_signed_pre_key(bundle));
  if (ret < 0) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "The spk in the bundle is invalid");
    goto complete;
  }

  ret = ec_public_key_serialize(&b_opk,
				session_pre_key_bundle_get_pre_key(bundle));
  if (ret < 0) {
    axc_log(&app->dctx_p->base, AXC_LOG_ERROR,
	    "The opk in the bundle is invalid");
    goto complete;
  }

  ret
    = axc_session_from_bundle_dake(session_pre_key_bundle_get_pre_key_id(bundle),
				   b_opk,
				   session_pre_key_bundle_get_signed_pre_key_id(bundle),
				   b_spk,
				   session_pre_key_bundle_get_signed_pre_key_signature(bundle),
				   NULL,
				   &remote_addr,
				   &app->dctx_p->base);

 complete:
  {
    axc_buf_free(bundle_path);
    axc_buf_free(b_spk);
    axc_buf_free(b_opk);
    SIGNAL_UNREF(bundle);
    gcry_sexp_release(s_bundle);
  }
  return ret;
}

void testapp_cleanup(test_application* app)
{
  if (app->ui_meth && app->ui_meth->online)
    app->ui_meth->online(app->ui, false);
  axc_context_dake_destroy_all((axc_context*)app->dctx_p);
  if (app->evsignal) {
    event_free(app->evsignal);
    app->evsignal = NULL;
  }
  struct event_base* evbase = (app->cinst.bev_to_peer)?
    bufferevent_get_base(app->cinst.bev_to_peer):evconnlistener_get_base(app->cinst.listener);
  if (app->cinst.listener) {
    evconnlistener_free(app->cinst.listener);
    app->cinst.listener = NULL;
  }
  if (app->cinst.bev_to_peer) {
    bufferevent_free(app->cinst.bev_to_peer);
    app->cinst.bev_to_peer = NULL;
  }
  event_base_free(evbase);
  if (app->ui_meth && app->ui_meth->teardown)
    app->ui_meth->teardown(app->ui);
  stlv_parser_uninit(&app->tlv_ctx);
}

int testapp_init(test_application* app,
		 const char* name, uint32_t devid,
		 const ui_methods* ui_meth, void* ui)
{
  struct sockaddr_un un_addr;
  un_addr.sun_family = AF_UNIX;
  char cwd[UNIX_PATH_MAX];
  if(!getcwd(cwd, sizeof(cwd)))
    return -1;

  socklen_t un_size = offsetof(struct sockaddr_un, sun_path)
    + snprintf(un_addr.sun_path, UNIX_PATH_MAX,
	       "%s/%u@%s", cwd, devid, name);

  if (un_size > UNIX_PATH_MAX)
    return -1;

  client_instance_init(&app->cinst, (struct sockaddr*)(&un_addr), un_size,
		       &pm_testapp, app);
  app->evsignal = NULL;
  app->ui_meth = ui_meth;
  app->ui = ui;
  stlv_parser_init(&app->tlv_ctx, &testapp_tlvdesc, app, 256, UINT16_MAX);
  return 0;
}

int testapp_wait(test_application* app)
{
  return client_instance_wait(&app->cinst);
}

int testapp_axc_ctx_init(test_application* app,
			 const char* filename,
			 axc_log_func_ft* log_func,
			 int log_level)
{
  int ret = 0;
  char cwd[UNIX_PATH_MAX];
  char db_fn[UNIX_PATH_MAX];
  if(!getcwd(cwd, sizeof(cwd)))
    return -1;

  ret = snprintf(db_fn, sizeof(db_fn), "%s/%s.db", cwd, filename);
  db_fn[UNIX_PATH_MAX - 1] = '\0';
  if (strlen(db_fn) < ret) return -1;

  ret = axc_context_dake_create(&app->dctx_p);
  if (ret != 0) return ret;
  ret = axc_context_set_db_fn(&app->dctx_p->base, db_fn, strlen(db_fn));
  if (ret != 0) return ret;
  if (log_func == NULL) log_func = axc_default_log;
  axc_context_set_log_func(&app->dctx_p->base, log_func);
  axc_context_set_log_level(&app->dctx_p->base, log_level);
  ret = axc_init_with_imp(&app->dctx_p->base, &axc_session_store_tmpl,
			  &axc_pre_key_store_tmpl, &axc_signed_pre_key_store_tmpl,
			  &axc_dakes_identity_key_store_tmpl, &axc_crypto_provider_tmpl);
#ifdef DUMPMSG
  axc_context_dake_set_dumper(app->dctx_p, &pbdumper_sexp);
#endif
  if (ret != 0) return ret;
  ret = axc_install(&app->dctx_p->base);
}
