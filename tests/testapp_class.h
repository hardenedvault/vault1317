#ifndef _TESTAPP_CLASS_H_
#define _TESTAPP_CLASS_H_

#include "simpletlv.h"
#include "sockevents.h"
#include "axc_helper.h"
#include "idake2session.h"
#include <sys/un.h>
#include "sexp.h"

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define DF_ui_online(x)				\
  int (x)(void* ui, bool on)
typedef DF_ui_online(ui_online_ft);

#define DF_ui_show_message(x)				\
  void (x)(void* ui, const char* message, size_t len)
typedef DF_ui_show_message(ui_show_message_ft);

#define DF_ui_teardown(x) void (x)(void* ui)
typedef DF_ui_teardown(ui_teardown_ft);

#define UNIX_PATH_MAX sizeof(((struct sockaddr_un*)0)->sun_path)

typedef struct ui_methods {
  ui_online_ft* online;
  ui_show_message_ft* showmsg;
  ui_teardown_ft* teardown;
} ui_methods;

typedef struct test_application {
  const ui_methods* ui_meth;
  axc_context_dake* dctx_p;
  client_instance cinst;
  struct event* evsignal;
  stlv_parser tlv_ctx;
  void* ui;
} test_application;

/*
 * "name:id" is encoded as "id@name", which is used in the path of
 * unix domain socket.
 */

int sigaddr_encode(char* buf, size_t buflen,
		   const signal_protocol_address* addr);
void sigaddr_decode(signal_protocol_address* addr, const char* straddr);
const char* basename(const char* path);

DF_event_callback(sigint_handler);

do_parse_ft testapp_parse_msg;

parser_log_ft testapp_log;

parser_postinit_ft testapp_postinit;

extern const parser_methods pm_testapp;

DF_event_callback(sigint_handler);

int testapp_send_msg(test_application* app, axc_buf* plain_text);

int testapp_connect(test_application* app);
int testapp_listen(test_application* app);
int testapp_set_self_sock_path(test_application* app,
			       const char* peer_sock_path);

int testapp_set_peer_sock_path(test_application* app,
			       const char* peer_sock_path);

int testapp_Idake_start(test_application* app);
int testapp_Odake_write_bundle(test_application* app);
int testapp_Odake_start(test_application* app);

void testapp_cleanup(test_application* app);

int testapp_init(test_application* app,
		 const char* name, uint32_t devid,
		 const ui_methods* ui_meth, void* ui);

int testapp_wait(test_application* app);

int testapp_axc_ctx_init(test_application* app,
			 const char* filename,
			 axc_log_func_ft* log_func,
			 int log_level);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
