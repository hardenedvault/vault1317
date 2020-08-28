#include "testapp_echo_ui.h"
#include "sexp.h"

DF_ui_show_message(echo_ui_show_msg)
{
  test_application* app = (test_application*)ui;
  static const char format[] = "Message from %d@%.*s: %.*s";
  signal_protocol_address remote_addr = {0, 0, 0};
  sigaddr_decode(&remote_addr,
		 basename(((const struct sockaddr_un*)
			  &app->cinst.peer_sa)->sun_path));
  size_t echo_len = snprintf(NULL, 0, format, remote_addr.device_id,
			     (int)(remote_addr.name_len), remote_addr.name,
			     (int)len, message);
  axc_buf* plain = signal_buffer_alloc(echo_len + 1);
  snprintf(axc_buf_get_data(plain), axc_buf_get_len(plain),
	   format, remote_addr.device_id,
	   (int)(remote_addr.name_len), remote_addr.name,
	   (int)len, message);
  axc_log(&app->dctx_p->base, AXC_LOG_INFO, (const char*)axc_buf_get_data(plain));
  testapp_send_msg(app, plain);
  axc_buf_free(plain);
}

DF_ui_online(echo_ui_online)
{
  test_application* app = (test_application*)ui;
  return testapp_Odake_write_bundle(app);
}

const struct ui_methods echo_ui_meth = {
  echo_ui_online,
  echo_ui_show_msg,
  NULL,
};
