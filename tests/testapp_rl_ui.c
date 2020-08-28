#include "testapp_rl_ui.h"
#include <fcntl.h>

readline_ui _rlui;

static const char prompt[]
= "press \'[\' and \']\' to start online and offline handshaking respectively.\n"
  "Message to send:";

static rl_vcpfunc_t rlui_process_line;
static DF_event_callback(rlui_event);

DF_ui_show_message(rlui_show_msg)
{
  test_application* app = ((readline_ui*)ui)->app;
  const char* un_path = ((const struct sockaddr_un*)
			 &app->cinst.peer_sa)->sun_path;
  printf("Message from %s:\n%.*s\n", basename(un_path),
	 len, message);
}

DF_ui_online(rlui_online)
{
  readline_ui* rlui = (readline_ui*)ui;
  int ret = -1;
  struct event_base* evbase = event_get_base(rlui->app->evsignal);
  do {
    if (on) {
      ret = rlui_bind_keys();
      if (ret) break;
      rl_callback_handler_install(prompt, rlui_process_line);
      ret = fcntl(fileno(rl_instream), F_SETFL, O_NONBLOCK);
      if (ret) break;
      rlui->rlevent = event_new(evbase, fileno(rl_instream), EV_READ|EV_PERSIST,
				rlui_event, rlui);
      ret = event_add(rlui->rlevent, NULL);
    } else {
      event_free(rlui->rlevent);
      rlui->rlevent = NULL;
      rl_callback_handler_remove();
      ret = fcntl(fileno(rl_instream), F_SETFL, ~O_NONBLOCK);
    }
  } while (0);
  return ret;
}

const ui_methods rlui_meth = {
  rlui_online,		      
  rlui_show_msg,
  NULL,
};

#define DF_rl_command_func(x) int (x)(int param, int key)
#define DF_rl_vcpfunc(x) void (x)(char* line)

DF_rl_command_func(rlui_Idake_start)
{
  return testapp_Idake_start(_rlui.app);
}

DF_rl_command_func(rlui_Odake_start)
{
  return testapp_Odake_start(_rlui.app);
}

static const rl_bind_entry rl_ui_bind_table[] = {
   { '[', rlui_Idake_start },
   { ']', rlui_Odake_start },
   { '\t', rl_insert }, //treat TAB as printable instead of completion.
   { KEYMAP_SIZE, NULL }
};

int rlui_bind_keys(void)
{
  int ret = -1;
  size_t i = 0;
  for (; i < sizeof(rl_ui_bind_table) / sizeof(rl_bind_entry); i++) {
    if (rl_ui_bind_table[i].key == KEYMAP_SIZE) break;
    ret = rl_bind_key(rl_ui_bind_table[i].key, rl_ui_bind_table[i].cmdfunc);
    if (ret != 0) break;
  }
  return ret;
}

DF_rl_vcpfunc(rlui_process_line)
{
  axc_buf* pmsg = NULL;
  if (line) {
    if (*line)
      add_history (line);
    do {
      pmsg = signal_buffer_create(line, strlen(line) + 1);
      if (!pmsg) break;
      testapp_send_msg(_rlui.app, pmsg);
    } while(0);
    axc_buf_free(pmsg);
    free (line);
  }
}

DF_event_callback(rlui_event)
{
  readline_ui* rlui = (readline_ui*)userdata;
  if (events | EV_READ) {
    rl_callback_read_char();
  }
}

DF_axc_log_func(rl_log_func)
{
  rl_save_prompt();
  {
    rl_message("[AXC %d] %s\n", level, message);
  }
  rl_restore_prompt();
}
