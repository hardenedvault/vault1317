#ifndef _TESTAPP_RL_UI_H_
#define _TESTAPP_RL_UI_H_

#include "testapp_class.h"
#include <readline/readline.h>
#include <readline/history.h>

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define DF_rl_command_func(x) int (x)(int param, int key)
#define DF_rl_vcpfunc(x) void (x)(char* line)

typedef struct readline_ui {
  test_application* app;
  struct event* rlevent;
} readline_ui;

typedef struct rl_bind_entry {
  int key;
  rl_command_func_t* cmdfunc;
} rl_bind_entry;

ui_show_message_ft rlui_show_msg;
ui_online_ft rlui_online;

extern const ui_methods rlui_meth;
extern readline_ui _rlui;

rl_command_func_t rlui_Idake_start;
rl_command_func_t rlui_Odake_start;

int rlui_bind_keys(void);
axc_log_func_ft rl_log_func;

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
