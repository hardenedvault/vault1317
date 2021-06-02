#include "testapp_class.h"
#include "testapp_rl_ui.h"
#include "testapp_echo_ui.h"
#include <string.h>

int test_client_init(test_application* app, const char* myname, const char* strservaddr)
{
  int ret = -1;
  signal_protocol_address myaddr = {0, 0, 0};
  do {
    ret = testapp_axc_ctx_init(app, myname, rl_log_func, AXC_LOG_DEBUG);
    if (ret < 0) break;
    myaddr.device_id = cachectx_get_faux_regid(app->cachectx_p);
    myaddr.name = myname;
    myaddr.name_len = strlen(myname);
    _rlui.app = app;
    ret = testapp_init(app, myaddr.name, myaddr.device_id, &rlui_meth, &_rlui);
    if (ret < 0) break;    
    ret = testapp_set_peer_sock_path(app, strservaddr);
    if (ret < 0) break;
    ret = testapp_connect(app);
  } while(0);
  return ret;
}

int test_server_init(test_application* app, const char* name)
{
  int ret = -1;
  signal_protocol_address addr = {0, 0, 0};
  do {
    ret = testapp_axc_ctx_init(app, name, NULL, AXC_LOG_DEBUG);
    if (ret < 0) break;
    addr.device_id = cachectx_get_faux_regid(app->cachectx_p);
    if (ret < 0) break;
    addr.name = name;
    addr.name_len = strlen(name);
    ret = testapp_init(app, addr.name, addr.device_id, &echo_ui_meth, app);  
  } while(0);
  return ret;
}

int test_gen_instance(test_application* app, const char* name)
{
  int ret = -1;
  uint32_t devid = 0;
  do {
    ret = testapp_axc_ctx_init(app, name, NULL, AXC_LOG_DEBUG);
    if (ret < 0) {
      fprintf(stderr, "Failed to initialize axc_ctx!\n");
      break;
    }
    devid = cachectx_get_faux_regid(app->cachectx_p);
    fprintf(stderr, "Instance for %s generated with device id %u.\n",
	    name, devid);
  } while (0);
  return ret;
}

int main(int argc, char* argv[])
{
  int ret = 0;
  event_enable_debug_mode();
  test_application app;
  memset(&app, 0, sizeof(app));
  if ((argc >= 3) && (0 == strcmp("generate", argv[1]))) {
    return test_gen_instance(&app, argv[2]);
  } else if ((argc >= 3) && (0 == strcmp("server", argv[1]))) {
    ret = test_server_init(&app, argv[2]);
    if (ret != 0) return ret;
    ret = testapp_listen(&app);
  } else if ((argc >= 4) && (0 == strcmp("client", argv[1]))) {
    ret = test_client_init(&app, argv[2], argv[3]);
    if (ret != 0) return ret;
  } else {
    fprintf(stderr,
	    "Usage:\n"
	    "Manually generate an instance: %s generate <instance name>\n"
	    "Run as server: %s server <server instance name>\n"
	    "\t a unix domain socket named <device id>@<server instance name> will be created.\n"
	    "Run as client: %s client <client instance name> <device id>@<server instance name>\n"
	    "Instances will be generated automatically if absent.\n",
	    argv[0], argv[0], argv[0]);
    return 1;
  }
  ret = testapp_wait(&app);
  testapp_cleanup(&app);
  return ret;
}
