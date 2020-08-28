#ifndef _SC_ARITH_H_
#define _SC_ARITH_H_

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif
#if 0
}
#endif

#define DF_event_callback(x)			\
  void (x)(evutil_socket_t fd, short events, void* userdata)

#define DF_bufferevent_data_cb(x)		\
  void (x)(struct bufferevent* bev, void* ctx)	

#define DF_bufferevent_event_cb(x)				\
  void (x)(struct bufferevent* bev, short what, void* ctx)

#define DF_evconnlistener_cb(x)						\
  void (x)(struct evconnlistener* listener,		\
	   evutil_socket_t fd, struct sockaddr* a,	\
	   int socklen, void* ctx)

#define DF_evconnlistener_errorcb(x)			\
  void (x)(struct evconnlistener* listener, void* ctx)

#define DF_do_parse(x)				\
  void (x)(void* parser, const void* data, size_t len)	
typedef DF_do_parse(do_parse_ft);

#define DF_parser_log(x)					\
  void (x)(void* parser, const char* msg, size_t len)
typedef DF_parser_log(parser_log_ft);

#define DF_parser_postinit(x)				\
  int (x)(void* parser)	
typedef DF_parser_postinit(parser_postinit_ft);

#define DF_stop_parser(x)				\
  void (x)(void* parser)	
typedef DF_stop_parser(stop_parser_ft);

#define DF_free_parser(x)				\
  void (x)(void* parser)	
typedef DF_free_parser(free_parser_ft);

#define DF_pthread_start_routine(x) void* (x)(void* arg)
typedef DF_pthread_start_routine(pthread_start_routine_ft);

typedef struct parser_methods {
  do_parse_ft* do_parse;
  parser_log_ft* log;
  parser_postinit_ft* postinit;
  stop_parser_ft* stop_parser;
  free_parser_ft* free_parser;
} parser_methods;

typedef int fd_t;
typedef struct client_instance {
  struct sockaddr_storage self_sa;
  socklen_t self_sa_size;
  struct sockaddr_storage peer_sa;
  socklen_t peer_sa_size;
  pthread_t tid;
  struct bufferevent* bev_to_peer;
  struct evconnlistener* listener; //NULL for client.
  const parser_methods* pmeth;
  void* parser;
} client_instance;

void client_instance_log(client_instance* cinstance,
			 const char* format, ...);

int client_instance_send(client_instance* cinstance,
			 const void* data, size_t len);

void client_instance_init(client_instance* cinstance,
			  struct sockaddr* self_sa,
			  socklen_t self_sa_size,
			  const parser_methods* pmeth,
			  void* parser);

int client_instance_listen(client_instance* cinstance);

int client_instance_connect(client_instance* cinstance, fd_t sock);

void client_instance_stop(client_instance* cinstance);
int client_instance_wait(client_instance* cinstance);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
