#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include "sockevents.h"

static DF_bufferevent_data_cb(client_instance_read_cb)
{
  client_instance* cinstance = (client_instance*)ctx;
  struct evbuffer* src = bufferevent_get_input(bev);

  size_t clen = evbuffer_get_contiguous_space(src);
  for (; clen; clen = evbuffer_get_contiguous_space(src)) {
    struct evbuffer_ptr pos;
    struct evbuffer_iovec vec;
    evbuffer_ptr_set(src, &pos, 0, EVBUFFER_PTR_SET);
    evbuffer_peek(src, clen, &pos, &vec, 1);
    if (cinstance->parser && cinstance->pmeth->do_parse)
      cinstance->pmeth->do_parse(cinstance->parser, vec.iov_base, vec.iov_len);
    evbuffer_drain(src, clen);
  }
}

static DF_bufferevent_event_cb(client_instance_event_cb)
{
  client_instance* cinstance = (client_instance*)ctx;
  if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
    if (what & BEV_EVENT_ERROR) {
      if (errno)
	client_instance_log(cinstance, "err on connection error");
    }
    client_instance_log(cinstance, "The other end has closed the socket!");
    client_instance_read_cb(bev, ctx);
    if (cinstance->listener) {
      // This instance works as a server
      bufferevent_free(bev);
      cinstance->bev_to_peer = NULL;
    }
  }
}

static DF_evconnlistener_cb(client_instance_accept_cb)
{
  client_instance* cinstance = (client_instance*)ctx;
  memcpy(&cinstance->peer_sa, a, socklen);
  cinstance->peer_sa_size = socklen;
  cinstance->bev_to_peer
    = bufferevent_socket_new(evconnlistener_get_base(listener), fd,
			     BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

  client_instance_log(cinstance, "The other end %s has connected the socket!",
		      ((const struct sockaddr_un*)&cinstance->peer_sa)->sun_path);
  bufferevent_setcb(cinstance->bev_to_peer, client_instance_read_cb,
		    NULL, client_instance_event_cb, cinstance);
  bufferevent_enable(cinstance->bev_to_peer, EV_READ|EV_WRITE);
}

static DF_bufferevent_data_cb(client_instance_postwrite_cb)
{
  bufferevent_setcb(bev, client_instance_read_cb,
		    NULL, client_instance_event_cb, ctx);
  bufferevent_disable(bev, EV_WRITE);
}

int client_instance_send(client_instance* cinstance,
			 const void* data, size_t len)
{
  struct evbuffer* dst = bufferevent_get_output(cinstance->bev_to_peer);
  int result = evbuffer_add(dst, data, len);
  bufferevent_setcb(cinstance->bev_to_peer, client_instance_read_cb,
		    client_instance_postwrite_cb,
		    client_instance_event_cb, cinstance);
  bufferevent_enable(cinstance->bev_to_peer, EV_WRITE);
  return result;
}

void client_instance_init(client_instance* cinstance,
			  struct sockaddr* self_sa,
			  socklen_t self_sa_size,
			  const parser_methods* pmeth,
			  void* parser)
{
  if (self_sa && self_sa_size) {
    cinstance->self_sa_size = self_sa_size;
    memcpy(&cinstance->self_sa, self_sa, self_sa_size);
  } else {
    cinstance->self_sa_size = 0;
  }
  cinstance->pmeth = pmeth;
  cinstance->parser = parser;
}

static DF_pthread_start_routine(client_instance_dispatcher)
{
  struct event_base* evbase = (struct event_base*)arg;
  intptr_t ret = event_base_dispatch(evbase);
  return (void*)ret;
}

void client_instance_log(client_instance* cinstance,
			 const char* format, ...)
{
  if(cinstance->pmeth->log) {
    va_list args, args_cpy;
    va_copy(args_cpy, args);
    va_start(args, format);
    size_t len = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);

    char msg[len];
    va_start(args_cpy, format);
    size_t final_len = vsnprintf(msg, len, format, args_cpy);
    va_end(args_cpy);
    if(final_len > 0) {
      cinstance->pmeth->log(cinstance->parser,
			    msg, len);
    }
  }
}


int client_instance_listen(client_instance* cinstance)
{
  struct event_base* evbase = event_base_new();
  pthread_t result_tid;
  if (!evbase) {
    client_instance_log(cinstance, "err on event_base_new()");
    return 1;
  }
  cinstance->listener
    = evconnlistener_new_bind(evbase, client_instance_accept_cb, cinstance,
			      LEV_OPT_CLOSE_ON_FREE|
			      LEV_OPT_CLOSE_ON_EXEC|
			      LEV_OPT_REUSEABLE, -1,
			      (struct sockaddr*)&cinstance->self_sa,
			      cinstance->self_sa_size);
  if (!cinstance->listener) {
    client_instance_log(cinstance, "err on evconnlistener_new_bind: %d: %s", errno, strerror(errno));
    return -1;
  }
  int ret = pthread_create(&cinstance->tid, NULL,
			   client_instance_dispatcher,
			   evbase);
  if (cinstance->pmeth->postinit)
    cinstance->pmeth->postinit(cinstance->parser);
  return ret;
}

int client_instance_connect(client_instance* cinstance, fd_t sock)
{
  struct event_base* evbase = event_base_new();
  pthread_t result_tid;
  int ret = 0;
  if (!evbase) {
    client_instance_log(cinstance, "err on event_base_new()");
    return 1;
  }

  ret = bind(sock, (struct sockaddr*)&cinstance->self_sa, cinstance->self_sa_size);
  if (ret == -1) {
    client_instance_log(cinstance, "err on bind(): %d: %s", errno, strerror(errno));
    return ret;
  }

  cinstance->bev_to_peer
    = bufferevent_socket_new(evbase, sock,
			     BEV_OPT_CLOSE_ON_FREE|
			     BEV_OPT_DEFER_CALLBACKS);
  bufferevent_setcb(cinstance->bev_to_peer, client_instance_read_cb,
		    NULL, client_instance_event_cb, cinstance);
  bufferevent_enable(cinstance->bev_to_peer, EV_READ|EV_WRITE);

  ret = bufferevent_socket_connect(cinstance->bev_to_peer,
				   (struct sockaddr*)&cinstance->peer_sa,
				   cinstance->peer_sa_size);
  if (ret < 0) {
    client_instance_log(cinstance, "err on bufferevent_socket_connect()");
    bufferevent_free(cinstance->bev_to_peer);
    return ret;
  }

  ret = pthread_create(&cinstance->tid, NULL,
		       client_instance_dispatcher,
		       evbase);

  if (ret < 0) {
    client_instance_log(cinstance, "err to loop the event!");
    event_base_free(evbase);
    return ret;
  }

  if (cinstance->pmeth->postinit)
    cinstance->pmeth->postinit(cinstance->parser);
  return ret;
}

void client_instance_stop(client_instance* cinstance)
{
  intptr_t tret = 0;
  if (!cinstance->bev_to_peer && !cinstance->listener)
    return;
  struct event_base* evbase = (cinstance->bev_to_peer)?
    bufferevent_get_base(cinstance->bev_to_peer):evconnlistener_get_base(cinstance->listener);
  if (0 != event_base_loopexit(evbase, NULL))
    client_instance_log(cinstance, "err on event_base_loopexit()");
}

int client_instance_wait(client_instance* cinstance)
{
  intptr_t tret = 0;
  int ret = pthread_join(cinstance->tid, (void**)&tret);
  if (0 != ret) {
    client_instance_log(cinstance, "err on pthread_join()");
  }
  return tret;
}
