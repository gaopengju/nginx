
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE           1
#define NGX_PEER_NEXT                2
#define NGX_PEER_FAILED              4


typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
#if (NGX_SSL)

typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
#endif


struct ngx_peer_connection_s {
    ngx_connection_t                *connection;    /* 对应的链接结构 */

    struct sockaddr                 *sockaddr;      /* 通过LB获取的服务器地址 */
    socklen_t                        socklen;
    ngx_str_t                       *name;

    ngx_uint_t                       tries;         /* 可利用的服务器数量，包括备用、正常 */
    ngx_msec_t                       start_time;    /* 连接时间 */

    ngx_event_get_peer_pt   get;   /* 四层代理
                                        RR: ngx_stream_upstream_get_round_robin_peer()
                                        hash: ngx_stream_upstream_get_hash_peer()
                                      七层代理
                                        RR: ngx_http_upstream_get_round_robin_peer()
                                        IP HASH: ngx_http_upstream_get_ip_hash_peer()
                                    */
    ngx_event_free_peer_pt  free;  /* RR: ngx_stream_upstream_free_round_robin_peer()
                                      rr: ngx_http_upstream_free_round_robin_peer() */
    void                            *data;          /* 维护LB工作数据
                                                         rr: ngx_stream_upstream_rr_peer_data_t
                                                         hash: ngx_stream_upstream_hash_peer_data_t->rrp
                                                         rr: ngx_http_upstream_rr_peer_data_t
                                                     */

#if (NGX_SSL)/* 会话恢复 */
    ngx_event_set_peer_session_pt    set_session; /* RR: ngx_stream_upstream_set_round_robin_peer_session()
                                                     rr: ngx_http_upstream_set_round_robin_peer_session() */
    ngx_event_save_peer_session_pt   save_session;/* RR: ngx_stream_upstream_save_round_robin_peer_session()
                                                     rr: ngx_http_upstream_save_round_robin_peer_session() */
#endif

    ngx_addr_t                      *local;         /* 绑定的本地地址 */

    int                              type;          /* 连接类型，SOCK_STREAM */
    int                              rcvbuf;

    ngx_log_t                       *log;

    unsigned                         cached:1;      /**/
#if (NGX_HAVE_TRANSPARENT_PROXY)
    unsigned                         transparent:1;
#endif

                                     /* ngx_connection_log_error_e */
    unsigned                         log_error:2;
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
