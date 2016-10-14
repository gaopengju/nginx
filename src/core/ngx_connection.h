
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;
/* nginx监听的插口描述结构 */
struct ngx_listening_s {
    ngx_socket_t        fd;         /* 插口fd */      

    struct sockaddr    *sockaddr;   /* 地址 */
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
    ngx_str_t           addr_text;  /* 地址的字符串形式，如'1.1.1.1:65530'*/

    int                 type;       /* 插口类型，如SOCK_STREAM */

    int                 backlog;    /* listen()的第二个参数，NGX_LISTEN_BACKLOG=511 */
    int                 rcvbuf;     /* 插口的收发缓存 */
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    ngx_connection_handler_pt   handler; /* 插口处理句柄ngx_http_init_connection() */

    void               *servers;         /* ngx_http_port_t数组，此链路对应的server；
                                            有可能一条链路对应多个server{}配置，如果
                                            一个server{listen 80;}，另一个server{
                                            listen 1.1.1.1:80;}，则只建立监听链路
                                            *:80 */
    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;     /* accept后，等待客户端请求数据的
                                                    超时时限 */
    ngx_listening_t    *previous;
    ngx_connection_t   *connection;              /* 监听到的请求连接 */

    ngx_uint_t          worker;

    unsigned            open:1;
    unsigned            remain:1;
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;      /* 是否调用了listen()，处于监听状态 */
    unsigned            nonblocking:1; /* */
    unsigned            shared:1;      /* shared between threads or processes */
    unsigned            addr_ntop:1;   /* 是否需要转换地址到可读格式，=1, 则赋值addr_text */
    unsigned            wildcard:1;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:1;
#endif
#if (NGX_HAVE_REUSEPORT)
    unsigned            reuseport:1;      /* 是否支持端口重用 */
    unsigned            add_reuseport:1;
#endif
    unsigned            keepalive:2;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter; /* 是否支持SO_ACCEPTFILTER, 字符过滤 */
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;     /* 是否支持TCP_FASTOPEN, 即三次握手时
                                         也用来传递数据*/
#endif

};


typedef enum {
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02


struct ngx_connection_s {
    void               *data;   /* 空闲时, 作为单链表指针的next;
                                   建立链接后, 指向具体协议, ngx_http_connection_t;
                                   接收到数据后, 指向请求, ngx_http_request_t;
                                 */
    ngx_event_t        *read;   /* 读事件，对应ngx_cycle->read_events[] */
    ngx_event_t        *write;  /* 写事件，对应ngx_cycle->write_events[] 
                                     索引和本结构在ngx_cycle->connections[]
                                     中的索引一致, 初始化时建立的对应关系 */
    ngx_socket_t        fd;     /* 插口描述符 */

    ngx_recv_pt         recv;   
    ngx_send_pt         send;
    ngx_recv_chain_pt   recv_chain;
    ngx_send_chain_pt   send_chain;  /* 对应的接收/发送函数；分别设置为
                                        ngx_recv/ngx_send
                                        ngx_recv_chain/ngx_send_chain*/

    ngx_listening_t    *listening;   /* 指向对应的监听链路信息结构 */

    off_t               sent;

    ngx_log_t          *log;

    ngx_pool_t         *pool;

    int                 type;

    struct sockaddr    *sockaddr;        /* 对端IP+PORT信息 */
    socklen_t           socklen;
    ngx_str_t           addr_text;

    ngx_str_t           proxy_protocol_addr;
    in_port_t           proxy_protocol_port;

#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

    struct sockaddr    *local_sockaddr;  /* 本连接绑定的本机地址 */
    socklen_t           local_socklen;

    ngx_buf_t          *buffer;          /* 请求报文缓存 */

    ngx_queue_t         queue;

    ngx_atomic_uint_t   number;          /* 本结构对应的请求index，从1开始的实时计数值 */

    ngx_uint_t          requests;        /* 本结构处理的总请求数，调试用？？？ */

    unsigned            buffered:8;

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            timedout:1;      /* 请求连接超时标志 */
    unsigned            error:1;
    unsigned            destroyed:1;

    unsigned            idle:1;
    unsigned            reusable:1;      /* 是否可重用? 设置了此标志, 此链接被
                                            放置到特定队列, 如果此时请求过
                                            多, 没有可用的空闲连接, 则释放
                                            打上此标记的连接, 达到重用的目
                                            的; 此处特定队列指ngx_cycle->
                                            reusable_connections_queue */
    unsigned            close:1;         /* 链接断开标志 */
    unsigned            shared:1;

    unsigned            sendfile:1;
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_conf_t *cf, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
