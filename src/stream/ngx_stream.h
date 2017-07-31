
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_H_INCLUDED_
#define _NGX_STREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_STREAM_SSL)
#include <ngx_stream_ssl_module.h>
#endif


typedef struct ngx_stream_session_s  ngx_stream_session_t;


#include <ngx_stream_variables.h>
#include <ngx_stream_script.h>
#include <ngx_stream_upstream.h>
#include <ngx_stream_upstream_round_robin.h>


/* 对比7层代理配置信息 ngx_http_conf_ctx_t, 少了loc_conf，因为四层代理
   没有location的概念 */
typedef struct {
    void                         **main_conf;   /* upstream{}层级配置 */
    void                         **srv_conf;    /* server{}层级配置 */
} ngx_stream_conf_ctx_t;

/* stream{server{listen}}解析结果 */
typedef struct {
    ngx_sockaddr_t                 sockaddr;  /* 监听地址 */
    socklen_t                      socklen;

    /* server ctx */
    ngx_stream_conf_ctx_t         *ctx;       /* 对应的server{}层级配置 */

    unsigned                       bind:1;    /* */
    unsigned                       wildcard:1;
#if (NGX_STREAM_SSL)
    unsigned                       ssl:1;     /* 是否为SSL */
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                       ipv6only:1;
#endif
#if (NGX_HAVE_REUSEPORT)
    unsigned                       reuseport:1;
#endif
    unsigned                       so_keepalive:2; /* 1/2, on/off */
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                            tcp_keepidle;
    int                            tcp_keepintvl;
    int                            tcp_keepcnt;
#endif
    int                            backlog;
    int                            type;      /* SOCK_DGRAM */
} ngx_stream_listen_t;


typedef struct {
    ngx_stream_conf_ctx_t         *ctx;
    ngx_str_t                      addr_text;
#if (NGX_STREAM_SSL)
    ngx_uint_t                     ssl;    /* unsigned   ssl:1; */
#endif
} ngx_stream_addr_conf_t;

typedef struct {
    in_addr_t                      addr;
    ngx_stream_addr_conf_t         conf;
} ngx_stream_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr                addr6;
    ngx_stream_addr_conf_t         conf;
} ngx_stream_in6_addr_t;

#endif


typedef struct {
    /* ngx_stream_in_addr_t or ngx_stream_in6_addr_t */
    void                          *addrs;
    ngx_uint_t                     naddrs;
} ngx_stream_port_t;


typedef struct {
    int                            family;
    int                            type;
    in_port_t                      port;
    ngx_array_t                    addrs; /* array of ngx_stream_conf_addr_t */
} ngx_stream_conf_port_t;


typedef struct {
    ngx_stream_listen_t            opt;
} ngx_stream_conf_addr_t;


typedef ngx_int_t (*ngx_stream_access_pt)(ngx_stream_session_t *s);

/* 四层代理的顶层信息结构 */
typedef struct {
    ngx_array_t servers;     /* 所有server{}配置解析结果, ngx_stream_core_srv_conf_t */
    ngx_array_t listen;      /* server{listen}配置解析结果, ngx_stream_listen_t */

    ngx_stream_access_pt  limit_conn_handler;
    ngx_stream_access_pt  access_handler;

    /* 后续为变量相关 */
    ngx_hash_t  variables_hash;
    ngx_array_t variables;   /* ngx_stream_variable_t */
    ngx_uint_t  ncaptures;

    ngx_uint_t  variables_hash_max_size;
    ngx_uint_t  variables_hash_bucket_size;

    ngx_hash_keys_arrays_t *variables_keys; /* 包括 ngx_stream_core_variables[] */
} ngx_stream_core_main_conf_t;


typedef void (*ngx_stream_handler_pt)(ngx_stream_session_t *s);

/* stream{server{}}配置解析 */
typedef struct {
    ngx_stream_handler_pt          handler;    /* proxy_pass: ngx_stream_proxy_handler() */

    ngx_stream_conf_ctx_t         *ctx;        /* 配置环境上下文层级结构 */

    u_char                        *file_name;
    ngx_int_t                      line;

    ngx_flag_t                     tcp_nodelay;/* 配置指令“tcp_nodelay on/off” */

    ngx_log_t                     *error_log;
} ngx_stream_core_srv_conf_t;


/* 对应stream流信息 */
struct ngx_stream_session_s {
    uint32_t  signature;         /* NGX_STREAM_MODULE, "STRM" */

    ngx_connection_t *connection;/* downstream底层链路 */

    off_t  received;

    ngx_log_handler_pt log_handler;

    void   **ctx;                /* 对应的配置环境上下文 */
    void   **main_conf;
    void   **srv_conf;

    ngx_stream_upstream_t *upstream;          /* 对应的upstream信息 */

    ngx_stream_variable_value_t   *variables; /* 可读取的变量 */

#if (NGX_PCRE)
    ngx_uint_t  ncaptures;
    int         *captures;
    u_char      *captures_data;
#endif
};


typedef struct {
    ngx_int_t                    (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t                    (*postconfiguration)(ngx_conf_t *cf);

    void                        *(*create_main_conf)(ngx_conf_t *cf);
    char                        *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                        *(*create_srv_conf)(ngx_conf_t *cf);
    char                        *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                                   void *conf);
} ngx_stream_module_t;


#define NGX_STREAM_MODULE       0x4d525453     /* 新添加的四层代理模块儿，"STRM" */

#define NGX_STREAM_MAIN_CONF    0x02000000
#define NGX_STREAM_SRV_CONF     0x04000000
#define NGX_STREAM_UPS_CONF     0x08000000


#define NGX_STREAM_MAIN_CONF_OFFSET  offsetof(ngx_stream_conf_ctx_t, main_conf)
#define NGX_STREAM_SRV_CONF_OFFSET   offsetof(ngx_stream_conf_ctx_t, srv_conf)


#define ngx_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define ngx_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define ngx_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


#define ngx_stream_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_stream_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

#define ngx_stream_conf_get_module_main_conf(cf, module)                       \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_stream_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define ngx_stream_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[ngx_stream_module.index] ?                                \
        ((ngx_stream_conf_ctx_t *) cycle->conf_ctx[ngx_stream_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)


void ngx_stream_init_connection(ngx_connection_t *c);
void ngx_stream_close_connection(ngx_connection_t *c);


extern ngx_module_t  ngx_stream_module;
extern ngx_uint_t    ngx_stream_max_module;
extern ngx_module_t  ngx_stream_core_module;


#endif /* _NGX_STREAM_H_INCLUDED_ */
