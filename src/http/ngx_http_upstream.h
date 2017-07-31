
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000400
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00000800
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00001000
#define NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00002000
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    ngx_msec_t                       bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;
    ngx_msec_t                       response_time;  /* 从开始连接到接收到响应耗时 */
    ngx_msec_t                       connect_time;   /* 连接耗时 */
    ngx_msec_t                       header_time;
    off_t                            response_length;

    ngx_str_t                       *peer;     /* 对端服务器名 */
} ngx_http_upstream_state_t;

/* http层配置环境中，承载所有upstream name的配置信息 */
typedef struct {
    ngx_hash_t headers_in_hash;  /* upstream支持的http头哈希表, 
                                        ngx_http_upstream_headers_in[] */
    ngx_array_t upstreams;       /* 对应upstream指令的配置信息, 
                                        ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);

/* 承载upstream{ip_hash;}等配置信息，构建LB负载 */
typedef struct {
    ngx_http_upstream_init_pt        init_upstream;  /* LB策略环境初始化函数, 分配内存等
                                                        ip_hash: ngx_http_upstream_init_ip_hash()
                                                        upstream{keepalive}: ngx_http_upstream_init_keepalive()
                                                      */
    ngx_http_upstream_init_peer_pt   init;           /* 处理客户请求前调用, 初始化LB计算环境
                                                        ip_hash: ngx_http_upstream_init_ip_hash_peer()
                                                        upstream{keepalive}: ngx_http_upstream_init_keepalive_peer()
                                                      */
    void                            *data;           /* LB策略需要的信息
                                                        RR: ngx_http_upstream_rr_peers_t */
} ngx_http_upstream_peer_t;

/* 承载upstream{server xxx;}配置指令的解析结果，存储
   在 struct ngx_http_upstream_srv_conf_s->servers[] */
typedef struct {
    ngx_str_t                        name;         /* 原始配置中, "域名:port"/"ip:port" */
    ngx_addr_t                      *addrs;        /* 服务器对应的地址 */
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;       /* 权重, 默认值1 */
    ngx_uint_t                       max_fails;    /* 参考时间内允许的最大失败次数, 默认值1 */
    time_t                           fail_timeout; /* 参考时间, 默认值10 */

    unsigned                         down:1;       /* 是否为备用设备?(一般不处理用户请求, 
                                                      当所有非备机不能提供服务时，才
                                                      启用) */
    unsigned                         backup:1;     /* 是否宕机? */
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020

/* 承载upstream name{}配置解析, upstream层级配置->srv_conf[ngx_http_upstream_module.ctx_index]的值 */
struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;     /* 构建LB算法所用，如IP HASH/RR等 */
    void                           **srv_conf; /* 构建****配置结构，回指upstream层级配置环境->srv_conf[] */

    ngx_array_t                     *servers;  /* 承载server配置指令解析结果, ngx_http_upstream_server_t */

    ngx_uint_t                       flags;    /* */
    ngx_str_t                        host;     /* 对应upstream的name */
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;     /* =0 */
    in_port_t                        default_port;
    ngx_uint_t                       no_port;  /* =1, unsigned no_port:1 */

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_shm_zone_t                  *shm_zone;
#endif
};


typedef struct {
    ngx_addr_t                      *addr;
    ngx_http_complex_value_t        *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_http_upstream_local_t;


typedef struct {
    ngx_http_upstream_srv_conf_t    *upstream;    /* 对应的upstream{}配置 */

    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       timeout;
    ngx_msec_t                       next_upstream_timeout;

    size_t                           send_lowat;
    size_t                           buffer_size;
    size_t                           limit_rate;

    size_t                           busy_buffers_size;
    size_t                           max_temp_file_size;
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    ngx_bufs_t                       bufs;

    ngx_uint_t                       ignore_headers;
    ngx_uint_t                       next_upstream;
    ngx_uint_t                       store_access;
    ngx_uint_t                       next_upstream_tries;
    ngx_flag_t                       buffering;
    ngx_flag_t                       request_buffering;
    ngx_flag_t                       pass_request_headers;
    ngx_flag_t                       pass_request_body;

    ngx_flag_t                       ignore_client_abort;
    ngx_flag_t                       intercept_errors;
    ngx_flag_t                       cyclic_temp_file;
    ngx_flag_t                       force_ranges;

    ngx_path_t                      *temp_path;

    ngx_hash_t                       hide_headers_hash;
    ngx_array_t                     *hide_headers;
    ngx_array_t                     *pass_headers;

    ngx_http_upstream_local_t       *local;           /* */

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache_zone;
    ngx_http_complex_value_t        *cache_value;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    ngx_flag_t                       cache_lock;
    ngx_msec_t                       cache_lock_timeout;
    ngx_msec_t                       cache_lock_age;

    ngx_flag_t                       cache_revalidate;
    ngx_flag_t                       cache_convert_head;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *no_cache;
#endif

    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

#if (NGX_HTTP_CACHE)
    signed                           cache:2;
#endif
    signed                           store:2;
    unsigned                         intercept_404:1;
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL)
    ngx_ssl_t                       *ssl;               /* SSL环境 */
    ngx_flag_t                       ssl_session_reuse; /* 配置指令"proxy_ssl_session_reuse on | off;"
                                                           0/1, SSL会话恢复 */

    ngx_http_complex_value_t        *ssl_name;          /* 配置指令“proxy_ssl_name host from proxy_pass;”
                                                           用于验证服务器端证书的服务器名 */
    ngx_flag_t                       ssl_server_name;   /* “proxy_ssl_server_name on | off;” 
                                                           建立连接时，是否通过拓展属性传递服务器名 */
    ngx_flag_t                       ssl_verify;        /* "proxy_ssl_verify on | off;"
                                                           是否验证upstream服务器证书 */
#endif

    ngx_str_t                        module;    /* ="proxy" */
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;
    ngx_table_elt_t                 *vary;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    ngx_array_t                      cache_control;
    ngx_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    ngx_resolver_addr_t             *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);

/* 维护upstream信息, struct ngx_http_request_t->upstream */
struct ngx_http_upstream_s {
    ngx_http_upstream_handler_pt     read_event_handler;
                                        /* proxy_pass: ngx_http_upstream_process_header() */
    ngx_http_upstream_handler_pt     write_event_handler;
                                        /* proxy_pass: ngx_http_upstream_send_request_handler() */
    ngx_peer_connection_t            peer;         /* 选定的服务器信息，如地址、底层链路等 */

    ngx_event_pipe_t                *pipe;         /* 支持缓存的情况下，维护downstream、upstream之间的关联 */

    ngx_chain_t                     *request_bufs; /* 维护发往upstream的报文内存, = ngx_http_request_t->request_body->bufs*/

    ngx_output_chain_ctx_t           output;       /* 输出信息 */
    ngx_chain_writer_ctx_t           writer;

    ngx_http_upstream_conf_t        *conf;         /* 对应的upstream配置相关信息, 
                                                      ngx_http_proxy_loc_conf_t->upstream */
#if (NGX_HTTP_CACHE)
    ngx_array_t                     *caches;
#endif

    ngx_http_upstream_headers_in_t   headers_in;   /* 从upstream应答的报文HTTP属性头 */

    ngx_http_upstream_resolved_t    *resolved;

    ngx_buf_t                        from_client;

    ngx_buf_t                        buffer;       /* 接收upstream应答的缓存 */
    off_t                            length;

    ngx_chain_t                     *out_bufs;
    ngx_chain_t                     *busy_bufs;
    ngx_chain_t                     *free_bufs;

    ngx_int_t (*input_filter_init)(void *data); /* ngx_http_proxy_input_filter_init() */
    ngx_int_t (*input_filter)(void *data, ssize_t bytes); /* ngx_http_proxy_non_buffered_copy_filter() */
    void      *input_filter_ctx;  /* ngx_http_request_t */

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
    ngx_int_t   (*create_request)(ngx_http_request_t *r);
                                     /* 创建请求，proxy_pass: ngx_http_proxy_create_request() */
    ngx_int_t   (*reinit_request)(ngx_http_request_t *r);
                                     /* proxy_pass: ngx_http_proxy_reinit_request() */
    ngx_int_t   (*process_header)(ngx_http_request_t *r);
                                     /* 处理回应报文，proxy_pass: ngx_http_proxy_process_status_line() */
    void        (*abort_request)(ngx_http_request_t *r);
                                     /* proxy_pass: ngx_http_proxy_abort_request() */
    void        (*finalize_request)(ngx_http_request_t *r, ngx_int_t rc);
                                     /* 结束处理，proxy_pass: ngx_http_proxy_finalize_request() */
    ngx_int_t   (*rewrite_redirect)(ngx_http_request_t *r, ngx_table_elt_t *h, size_t prefix);
                                     /* proxy_redirect: ngx_http_proxy_rewrite_redirect() */
    ngx_int_t   (*rewrite_cookie)(ngx_http_request_t *r, ngx_table_elt_t *h);
                                     /* proxy_cookie_path/proxy_cookie_domain: ngx_http_proxy_rewrite_cookie() */

    ngx_msec_t                       timeout;

    ngx_http_upstream_state_t       *state;        /* 统计信息 */

    ngx_str_t                        method;
    ngx_str_t                        schema;       /* "http://"或"https://" */
    ngx_str_t                        uri;

#if (NGX_HTTP_SSL)
    ngx_str_t                        ssl_name;
#endif

    ngx_http_cleanup_pt             *cleanup;      /* 清理句柄, */

    unsigned                         store:1;
    unsigned                         cacheable:1;
    unsigned                         accel:1;      /* =1 */
    unsigned                         ssl:1;        /* 是否为SSL */
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    unsigned                         buffering:1;  /**/
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;

    unsigned                         request_sent:1;      /* 已发送请求到upstream */
    unsigned                         request_body_sent:1;
    unsigned                         header_sent:1;       /* 已发送报文头到downstream */
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


ngx_int_t ngx_http_upstream_cookie_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t ngx_http_upstream_header_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
