
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_SSL_H_INCLUDED_
#define _NGX_HTTP_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t                      enable;   /* 此HTTP域名是否使能SSL, 对应指令"ssl on/off" */

    ngx_ssl_t                       ssl;      /* 创建的SSL环境，依次创建SSL对象 */

    ngx_flag_t                      prefer_server_ciphers;  /* 优先选用服务器设定的套件，对应指令“ssl_prefer_server_ciphers on | off;” */

    ngx_uint_t                      protocols;        /* 支持的SSL版本掩码, ngx_http_ssl_protocols[], 对应指令“ssl_protocols SSLv2 TLSv1.2;” */

    ngx_uint_t                      verify;           /* 支持验证客户端，对应指令"ssl_verify_client on | off | optional | optional_no_ca;" */
    ngx_uint_t                      verify_depth;     /* 验证客户端证书链深度，对应指令“ssl_verify_depth number;” */

    size_t                          buffer_size;      /* 发送数据的buff大小，对应指令“ssl_buffer_size 16k;” */

    ssize_t                         builtin_session_cache;  /* worker本地会话缓存的大小，对应指令"ssl_session_cache builtin[:size];" */

    time_t                          session_timeout;  /* 会话超时，对应指令“ssl_session_timeout time;” */

    ngx_array_t                    *certificates;     /* 存储服务端公钥文件名，对应指令ssl_certificate */
    ngx_array_t                    *certificate_keys; /* 存储服务端私钥文件名，对应指令ssl_certificate_key */

    ngx_str_t                       dhparam;          /* DHE密钥磋商算法的DH parameters，对应指令“ssl_dhparam file” */
    ngx_str_t                       ecdh_curve;       /* 为ECDHE ciphers套件指定曲綫，对应指令“ssl_ecdh_curve prime256v1:secp384r1;” */
    ngx_str_t                       client_certificate;  /* 认证客户端的可信任CA，将发送给客户端，对应指令“ssl_client_certificate file;” */
    ngx_str_t                       trusted_certificate; /* 功能等同于client_certificate，但不发送给客户端，对应指令“ssl_trusted_certificate file;” */
    ngx_str_t                       crl;              /* 包含CRL的文件，对应指令“ssl_crl file;” */

    ngx_str_t                       ciphers;          /* 保存使能的套件，对应指令“ssl_ciphers ciphers;” */

    ngx_array_t                    *passwords;        /* 加载私钥文件时需要的密码数组，对应指令ssl_password_file */

    ngx_shm_zone_t                 *shm_zone;         /* 各worker共享的会话缓存大小，对应指令"ssl_session_cache shared:name:size;" */

    ngx_flag_t                      session_tickets;     /* 对应指令"ssl_session_tickets on | off;" */
    ngx_array_t                    *session_ticket_keys; /* 对应指令“ssl_session_ticket_key file;” */

    ngx_flag_t                      stapling;
    ngx_flag_t                      stapling_verify;
    ngx_str_t                       stapling_file;
    ngx_str_t                       stapling_responder;

    u_char                         *file;
    ngx_uint_t                      line;
} ngx_http_ssl_srv_conf_t;


extern ngx_module_t  ngx_http_ssl_module;


#endif /* _NGX_HTTP_SSL_H_INCLUDED_ */
