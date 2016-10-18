
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_VARIABLES_H_INCLUDED_
#define _NGX_HTTP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_variable_value_t  ngx_http_variable_value_t;

#define ngx_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_http_variable_s  ngx_http_variable_t;

typedef void (*ngx_http_set_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_http_get_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


#define NGX_HTTP_VAR_CHANGEABLE   1   /* 变量是否可重复添加，后续值覆盖前值 */
#define NGX_HTTP_VAR_NOCACHEABLE  2   /* 变量不可缓存，此时每次获取变量值都重新计算，如uri */
#define NGX_HTTP_VAR_INDEXED      4   /* 变量被配置文件引用 */
#define NGX_HTTP_VAR_NOHASH       8   /**/

/* 变量名的描述结果；变量值结构定义在~/src/core/ngx_string.h；
   变量名和变量值分开的好处是节省内存，如多个变量，可能只需要一个变量名，多个变量值 */
struct ngx_http_variable_s {
    ngx_str_t                     name;   /* 变量名字符串 */
    ngx_http_set_variable_pt      set_handler;   /* 组成脚本引擎的一部分, 在处理请求过程中
                                                    动态更新对应的变量值; 带有此接口的
                                                    变量都是_CHANGEABLE + _NOCACHEABLE */
    ngx_http_get_variable_pt      get_handler;   /* 获取变量值的回调函数, 通过其屏蔽简单的
                                                    "直接的情况"和复杂的"间接的情况"之
                                                     间的差异 */
    uintptr_t                     data;   /* 此值一般作为->set_handler/get_handler
                                             函数的第三个参数, 在"直接的情况"下
                                             用于指定变量在请求头中的偏移, 以便
                                             回调函数操作(修改/读取)存放变量值的地方 */
    ngx_uint_t                    flags;  /* 变量标识，NGX_HTTP_VAR_* */
    ngx_uint_t                    index;  /* 被配置文件引用，对应ngx_http_core_main_conf_t->variables[]索引 */
};


ngx_http_variable_t *ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);
ngx_int_t ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_http_variable_value_t *ngx_http_get_indexed_variable(ngx_http_request_t *r,
    ngx_uint_t index);
ngx_http_variable_value_t *ngx_http_get_flushed_variable(ngx_http_request_t *r,
    ngx_uint_t index);

ngx_http_variable_value_t *ngx_http_get_variable(ngx_http_request_t *r,
    ngx_str_t *name, ngx_uint_t key);

ngx_int_t ngx_http_variable_unknown_header(ngx_http_variable_value_t *v,
    ngx_str_t *var, ngx_list_part_t *part, size_t prefix);


#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                    capture;
    ngx_int_t                     index;
} ngx_http_regex_variable_t;


typedef struct {
    ngx_regex_t                  *regex;
    ngx_uint_t                    ncaptures;
    ngx_http_regex_variable_t    *variables;
    ngx_uint_t                    nvariables;
    ngx_str_t                     name;
} ngx_http_regex_t;


typedef struct {
    ngx_http_regex_t             *regex;
    void                         *value;
} ngx_http_map_regex_t;


ngx_http_regex_t *ngx_http_regex_compile(ngx_conf_t *cf,
    ngx_regex_compile_t *rc);
ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re,
    ngx_str_t *s);

#endif


typedef struct {
    ngx_hash_combined_t           hash;
#if (NGX_PCRE)
    ngx_http_map_regex_t         *regex;
    ngx_uint_t                    nregex;
#endif
} ngx_http_map_t;


void *ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map,
    ngx_str_t *match);


ngx_int_t ngx_http_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_http_variables_init_vars(ngx_conf_t *cf);


extern ngx_http_variable_value_t  ngx_http_variable_null_value;
extern ngx_http_variable_value_t  ngx_http_variable_true_value;


#endif /* _NGX_HTTP_VARIABLES_H_INCLUDED_ */
