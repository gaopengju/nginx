
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_SCRIPT_H_INCLUDED_
#define _NGX_HTTP_SCRIPT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* 脚本引擎执行时所需的堆栈, 后进先出, 用于保存中间的变量等信息 */
typedef struct {
    u_char                     *ip;           /* 当前脚本的回调指针 */
    u_char                     *pos;          /* 当前的解析结果，指向->buf的某个位置 */
    ngx_http_variable_value_t  *sp;           /* 栈顶指针, 临时保存变量值, 用于在
                                                 脚本之间传递数据 */
    ngx_str_t                   buf;          /* 变量值的结果内存 */
    ngx_str_t                   line;

    /* the start of the rewritten arguments */
    u_char                     *args;         /* 参数的位置，=当前的pos */

    unsigned                    flushed:1;    /* 是否已清空非可缓存的变量值 */
    unsigned                    skip:1;
    unsigned                    quote:1;
    unsigned                    is_args:1;    /* 当前为参数 */
    unsigned                    log:1;

    ngx_int_t                   status;
    ngx_http_request_t         *request;      /* 对应的客户端请求 */
} ngx_http_script_engine_t;


typedef struct {
    ngx_conf_t                 *cf;              /* 配置信息 */
    ngx_str_t                  *source;          /* 待解析字符串 */

    ngx_array_t               **flushes;         /* 变量对应的索引(对应ngx_http_core_main_conf_t->variables[]下标)数组 */
    ngx_array_t               **lengths;         /* 获取变量长度的脚本数组 */
    ngx_array_t               **values;          /* 获取变量值的脚本数组 */

    ngx_uint_t                  variables;       /* source字符串的变量个数 */
    ngx_uint_t                  ncaptures;       /* 最大的捕捉变量索引值 */
    ngx_uint_t                  captures_mask;   /* 捕捉变量索引掩码，bit位 */
    ngx_uint_t                  size;            /* */

    void                       *main;            /* NULL */

    unsigned                    compile_args:1;  /* 0, 是否编译参数 */
    unsigned                    complete_lengths:1;   /* 1 */
    unsigned                    complete_values:1;    /* 1 */
    unsigned                    zero:1;               /* 0, 脚本是否需要以NULL结尾 */
    unsigned                    conf_prefix:1;        /* 0 */
    unsigned                    root_prefix:1;        /* 0 */

    unsigned                    dup_capture:1;   /* 是否有重复的捕捉变量 */
    unsigned                    args:1;          /* 0, 是否解析参数 */
} ngx_http_script_compile_t;

/* 字符串编译的结果，包括各种脚本 */
typedef struct {
    ngx_str_t                   value;           /* 原始字符串，或简单值 */
    ngx_uint_t                 *flushes;         /* 存储普通变量的索引(对应ngx_http_core_main_conf_t->variables[]下标) */
    void                       *lengths;         /* 存储获取变量值长度的脚本 */
    void                       *values;          /* 存储获取变量值的脚本 */
} ngx_http_complex_value_t;


typedef struct {
    ngx_conf_t                 *cf;
    ngx_str_t                  *value;           /* 待解析编译的字符串 */
    ngx_http_complex_value_t   *complex_value;   /* 解析编译结果 */

    unsigned                    zero:1;
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;
} ngx_http_compile_complex_value_t;


typedef void (*ngx_http_script_code_pt) (ngx_http_script_engine_t *e);
typedef size_t (*ngx_http_script_len_code_pt) (ngx_http_script_engine_t *e);


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   len;
} ngx_http_script_copy_code_t;

/* 简单脚本引擎的结构, 对应"set $var value;"的配置语法对应请求变量赋值的过程 */
typedef struct {
    ngx_http_script_code_pt     code;  /* 把压栈的变量值出栈的函数, 默认为
                                            ngx_http_script_set_var_code()*/
    uintptr_t                   index; /* 变量在ngx_http_core_main_conf_t->variables[]的索引 */
} ngx_http_script_var_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    ngx_http_set_variable_pt    handler;
    uintptr_t                   data;
} ngx_http_script_var_handler_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   n;     /* 捕捉变量的索引 * 2; 2和PCRE相关 */
} ngx_http_script_copy_capture_code_t;


#if (NGX_PCRE)

typedef struct {
    ngx_http_script_code_pt     code;
    ngx_http_regex_t           *regex;
    ngx_array_t                *lengths;
    uintptr_t                   size;
    uintptr_t                   status;
    uintptr_t                   next;

    uintptr_t                   test:1;
    uintptr_t                   negative_test:1;
    uintptr_t                   uri:1;
    uintptr_t                   args:1;

    /* add the r->args to the new arguments */
    uintptr_t                   add_args:1;

    uintptr_t                   redirect:1;
    uintptr_t                   break_cycle:1;

    ngx_str_t                   name;
} ngx_http_script_regex_code_t;


typedef struct {
    ngx_http_script_code_pt     code;

    uintptr_t                   uri:1;
    uintptr_t                   args:1;

    /* add the r->args to the new arguments */
    uintptr_t                   add_args:1;

    uintptr_t                   redirect:1;
} ngx_http_script_regex_end_code_t;

#endif


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   conf_prefix;
} ngx_http_script_full_name_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   status;
    ngx_http_complex_value_t    text;
} ngx_http_script_return_code_t;


typedef enum {
    ngx_http_script_file_plain = 0,
    ngx_http_script_file_not_plain,
    ngx_http_script_file_dir,
    ngx_http_script_file_not_dir,
    ngx_http_script_file_exists,
    ngx_http_script_file_not_exists,
    ngx_http_script_file_exec,
    ngx_http_script_file_not_exec
} ngx_http_script_file_op_e;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   op;
} ngx_http_script_file_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   next;
    void                      **loc_conf;
} ngx_http_script_if_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    ngx_array_t                *lengths;
} ngx_http_script_complex_value_code_t;

/* 简单脚本引擎的结构, 对应"set $var value;"的配置语法对应获取(变量)值的过程 */
typedef struct {
    ngx_http_script_code_pt     code;        /* 变量值压栈函数，ngx_http_script_value_code() */
    uintptr_t                   value;       /* 变量值的atoi()结果，具体的数值或0-对应atoi()失败 */
    uintptr_t                   text_len;    /* 原变量值的字符串形式 */
    uintptr_t                   text_data;
} ngx_http_script_value_code_t;


void ngx_http_script_flush_complex_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *val);
ngx_int_t ngx_http_complex_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *val, ngx_str_t *value);
ngx_int_t ngx_http_compile_complex_value(ngx_http_compile_complex_value_t *ccv);
char *ngx_http_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


ngx_int_t ngx_http_test_predicates(ngx_http_request_t *r,
    ngx_array_t *predicates);
char *ngx_http_set_predicate_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

ngx_uint_t ngx_http_script_variables_count(ngx_str_t *value);
ngx_int_t ngx_http_script_compile(ngx_http_script_compile_t *sc);
u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void ngx_http_script_flush_no_cacheable_variables(ngx_http_request_t *r,
    ngx_array_t *indices);

void *ngx_http_script_start_code(ngx_pool_t *pool, ngx_array_t **codes,
    size_t size);
void *ngx_http_script_add_code(ngx_array_t *codes, size_t size, void *code);

size_t ngx_http_script_copy_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_var_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_var_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_capture_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_capture_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_mark_args_code(ngx_http_script_engine_t *e);
void ngx_http_script_start_args_code(ngx_http_script_engine_t *e);
#if (NGX_PCRE)
void ngx_http_script_regex_start_code(ngx_http_script_engine_t *e);
void ngx_http_script_regex_end_code(ngx_http_script_engine_t *e);
#endif
void ngx_http_script_return_code(ngx_http_script_engine_t *e);
void ngx_http_script_break_code(ngx_http_script_engine_t *e);
void ngx_http_script_if_code(ngx_http_script_engine_t *e);
void ngx_http_script_equal_code(ngx_http_script_engine_t *e);
void ngx_http_script_not_equal_code(ngx_http_script_engine_t *e);
void ngx_http_script_file_code(ngx_http_script_engine_t *e);
void ngx_http_script_complex_value_code(ngx_http_script_engine_t *e);
void ngx_http_script_value_code(ngx_http_script_engine_t *e);
void ngx_http_script_set_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_var_set_handler_code(ngx_http_script_engine_t *e);
void ngx_http_script_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_nop_code(ngx_http_script_engine_t *e);


#endif /* _NGX_HTTP_SCRIPT_H_INCLUDED_ */
