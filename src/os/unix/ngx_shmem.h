
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/* 共享内存的描述结构 */
typedef struct {
    u_char      *addr;     /* 起始地址，一般为管理机制slab的结构，ngx_slab_pool_t */
    size_t       size;     /* 大小 */
    ngx_str_t    name;     /* 共享内存名称，做为唯一标识 */
    ngx_log_t   *log;      /* 日志 */
    ngx_uint_t   exists;   /* unsigned  exists:1;  */
} ngx_shm_t;


ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
void ngx_shm_free(ngx_shm_t *shm);


#endif /* _NGX_SHMEM_H_INCLUDED_ */
