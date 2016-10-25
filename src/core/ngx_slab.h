
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/* slab机制的页管理结构 */
typedef struct ngx_slab_page_s  ngx_slab_page_t;
struct ngx_slab_page_s {
    uintptr_t         slab;               /* 空闲内存块儿的连续页数；如果被占用，
                                             则 = 连续页数|NGX_SLAB_PAGE_START */
    ngx_slab_page_t  *next;               /* 下个内存块儿地址 */
    uintptr_t         prev;               /* 上一个内存块儿地址 */
};

/* 共享内存的slab管理机制 */
typedef struct {
    ngx_shmtx_sh_t    lock;              /* 实现原子锁的信息结构，=0/ngx_pid */

    size_t            min_size;          /* 最小划分块儿大小，8 */
    size_t            min_shift;         /* log2(min_size) */

    ngx_slab_page_t  *pages;             /* 首个页表管理结构的起始地址 */
    ngx_slab_page_t  *last;              /* 尾端页表管理结构的起始地址 */
    ngx_slab_page_t   free;              /* 空闲页链表头，dummy，用来表征起始、结束点 */

    u_char           *start;             /* slab管理中，存储数据的页开始地址 */
    u_char           *end;               /* 共享内存结束地址 */

    ngx_shmtx_t       mutex;             /* 互斥锁，可利用原子锁或文件锁机制 */

    u_char           *log_ctx;
    u_char            zero;              /* ='\0'，0的ascii值 */

    unsigned          log_nomem:1;       /* =1 */

    void             *data;              /* 具体业务模块儿的特定数据结构指针 */
    void             *addr;              /* 对应的共享内存起始地址 */
} ngx_slab_pool_t;


void ngx_slab_init(ngx_slab_pool_t *pool);
void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size);
void ngx_slab_free(ngx_slab_pool_t *pool, void *p);
void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);


#endif /* _NGX_SLAB_H_INCLUDED_ */
