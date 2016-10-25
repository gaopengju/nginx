
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_atomic_t   lock;               /* 加锁时，存放ngx_pid，即加锁的进程pid；
                                          以此来区分锁标识，实现互斥锁；解锁时
                                          为0 */
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t   wait;
#endif
} ngx_shmtx_sh_t;


typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    ngx_atomic_t  *lock;               /* 对应ngx_shmtx_sh_t->lock */
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t  *wait;               /* 对应ngx_shmtx_sh_t->wait */
    ngx_uint_t     semaphore;          /* 0/1, 是否支持信号量 */
    sem_t          sem;
#endif
#else
    ngx_fd_t       fd;
    u_char        *name;
#endif
    ngx_uint_t     spin;               /* 加锁失败后，自旋次数，默认值2048; 
                                          超过此值后，本进程讲让出cpu等待下
                                          次唤醒再执行时继续申请加锁 */
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
    u_char *name);
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
