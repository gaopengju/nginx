
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

/* 单个PEER服务器信息 */
typedef struct ngx_stream_upstream_rr_peer_s   ngx_stream_upstream_rr_peer_t;
struct ngx_stream_upstream_rr_peer_s {
    struct sockaddr *sockaddr;        /* 服务器地址 */
    socklen_t       socklen;
    ngx_str_t       name;             /* IP文本 */
    ngx_str_t       server;           /* 服务器域名 */

    ngx_int_t       current_weight;
    ngx_int_t       effective_weight;
    ngx_int_t       weight;           /* 配置权重 */

    ngx_uint_t      conns;            /* 链路计数 */

    ngx_uint_t      fails;
    time_t          accessed;
    time_t          checked;

    ngx_uint_t      max_fails;        /* 配置 */
    time_t          fail_timeout;

    ngx_uint_t      down;         /* unsigned  down:1; */

#if (NGX_STREAM_SSL)
    void            *ssl_session;
    int             ssl_session_len;
#endif

    ngx_stream_upstream_rr_peer_t   *next;

#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_atomic_t                     lock;
#endif
};

/* 加权RR数据结构 */
typedef struct ngx_stream_upstream_rr_peers_s  ngx_stream_upstream_rr_peers_t;
struct ngx_stream_upstream_rr_peers_s {
    ngx_uint_t                       number;       /* 服务器数量 */

#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_slab_pool_t                 *shpool;
    ngx_atomic_t                     rwlock;
    ngx_stream_upstream_rr_peers_t  *zone_next;
#endif

    ngx_uint_t                       total_weight; /* 总权重 */

    unsigned                         single:1;     /* 0/1, 是否仅有一台服务器 */
    unsigned                         weighted:1;   /* 0/1, 是否为加权RR */

    ngx_str_t                       *name;         /* ngx_stream_upstream_srv_conf_t->host */

    ngx_stream_upstream_rr_peers_t  *next;         /* backup服务器配置信息，数据结构和当前一致 */

    ngx_stream_upstream_rr_peer_t   *peer;         /* 各服务器配置数组 */
};


#if (NGX_STREAM_UPSTREAM_ZONE)

#define ngx_stream_upstream_rr_peers_rlock(peers)                             \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_rlock(&peers->rwlock);                                     \
    }

#define ngx_stream_upstream_rr_peers_wlock(peers)                             \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peers->rwlock);                                     \
    }

#define ngx_stream_upstream_rr_peers_unlock(peers)                            \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peers->rwlock);                                    \
    }


#define ngx_stream_upstream_rr_peer_lock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peer->lock);                                        \
    }

#define ngx_stream_upstream_rr_peer_unlock(peers, peer)                       \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peer->lock);                                       \
    }

#else

#define ngx_stream_upstream_rr_peers_rlock(peers)
#define ngx_stream_upstream_rr_peers_wlock(peers)
#define ngx_stream_upstream_rr_peers_unlock(peers)
#define ngx_stream_upstream_rr_peer_lock(peers, peer)
#define ngx_stream_upstream_rr_peer_unlock(peers, peer)

#endif


typedef struct {
    ngx_stream_upstream_rr_peers_t  *peers;    /* 关联LB配置数据, 
                                                  ngx_stream_upstream_srv_conf_t->peer.data */
    ngx_stream_upstream_rr_peer_t   *current;  /*  */
    uintptr_t                       *tried;    /* 服务器数量较多时：维护尝试状态位表 */
    uintptr_t                        data;     /* 服务器数量较少时：维护尝试状态位表 */
} ngx_stream_upstream_rr_peer_data_t;


ngx_int_t ngx_stream_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
ngx_int_t ngx_stream_upstream_init_round_robin_peer(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);
ngx_int_t ngx_stream_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_stream_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);


#endif /* _NGX_STREAM_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
