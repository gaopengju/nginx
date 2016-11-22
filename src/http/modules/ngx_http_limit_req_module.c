
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* 限速模块儿的共享内存信息结构 */
typedef struct {
    u_char                       color;   /* 节点颜色 */
    u_char                       dummy;
    u_short                      len;     /* data[]的长度 */
    ngx_queue_t                  queue;   /* 链接入ngx_http_limit_req_shctx_t->queue */
    ngx_msec_t                   last;    /* 上一次调度的时间，用于驱动"漏桶"算法 */
    ngx_uint_t                   excess;  /* 上一次调度后，待处理的请求数，单位0.001r */
    ngx_uint_t                   count;   /* 实际上为ngx_http_limit_req_ctx_t->node临
                                                时节点的锁，保证node节点操作期间不被
                                                删除 */
    u_char                       data[1]; /* KEY值 */
} ngx_http_limit_req_node_t;
typedef struct {
    ngx_rbtree_t                  rbtree; /* 树节点，ngx_http_limit_req_node_t，存放
                                             检查命中各KEY的请求是否应限速所需的信息 */
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   queue;  /* 用于回收长期没有访问的节点内存；
                                             队列首为活跃节点 */
} ngx_http_limit_req_shctx_t;
typedef struct {
    ngx_http_limit_req_shctx_t  *sh;      /* 限速队列的实现，ngx_http_limit_req_shctx_t，管理客户端节点信息 */
    ngx_slab_pool_t             *shpool;  /* 共享内存的起始地址，slab管理结构 */
    ngx_uint_t                   rate;    /* 限速值，单位0.001r/s(减少浮点预算，提升效率) */
    ngx_http_complex_value_t     key;     /* 限速key的编译结果 */
    ngx_http_limit_req_node_t   *node;    /* 临时指针，需要更新excess和last的节点 */
} ngx_http_limit_req_ctx_t;


/* 基于key的限速模块儿的配置信息结构 */
typedef struct {
    ngx_shm_zone_t              *shm_zone;  /* 对应的共享内存 */
    ngx_uint_t                   burst;     /* 突发流量，单位0.001r/s */
    ngx_uint_t                   nodelay;   /* 超过限速的流量是否需要延迟发送？unsigned  nodelay:1 */
} ngx_http_limit_req_limit_t;
typedef struct {
    ngx_array_t                  limits;            /* 限速设置数组，ngx_http_limit_req_limit_t */
    ngx_uint_t                   limit_log_level;   /* 限速日志级别 */
    ngx_uint_t                   delay_log_level;   /* 延迟处理日志级别，=limit_log_level+1 */
    ngx_uint_t                   status_code;       /* 超过限速的突发流量后，或共享内存不足时，请求的响应 */
} ngx_http_limit_req_conf_t;


static void ngx_http_limit_req_delay(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_req_lookup(ngx_http_limit_req_limit_t *limit,
    ngx_uint_t hash, ngx_str_t *key, ngx_uint_t *ep, ngx_uint_t account);
static ngx_msec_t ngx_http_limit_req_account(ngx_http_limit_req_limit_t *limits,
    ngx_uint_t n, ngx_uint_t *ep, ngx_http_limit_req_limit_t **limit);
static void ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx,
    ngx_uint_t n);

static void *ngx_http_limit_req_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_limit_req_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_limit_req_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_limit_req_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};

/* 配置指令处理 */
static ngx_command_t  ngx_http_limit_req_commands[] = {

    { ngx_string("limit_req_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_limit_req_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_req"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_limit_req,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_req_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_conf_t, limit_log_level),
      &ngx_http_limit_req_log_levels },

    { ngx_string("limit_req_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_conf_t, status_code),
      &ngx_http_limit_req_status_bounds },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_req_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_limit_req_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_limit_req_create_conf,        /* create location configuration */
    ngx_http_limit_req_merge_conf          /* merge location configuration */
};

/* nginx的基于key的限速模块儿，此处的key可以为nginx的变量、文本和它们的组合 */
ngx_module_t  ngx_http_limit_req_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_req_module_ctx,        /* module context */
    ngx_http_limit_req_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/* 基于key的限速模块儿的处理句柄，处于NGX_HTTP_PREACCESS_PHASE阶段

   采用“漏桶”算法，如果未超过设定值或未超过阈值，则正常发送或缓存；否则丢弃 
   
   限速策略必须逐个过，此模块儿存在如下限制：
       1) 不能针对KEY的不同值，限定不同的访问频率(如，不同IP不同限速)
       2) 不能实时动态更改, 只能通过修改配置RELOAD NGINX来生效

   参考：http://www.just4coding.com/blog/2015/09/08/ngx-http-limit-req-module/ */
static ngx_int_t
ngx_http_limit_req_handler(ngx_http_request_t *r)
{
    uint32_t                     hash;
    ngx_str_t                    key;
    ngx_int_t                    rc;
    ngx_uint_t                   n, excess;
    ngx_msec_t                   delay;
    ngx_http_limit_req_ctx_t    *ctx;
    ngx_http_limit_req_conf_t   *lrcf;
    ngx_http_limit_req_limit_t  *limit, *limits;

    /* <TAKE CARE!!!>子请求采用和对应主请求相同的限速处理方式;
                     也保证每个请求只过一次限速模块儿 */
    if (r->main->limit_req_set) {
        return NGX_DECLINED;
    }

    /* 获取限速模块儿的location配置信息 */
    lrcf = ngx_http_get_module_loc_conf(r, ngx_http_limit_req_module);
    limits = lrcf->limits.elts;

    excess = 0;

    rc = NGX_DECLINED;

#if (NGX_SUPPRESS_WARN)
    limit = NULL;
#endif

    /* 遍历location设定的限速策略 */
    for (n = 0; n < lrcf->limits.nelts; n++) {
        limit = &limits[n];
        ctx = limit->shm_zone->data;

        /* 提取此请求中对应KEY的值 */
        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (key.len == 0) {
            continue;
        }
        if (key.len > 65535) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 65535 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        /* 计算key的hash值，利用此在红黑树中索引 */
        hash = ngx_crc32_short(key.data, key.len);
        ngx_shmtx_lock(&ctx->shpool->mutex);

        /* 查找并匹配； 返回值含义如下：
              NGX_ERROR       内存分配错误
              NGX_BUSY        超过了设置的最大请求频率，直接以状态码结束请求
              NGX_AGAIN       通过了某条策略，继续匹配下一条
              NGX_OK          通过了所有限速策略
         */
        rc = ngx_http_limit_req_lookup(limit, hash, &key, &excess,
                                       (n == lrcf->limits.nelts - 1));
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit_req[%ui]: %i %ui.%03ui",
                       n, rc, excess / 1000, excess % 1000);

        /* 判断是否继续匹配 */
        if (rc != NGX_AGAIN) {
            break;
        }
    }

    /* 未设置限速策略，直接退出此handler，继续执行本阶段的其他handler */
    if (rc == NGX_DECLINED) {
        return NGX_DECLINED;
    }

    /* 设置对应主请求的限速标识 */
    r->main->limit_req_set = 1;

    /* 丢包 */
    if (rc == NGX_BUSY || rc == NGX_ERROR) {

        if (rc == NGX_BUSY) {
            ngx_log_error(lrcf->limit_log_level, r->connection->log, 0,
                          "limiting requests, excess: %ui.%03ui by zone \"%V\"",
                          excess / 1000, excess % 1000,
                          &limit->shm_zone->shm.name);
        }

        while (n--) {                      /* 此请求将被丢弃(实际上是回复503) */
            ctx = limits[n].shm_zone->data;/* 因此不计入漏桶算法的更新体系 */

            if (ctx->node == NULL) {
                continue;
            }

            ngx_shmtx_lock(&ctx->shpool->mutex);
            ctx->node->count--;
            ngx_shmtx_unlock(&ctx->shpool->mutex);

            ctx->node = NULL;
        }

        return lrcf->status_code;          /* 默认返回系统忙(503) */
    }

    /* rc == NGX_AGAIN || rc == NGX_OK */

    if (rc == NGX_AGAIN) {                 /*  会有此返回值麽??? */
        excess = 0;
    }

    /* 计算是否需要延迟，delay为处理完当前所有剩余请求所需的时间
       此时的excess/limit对应最后一个限速策略 */
    delay = ngx_http_limit_req_account(limits, n, &excess, &limit);
    if (!delay) {
        return NGX_DECLINED;               /* 不限速，不延时，因此进入本阶段其他句柄的处理 */
    }

    /* 延迟请求 */
    ngx_log_error(lrcf->delay_log_level, r->connection->log, 0,
                  "delaying request, excess: %ui.%03ui, by zone \"%V\"",
                  excess / 1000, excess % 1000, &limit->shm_zone->shm.name);
    if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_limit_req_delay;
    ngx_add_timer(r->connection->write, delay);

    return NGX_AGAIN;
}


static void
ngx_http_limit_req_delay(ngx_http_request_t *r)
{
    ngx_event_t  *wev;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "limit_req delay");

    wev = r->connection->write;

    if (!wev->timedout) {

        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    wev->timedout = 0;

    if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->read_event_handler = ngx_http_block_reading;
    r->write_event_handler = ngx_http_core_run_phases;

    /* 继续后续阶段处理 */
    ngx_http_core_run_phases(r);
}


static void
ngx_http_limit_req_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    ngx_http_limit_req_node_t   *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (ngx_http_limit_req_node_t *) &node->color;
            lrnt = (ngx_http_limit_req_node_t *) &temp->color;

            p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

/* 基于key的限速模块儿，hash表查找 */
static ngx_int_t
ngx_http_limit_req_lookup(ngx_http_limit_req_limit_t *limit, ngx_uint_t hash,
    ngx_str_t *key, ngx_uint_t *ep, ngx_uint_t account)
{
    size_t                      size;
    ngx_int_t                   rc, excess;
    ngx_time_t                 *tp;
    ngx_msec_t                  now;
    ngx_msec_int_t              ms;
    ngx_rbtree_node_t          *node, *sentinel;
    ngx_http_limit_req_ctx_t   *ctx;
    ngx_http_limit_req_node_t  *lr;

    /* 记录当前时间 */
    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    /* 搜索红黑树 */
    ctx = limit->shm_zone->data;
    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;
    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* 键的hash值相同，hash == node->key，比较键内容 */
        lr = (ngx_http_limit_req_node_t *) &node->color;
        rc = ngx_memn2cmp(key->data, lr->data, key->len, (size_t) lr->len);
        /* 情形1: 匹配到某个限速节点 */
        if (rc == 0) {
            ngx_queue_remove(&lr->queue);
            ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);
                                              /* 加入队列首，保证短期不会被删除 */

            ms = (ngx_msec_int_t) (now - lr->last);
            excess = lr->excess - ctx->rate * ngx_abs(ms) / 1000 + 1000;
            if (excess < 0) {                 /* 漏桶算法核心公式：1000代表当前的请求(别忘了1000的预设倍数) */
                excess = 0;                   /*     ctx->rate * ngx_abs(ms) / 1000, 代表产生的令牌 */
            }                                 /*     lr->excess, 代表上一次处理后剩余的待处理请求数 */

            
            *ep = excess;                     /* 返回超限值 */

            if ((ngx_uint_t) excess > limit->burst) {
                return NGX_BUSY;              /* 超限值超过阈值；需直接丢弃请求报文 */
            }

            if (account) {                    /* location中最后一条限速策略，记录信息，不再继续匹配 */
                lr->excess = excess;
                lr->last = now;
                return NGX_OK;
            }

            lr->count++;                      /* 保证不被清理 */
            ctx->node = lr;                   /* 挂接到临时节点，待后续更新->excess/last */
            return NGX_AGAIN;                 /* 继续匹配下一条限速策略 */
        }

        node = (rc < 0) ? node->left : node->right;
    }

    /*** 情形2: 未匹配到限速节点，增加节点到红黑树 ***/
    *ep = 0;

    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_limit_req_node_t, data)
           + key->len;


    ngx_http_limit_req_expire(ctx, 1);                      /* 删除0速率的节点 */
    /* 分配新节点(计算大小很给力，是不是!!!) */
    node = ngx_slab_alloc_locked(ctx->shpool, size);
    if (node == NULL) {
        ngx_http_limit_req_expire(ctx, 0);                  /* 强制删除1个节点 */
        node = ngx_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "could not allocate node%s", ctx->shpool->log_ctx);
            return NGX_ERROR;
        }
    }

    /* 插入到红黑树，并插入到延迟发送队列 */
    node->key = hash;
    lr = (ngx_http_limit_req_node_t *) &node->color;
    lr->len = (u_short) key->len;
    lr->excess = 0;
    ngx_memcpy(lr->data, key->data, key->len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);
    ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

    if (account) {                             /* 最后一条限速策略，后续不再匹配 */
        lr->last = now;
        lr->count = 0;
        return NGX_OK;
    }

    lr->last = 0;                              /* 继续匹配 */
    lr->count = 1;
    ctx->node = lr;

    return NGX_AGAIN;
}

/* 基于key的限速模块儿，计算处理完所有请求需要的最大时间；
   因为在不同的限速模块儿可能延时不一致，选择最大的值返回 */
static ngx_msec_t
ngx_http_limit_req_account(ngx_http_limit_req_limit_t *limits, ngx_uint_t n,
    ngx_uint_t *ep, ngx_http_limit_req_limit_t **limit)
{
    ngx_int_t                   excess;
    ngx_time_t                 *tp;
    ngx_msec_t                  now, delay, max_delay;
    ngx_msec_int_t              ms;
    ngx_http_limit_req_ctx_t   *ctx;
    ngx_http_limit_req_node_t  *lr;

    excess = *ep;

    /* 计算最后限速策略处理完所有请求需要的延迟时间 */
    if (excess == 0 || (*limit)->nodelay) {
        max_delay = 0;
    } else {
        ctx = (*limit)->shm_zone->data;
        max_delay = excess * 1000 / ctx->rate;
    }

    /* 依次计算其他策略所需的延迟时间；并更新对应的“漏桶”变量 */
    while (n--) {
        ctx = limits[n].shm_zone->data;
        lr = ctx->node;

        if (lr == NULL) {           /* 除最后一个限速策略外，都挂接了临时节点 */
            continue;
        }

        ngx_shmtx_lock(&ctx->shpool->mutex);

        tp = ngx_timeofday();

        now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);
        ms = (ngx_msec_int_t) (now - lr->last);

        excess = lr->excess - ctx->rate * ngx_abs(ms) / 1000 + 1000;
        if (excess < 0) {           /* 新建节点此值一定小于0, 不限速 */
            excess = 0;
        }

        lr->last = now;             /* 更新 */
        lr->excess = excess;
        lr->count--;

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ctx->node = NULL;           /* 清空临时指针 */

        if (limits[n].nodelay) {    /* 设置了标识，强制不延时 */
            continue;
        }

        delay = excess * 1000 / ctx->rate;

        if (delay > max_delay) {    /* 更新最大值 */
            max_delay = delay;
            *ep = excess;
            *limit = &limits[n];
        }
    }

    return max_delay;               /* 返回最大值 */
}

/* 根据要求，删除老旧节点，以使得分配内存成功 */
static void
ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx, ngx_uint_t n)
{
    ngx_int_t                   excess;
    ngx_time_t                 *tp;
    ngx_msec_t                  now;
    ngx_queue_t                *q;
    ngx_msec_int_t              ms;
    ngx_rbtree_node_t          *node;
    ngx_http_limit_req_node_t  *lr;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    /*
     * n == 1 deletes one or two zero rate entries     1表示删除1~3个0速率节点
     * n == 0 deletes oldest entry by force            0表示强制删除1个节点
     *        and one or two zero rate entries             并删除1~2个0速率节点
     */
    while (n < 3) {
        if (ngx_queue_empty(&ctx->sh->queue)) {
            return;
        }

        q = ngx_queue_last(&ctx->sh->queue);    /* 插入时放置在head，因此尾巴初为最不活跃节点 */
        lr = ngx_queue_data(q, ngx_http_limit_req_node_t, queue);
        if (lr->count) {                        /* 当需要更新漏桶算法的数据时，此值不为0 */
            /*
             * There is not much sense in looking further,
             * because we bump nodes on the lookup stage.
             */
            return;
        }

        if (n++ != 0) {                         /* 参数为0, 强制删除 */
            ms = (ngx_msec_int_t) (now - lr->last);
            ms = ngx_abs(ms);

            if (ms < 60000) {                         /* 60s内的不删除 */
                return;
            }

            excess = lr->excess - ctx->rate * ms / 1000;
            if (excess > 0) {                         /* 有剩余任务的不删除 */
                return;
            }
        }

        ngx_queue_remove(q);                    /* 从队列删除 */
        node = (ngx_rbtree_node_t *)            /* 从红黑树删除 */
                   ((u_char *) lr - offsetof(ngx_rbtree_node_t, color));
        ngx_rbtree_delete(&ctx->sh->rbtree, node);
        ngx_slab_free_locked(ctx->shpool, node);
    }
}

/* 共享内存创建后，限速模块儿调用此函数初始化共享内存，以明确内存使用 */
static ngx_int_t
ngx_http_limit_req_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_req_ctx_t  *octx = data;

    size_t                     len;
    ngx_http_limit_req_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_req \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_req_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_limit_req_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    len = sizeof(" in limit_req zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in limit_req zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


static void *
ngx_http_limit_req_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_req_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->limit_log_level = NGX_CONF_UNSET_UINT;
    conf->status_code = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_req_conf_t *prev = parent;
    ngx_http_limit_req_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    ngx_conf_merge_uint_value(conf->limit_log_level, prev->limit_log_level,
                              NGX_LOG_ERR);

    conf->delay_log_level = (conf->limit_log_level == NGX_LOG_INFO) ?
                                NGX_LOG_INFO : conf->limit_log_level + 1;

    ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NGX_HTTP_SERVICE_UNAVAILABLE);

    return NGX_CONF_OK;
}

/* 解析限速共享域配置语句，格式如下
      limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s; */
static char *
ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                            *p;
    size_t                             len;
    ssize_t                            size;
    ngx_str_t                         *value, name, s;
    ngx_int_t                          rate, scale;
    ngx_uint_t                         i;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_limit_req_ctx_t          *ctx;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    /* 分配共享内存的使用信息环境 */
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    /* 编译解析限速的key字符串 */
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    rate = 1;
    scale = 1;
    name.len = 0;

    /* 解析配置语句 */
    for (i = 2; i < cf->args->nelts; i++) {
        /* 共享内存，名字:大小 */
        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            /* 共享内存大小，不得小于8页 */
            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        /* 速率限制字段，支持/秒或/分钟 */
        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;
            p = value[i].data + len - 3;

            if (ngx_strncmp(p, "r/s", 3) == 0) {
                scale = 1;
                len -= 3;

            } else if (ngx_strncmp(p, "r/m", 3) == 0) {
                scale = 60;
                len -= 3;
            }

            rate = ngx_atoi(value[i].data + 5, len - 5);
            if (rate <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    /* 换算限速速率，扩大1000倍，减少浮点数运算，提升效率 */
    ctx->rate = rate * 1000 / scale;

    /* 解析结果加入cycle的共享内存链，待配置解析完毕后再分配 */
    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_limit_req_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return NGX_CONF_ERROR;
    }

    /* 设置共享内存的初始化句柄，特定于模块儿；设置对应的模块儿信息环境 */
    shm_zone->init = ngx_http_limit_req_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}

/* 在具体的location引入限速模块儿，配置指令如下：
      limit_req zone=one burst=5 */
static char *
ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_req_conf_t  *lrcf = conf;

    ngx_int_t                    burst;
    ngx_str_t                   *value, s;
    ngx_uint_t                   i, nodelay;
    ngx_shm_zone_t              *shm_zone;
    ngx_http_limit_req_limit_t  *limit, *limits;

    value = cf->args->elts;

    shm_zone = NULL;
    burst = 0;
    nodelay = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            shm_zone = ngx_shared_memory_add(cf, &s, 0,
                                             &ngx_http_limit_req_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "burst=", 6) == 0) {

            burst = ngx_atoi(value[i].data + 6, value[i].len - 6);
            if (burst <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid burst rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "nodelay") == 0) {
            nodelay = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    limits = lrcf->limits.elts;

    if (limits == NULL) {
        if (ngx_array_init(&lrcf->limits, cf->pool, 1,
                           sizeof(ngx_http_limit_req_limit_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    /* 每个配置环境，只能配置一次相同元素的限速 */
    for (i = 0; i < lrcf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    limit = ngx_array_push(&lrcf->limits);
    if (limit == NULL) {
        return NGX_CONF_ERROR;
    }

    limit->shm_zone = shm_zone;
    limit->burst = burst * 1000;
    limit->nodelay = nodelay;

    return NGX_CONF_OK;
}

/* 基于key的限速模块儿注册处理句柄 */
static ngx_int_t
ngx_http_limit_req_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    /* 访问控制前的阶段 注册限速句柄 */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_req_handler;

    return NGX_OK;
}
