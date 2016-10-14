
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

/* 分为两个队列，因为插入ACCEPT事件需要持有锁，而其他的事件不需要持有锁；
   分开处理，从而最大限度的压缩加锁串行的时间粒度 */
ngx_queue_t  ngx_posted_accept_events;        /* ACCEPT事件队列 */
ngx_queue_t  ngx_posted_events;               /* 其他读写IO事件队列 */


void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    while (!ngx_queue_empty(posted)) {
        q = ngx_queue_head(posted);
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        ngx_delete_posted_event(ev);

        ev->handler(ev);            /* 调用对应的处理函数 
                                          ACCEPT事件:ngx_event_accept/ngx_event_recvmsg
                                          普通HTTP处理事件:ngx_http_wait_request_handler()
                                     */
    }
}
