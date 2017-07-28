
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);
/* 共享内存区域的描述结构 */
struct ngx_shm_zone_s {
    void                     *data;     /* 对应的模块儿信息，如ngx_http_limit_req_ctx_t */
    ngx_shm_t                 shm;      /* 详细描述信息 */
    ngx_shm_zone_init_pt      init;     /* 初始回调函数，如ngx_http_limit_req_init_zone() */
    void                     *tag;      /* 标签，一般为模块儿地址信息，区分共享内存的用途；
                                            防止不同模块儿创建同名称的共享内存，造成逻辑
                                            混乱 */
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; 是否可重用? 可重用的情况
                                           下，在reload处理时，没有变化的共享内存不必再重
                                           新分配，仅仅重新初始化就ok */
};


struct ngx_cycle_s {
    void                  ****conf_ctx;        /* 模块儿配置结构内存 */
    ngx_pool_t               *pool;            /* 对应的内存池 */

    ngx_log_t                *log;             /* 日志描述结构 */
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;
    ngx_connection_t         *free_connections;  /* 维护空闲连接单链表 */
    ngx_uint_t                free_connection_n;

    ngx_module_t            **modules;        /* 本配置周期对应的模块儿信息，ngx_modules[]的副本 */
    ngx_uint_t                modules_n;      /* 内置模块儿数，=ngx_modules_n */
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    ngx_queue_t               reusable_connections_queue;  /* 实现链路的keepalive */
                                              /* 可重用队列, 当ngx_connection_t->reusable
                                                 =1, 则加入此队列; 当进程资源紧张, 没
                                                 有空闲连接可用时, 此队列中的连接将被释放,
                                                 重用; 通过ngx_reusable_connection()
                                                 函数可加入、移出此队列*/
    ngx_array_t               listening;      /* 维护监听接口套接字; 如果是通过reload
                                                 方式加载, 初始时为继承的老进程的监听
                                                 插口fd数组; 也可以通过环境变量继承已
                                                 打开的插口数组, export NGINX="
                                                 16000:16500:16600;" 
                                                 ngx_listening_t */
    ngx_array_t               paths;
    ngx_array_t               config_dump;
    ngx_list_t                open_files;
    ngx_list_t                shared_memory;  /* 共享内存链表 */

    ngx_uint_t                connection_n;   /* 配置events{}中参数worker_connections
                                                 的值，默认512; =ngx_event_conf_t
                                                 ->connections; 单个worker连接数
                                                 上限*/
    ngx_uint_t                files_n;        /* files[]数组的大小 */

    ngx_connection_t         *connections;    /* 初始时分配的请求连接信息结构池, connection_n */
    ngx_event_t              *read_events;    /* 连接的读事件, connection_n */
    ngx_event_t              *write_events;   /* 连接的写事件, connection_n */

    ngx_cycle_t              *old_cycle;      /* 老的cycle, 以此为模板初始化新cycle结构 */

    ngx_str_t                 conf_file;      /* 配置文件，-c参数 */
    ngx_str_t                 conf_param;     /* 命令行配置，-g参数 */
    ngx_str_t                 conf_prefix;    /* 配置文件nginx.conf前置路径，-p参数 */
    ngx_str_t                 prefix;         /* 配置路径前缀，-p参数 */
    ngx_str_t                 lock_file;
    ngx_str_t                 hostname;       /* 主机名，由gethostname()获得，等价于uname -n */
};


typedef struct {
    ngx_flag_t                daemon;
    ngx_flag_t                master;

    ngx_msec_t                timer_resolution;   /* 是否使用SIGALRM提供定时器解决方案 */

    ngx_int_t                 worker_processes;   /* 配置worker_processes，worker进程数 */
    ngx_int_t                 debug_points;

    ngx_int_t                 rlimit_nofile;      /* 配置worker_rlimit_nofile，worker进程允许打开的fd上限 */
    off_t                     rlimit_core;        /* 配置worker_rlimit_core，core文件大小上限；0表示不创建core文件 */

    int                       priority;           /* 配置worker_priority，worker进程调度优先级 */

    ngx_uint_t                cpu_affinity_auto;  /* 配置worker_cpu_affinity auto，自动设置cpu亲昵性*/
    ngx_uint_t                cpu_affinity_n;     /* cpu_affinity[]数组大小 */
    ngx_cpuset_t             *cpu_affinity;       /* 配置worker_cpu_affinity，cpu亲昵性*/

    char                     *username;           /* 用户名 */
    ngx_uid_t                 user;               /* 用户ID */
    ngx_gid_t                 group;              /* 用户组ID */

    ngx_str_t                 working_directory;  /* 配置working_directory，worker进程执行路径 */
    ngx_str_t                 lock_file;

    ngx_str_t                 pid;      /* nginx.conf的pid指令指定的文件路径 */
    ngx_str_t                 oldpid;

    ngx_array_t               env;
    char                    **environment;        /* 保存的环境变量 */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
