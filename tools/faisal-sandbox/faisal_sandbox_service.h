#ifndef FAISAL_SANDBOX_SERVICE_H
#define FAISAL_SANDBOX_SERVICE_H
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#define FSB_MAX_SANDBOXES 128U
#define FSB_MAX_NAME 64U
#define FSB_MAX_REASON 160U
#define FSB_MAGIC 0x46534231U
#define FSB_VERSION 1U
#define FSB_CAP_EXEC (1ULL<<0)
#define FSB_CAP_COMMAND (1ULL<<1)
#define FSB_CAP_MEMORY_READ (1ULL<<2)
#define FSB_CAP_MEMORY_WRITE (1ULL<<3)
#define FSB_CAP_BROWSER (1ULL<<4)
#define FSB_CAP_NETWORK (1ULL<<5)
#define FSB_CAP_FILESYSTEM_READ (1ULL<<6)
#define FSB_CAP_FILESYSTEM_WRITE (1ULL<<7)
#define FSB_CAP_DEVICE (1ULL<<8)
#define FSB_CAP_DEBUG (1ULL<<9)
#define FSB_CAP_BUILD (1ULL<<10)
#define FSB_CAP_DEPLOY (1ULL<<11)
#define FSB_CAP_SECRET (1ULL<<12)
#define FSB_CAP_RESEARCH (1ULL<<13)
#define FSB_CAP_RECOVERY (1ULL<<14)
enum fsb_class { FSB_TASK=1,FSB_COMMAND,FSB_MEMORY,FSB_BROWSER,FSB_BUG_FINDER,FSB_DEBUGGER,FSB_RESEARCH,FSB_MODEL,FSB_BUILD_TEST,FSB_DEPLOY_CANARY,FSB_SECRETS,FSB_RECOVERY };
enum fsb_state { FSB_CREATED=1,FSB_RUNNING,FSB_CHECKPOINTED,FSB_FAILED,FSB_CANCELLED,FSB_RECOVERED };
enum fsb_status { FSB_OK=0,FSB_ERR_ARGUMENT=-1,FSB_ERR_IO=-2,FSB_ERR_CORRUPT=-3,FSB_ERR_FULL=-4,FSB_ERR_NOT_FOUND=-5,FSB_ERR_POLICY=-6,FSB_ERR_STATE=-7,FSB_ERR_AUTHORITY=-8 };
struct fsb_policy { uint64_t capability_mask,network_mask,filesystem_mask,device_mask,secret_mask,cpu_quota_ns,memory_bytes,io_bytes; uint32_t max_runtime_sec,tenant_id,trust_level,require_verification; };
struct fsb_sandbox { uint64_t sandbox_id,parent_id,agent_id,generation,checkpoint_id,provenance_sequence; uint32_t class_id,state,tenant_id; struct fsb_policy policy; char name[FSB_MAX_NAME]; char failure_reason[FSB_MAX_REASON]; };
struct fsb_service { int fd; uint64_t next_id,next_checkpoint,next_sequence; char path[4096]; struct fsb_sandbox sandboxes[FSB_MAX_SANDBOXES]; size_t count; pthread_mutex_t lock; int lock_initialized; };
int fsb_open(struct fsb_service*,const char*); void fsb_close(struct fsb_service*); int fsb_replay(struct fsb_service*);
int fsb_create(struct fsb_service*,uint32_t,uint64_t,uint64_t,uint32_t,const char*,const struct fsb_policy*,struct fsb_sandbox*);
int fsb_admit(const struct fsb_sandbox*,uint64_t,uint64_t,uint64_t,uint32_t);
int fsb_start(struct fsb_service*,uint64_t,struct fsb_sandbox*); int fsb_checkpoint(struct fsb_service*,uint64_t,uint64_t,uint64_t,struct fsb_sandbox*);
int fsb_cancel(struct fsb_service*,uint64_t,const char*,struct fsb_sandbox*); int fsb_fail(struct fsb_service*,uint64_t,const char*,struct fsb_sandbox*); int fsb_recover(struct fsb_service*,uint64_t,uint64_t,struct fsb_sandbox*);
int fsb_query(const struct fsb_service*,uint64_t,struct fsb_sandbox*); int fsb_test_policy_matrix(struct fsb_service*);
#endif
