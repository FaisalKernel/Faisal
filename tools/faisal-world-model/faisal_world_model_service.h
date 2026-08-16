#ifndef FAISAL_WORLD_MODEL_SERVICE_H
#define FAISAL_WORLD_MODEL_SERVICE_H
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#define FWM_MAX_ENTITIES 256U
#define FWM_MAX_SIGNALS 128U
#define FWM_MAX_TEXT 256U
#define FWM_MAX_TYPE 32U
#define FWM_MAX_NAME 96U
#define FWM_MAGIC 0x46574d31U
#define FWM_VERSION 1U
enum fwm_entity_type { FWM_MACHINE=1,FWM_PROCESS,FWM_AGENT,FWM_SERVICE,FWM_USER,FWM_RESOURCE,FWM_MODEL,FWM_DATASET,FWM_NETWORK,FWM_FILE,FWM_API,FWM_DEPENDENCY,FWM_DEPLOYMENT,FWM_INCIDENT,FWM_OBJECTIVE };
enum fwm_state { FWM_UNKNOWN=0,FWM_CONSISTENT=1,FWM_DRIFTED=2,FWM_RESOLVED=3 };
enum fwm_status { FWM_OK=0,FWM_ERR_ARGUMENT=-1,FWM_ERR_IO=-2,FWM_ERR_CORRUPT=-3,FWM_ERR_FULL=-4,FWM_ERR_NOT_FOUND=-5,FWM_ERR_CONFLICT=-6 };
struct fwm_entity { uint64_t entity_id,generation,provenance_sequence,observed_at_ns,expected_at_ns; uint32_t type,state,confidence_ppm,actionable; char type_name[FWM_MAX_TYPE]; char name[FWM_MAX_NAME]; char observed[FWM_MAX_TEXT]; char expected[FWM_MAX_TEXT]; uint8_t observed_digest[32],expected_digest[32]; };
struct fwm_signal { uint64_t signal_id,entity_id,generation,created_at_ns,provenance_sequence; uint32_t type,severity,actionable; char reason[FWM_MAX_TEXT]; };
struct fwm_service { int fd; uint64_t next_entity_id,next_signal_id,next_sequence,generation; char path[4096]; struct fwm_entity entities[FWM_MAX_ENTITIES]; struct fwm_signal signals[FWM_MAX_SIGNALS]; size_t entity_count,signal_count; pthread_mutex_t lock; int lock_initialized; };
int fwm_open(struct fwm_service*,const char*); void fwm_close(struct fwm_service*); int fwm_replay(struct fwm_service*);
int fwm_observe(struct fwm_service*,uint32_t,const char*,const char*,uint64_t,uint64_t,uint32_t,struct fwm_entity*);
int fwm_expect(struct fwm_service*,uint32_t,const char*,const char*,uint64_t,uint64_t,uint32_t,struct fwm_entity*);
int fwm_reconcile(struct fwm_service*,uint64_t,uint64_t,uint32_t*,struct fwm_signal*,size_t,size_t*);
int fwm_query(const struct fwm_service*,uint64_t,struct fwm_entity*); int fwm_query_signal(const struct fwm_service*,uint64_t,struct fwm_signal*);
#endif
