#ifndef FAISAL_MODEL_ROUTER_H
#define FAISAL_MODEL_ROUTER_H
#include <stddef.h>
#include <stdint.h>
#define FMR_MAX_MODELS 64U
#define FMR_MAX_NAME 96U
#define FMR_MAX_REASON 256U
#define FMR_MAX_HISTORY 16U
#define FMR_LOCAL 1U
#define FMR_CLOUD 2U
#define FMR_OPEN 4U
#define FMR_PROPRIETARY 8U
#define FMR_REASONING 16U
#define FMR_CODING 32U
#define FMR_VISION 64U
#define FMR_SPEECH 128U
#define FMR_EMBEDDING 256U
#define FMR_MULTIMODAL 512U
enum fmr_status { FMR_OK=0,FMR_ERR_ARGUMENT=-1,FMR_ERR_IO=-2,FMR_ERR_CORRUPT=-3,FMR_ERR_FULL=-4,FMR_ERR_NOT_FOUND=-5,FMR_ERR_NO_ROUTE=-6 };
enum fmr_route_state { FMR_ROUTE_SELECTED=1,FMR_ROUTE_ESCALATED=2,FMR_ROUTE_DEESCALATED=3 };
struct fmr_model { uint64_t model_id; uint32_t provider_kind,modalities,health_ppm,accuracy_ppm; uint64_t latency_ns,cost_micro,context_tokens,hardware_mask,locality_mask; uint32_t privacy_level,confidence_ppm; uint64_t successes,failures,total_latency_ns; char provider[FMR_MAX_NAME]; char name[FMR_MAX_NAME]; };
struct fmr_request { uint32_t difficulty,required_modalities,privacy_level; uint64_t max_latency_ns,max_cost_micro,min_accuracy_ppm,context_tokens,hardware_mask,locality_mask; uint32_t require_local,allow_cloud; };
struct fmr_route { uint64_t model_id; uint32_t state; uint32_t score; uint64_t estimated_latency_ns,estimated_cost_micro; char reason[FMR_MAX_REASON]; };
struct fmr_router { struct fmr_model models[FMR_MAX_MODELS]; size_t count; uint64_t next_model_id; };
int fmr_init(struct fmr_router*); int fmr_register(struct fmr_router*,const char*,const char*,uint32_t,uint32_t,uint32_t,uint64_t,uint64_t,uint64_t,uint64_t,uint32_t,uint32_t,struct fmr_model*);
int fmr_record_result(struct fmr_router*,uint64_t,int,uint64_t,uint32_t); int fmr_route(const struct fmr_router*,const struct fmr_request*,struct fmr_route*); int fmr_get(const struct fmr_router*,uint64_t,struct fmr_model*);
#endif
