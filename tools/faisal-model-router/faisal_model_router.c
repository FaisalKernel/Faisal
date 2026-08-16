#include "faisal_model_router.h"
#include <stdio.h>
#include <string.h>
static struct fmr_model* find(struct fmr_router*r,uint64_t id){size_t i;for(i=0;i<r->count;i++)if(r->models[i].model_id==id)return&r->models[i];return 0;}
int fmr_init(struct fmr_router*r){if(!r)return FMR_ERR_ARGUMENT;memset(r,0,sizeof*r);r->next_model_id=1;return FMR_OK;}
int fmr_register(struct fmr_router*r,const char*p,const char*n,uint32_t pk,uint32_t mods,uint32_t health,uint64_t lat,uint64_t cost,uint64_t ctx,uint64_t hw,uint32_t privacy,uint32_t locality,struct fmr_model*out){struct fmr_model*m;if(!r||!p||!n||!out||!p[0]||!n[0]||r->count>=FMR_MAX_MODELS)return FMR_ERR_ARGUMENT;m=&r->models[r->count++];memset(m,0,sizeof*m);m->model_id=r->next_model_id++;m->provider_kind=pk;m->modalities=mods;m->health_ppm=health;m->accuracy_ppm=health;m->latency_ns=lat;m->cost_micro=cost;m->context_tokens=ctx;m->hardware_mask=hw;m->privacy_level=privacy;m->locality_mask=locality;m->confidence_ppm=health;strncpy(m->provider,p,sizeof m->provider-1);strncpy(m->name,n,sizeof m->name-1);*out=*m;return FMR_OK;}
int fmr_get(const struct fmr_router*r,uint64_t id,struct fmr_model*out){struct fmr_model*m=find((struct fmr_router*)r,id);if(!r||!out)return FMR_ERR_ARGUMENT;if(!m)return FMR_ERR_NOT_FOUND;*out=*m;return FMR_OK;}
int fmr_record_result(struct fmr_router*r,uint64_t id,int success,uint64_t latency,uint32_t accuracy){struct fmr_model*m;if(!r)return FMR_ERR_ARGUMENT;m=find(r,id);if(!m)return FMR_ERR_NOT_FOUND;if(success)m->successes++;else m->failures++;m->total_latency_ns+=latency;m->health_ppm=(uint32_t)((m->successes*1000000ULL)/(m->successes+m->failures));if(accuracy)m->accuracy_ppm=accuracy; m->confidence_ppm=(m->health_ppm+m->accuracy_ppm)/2;return FMR_OK;}
static int allowed(const struct fmr_model*m,const struct fmr_request*q){if((m->modalities&q->required_modalities)!=q->required_modalities||m->context_tokens<q->context_tokens)return 0;if(q->require_local&&!(m->provider_kind&FMR_LOCAL))return 0;if(!q->allow_cloud&&(m->provider_kind&FMR_CLOUD))return 0;if(m->privacy_level<q->privacy_level)return 0;if(q->hardware_mask&&!(m->hardware_mask&q->hardware_mask))return 0;if(q->locality_mask&&!(m->locality_mask&q->locality_mask))return 0;if(q->max_latency_ns&&m->latency_ns>q->max_latency_ns)return 0;if(q->max_cost_micro&&m->cost_micro>q->max_cost_micro)return 0;if(q->min_accuracy_ppm&&m->accuracy_ppm<q->min_accuracy_ppm)return 0;if(m->health_ppm<100000)return 0;return 1;}
int fmr_route(const struct fmr_router*r,const struct fmr_request*q,struct fmr_route*out){size_t i;const struct fmr_model*best=0;uint64_t bestscore=0;uint32_t state=FMR_ROUTE_SELECTED;if(!r||!q||!out)return FMR_ERR_ARGUMENT;for(i=0;i<r->count;i++){const struct fmr_model*m=&r->models[i];uint64_t score;if(!allowed(m,q))continue;score=(uint64_t)m->accuracy_ppm*3ULL+(uint64_t)m->health_ppm*2ULL+(m->context_tokens>=q->context_tokens?1000000:0);if(q->max_latency_ns)score+=(m->latency_ns<=q->max_latency_ns?500000:0);if(q->max_cost_micro)score+=(m->cost_micro<=q->max_cost_micro?500000:0);if(!best||score>bestscore){best=m;bestscore=score;}}
if (!best)
	return FMR_ERR_NO_ROUTE;
memset(out, 0, sizeof *out);
out->model_id = best->model_id;
out->state = state;
out->score = bestscore > 0xffffffff ? 0xffffffff : (uint32_t)bestscore;
out->estimated_latency_ns = best->latency_ns;
out->estimated_cost_micro = best->cost_micro;
snprintf(out->reason, sizeof out->reason,
	 "selected provider=%s model=%s health_ppm=%u accuracy_ppm=%u",
	 best->provider, best->name, best->health_ppm, best->accuracy_ppm);
if (q->difficulty >= 800)
	out->state = FMR_ROUTE_ESCALATED;
if (q->difficulty <= 200 && best->cost_micro < 1000)
	out->state = FMR_ROUTE_DEESCALATED;
return FMR_OK;}
