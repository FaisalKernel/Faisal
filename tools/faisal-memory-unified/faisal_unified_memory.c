#define _GNU_SOURCE
#include "faisal_unified_memory.h"
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct fum_header { uint32_t magic; uint16_t version; uint16_t kind; uint32_t size; uint64_t sequence; };
enum { FUM_REC_BACKEND = 1, FUM_REC_RECORD = 2 };

static void digest(const char *text, uint8_t out[FUM_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new(); unsigned int n = 0;
	if (!ctx || !EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) || !EVP_DigestUpdate(ctx, text, strlen(text)) || !EVP_DigestFinal_ex(ctx, out, &n) || n != FUM_DIGEST_SIZE) memset(out, 0, FUM_DIGEST_SIZE);
	EVP_MD_CTX_free(ctx);
}
static int write_rec(struct fum_service *s, uint16_t kind, const void *p, uint32_t size)
{
	struct fum_header h = { FUM_JOURNAL_MAGIC, FUM_JOURNAL_VERSION, kind, size, s->next_sequence++ };
	if (write(s->journal_fd, &h, sizeof(h)) != sizeof(h) || write(s->journal_fd, p, size) != (ssize_t)size || fsync(s->journal_fd) < 0) return FUM_ERR_IO;
	return FUM_OK;
}
static struct fum_record *find_record(struct fum_service *s, uint64_t id)
{ size_t i; for (i=0;i<s->record_count;i++) if (s->records[i].record_id==id) return &s->records[i]; return NULL; }
static struct fum_backend *find_backend(struct fum_service *s, uint64_t id)
{ size_t i; for (i=0;i<s->backend_count;i++) if (s->backends[i].backend_id==id) return &s->backends[i]; return NULL; }

int fum_replay(struct fum_service *s)
{
	struct fum_header h; uint8_t payload[sizeof(struct fum_record) > sizeof(struct fum_backend) ? sizeof(struct fum_record) : sizeof(struct fum_backend)];
	if (!s || s->journal_fd < 0 || lseek(s->journal_fd,0,SEEK_SET)<0) return FUM_ERR_ARGUMENT;
	s->record_count=s->backend_count=0; s->next_sequence=1;
	for (;;) {
		ssize_t n=read(s->journal_fd,&h,sizeof(h)); if (!n) break;
		if (n!=sizeof(h)||h.magic!=FUM_JOURNAL_MAGIC||h.version!=FUM_JOURNAL_VERSION||h.size>sizeof(payload)||read(s->journal_fd,payload,h.size)!=(ssize_t)h.size) return FUM_ERR_CORRUPT;
		if (h.kind==FUM_REC_BACKEND && h.size==sizeof(struct fum_backend)) { if(s->backend_count>=FUM_MAX_BACKENDS)return FUM_ERR_FULL; s->backends[s->backend_count++]=*(struct fum_backend*)payload; }
		else if(h.kind==FUM_REC_RECORD && h.size==sizeof(struct fum_record)) { struct fum_record *r=(struct fum_record*)payload,*old=find_record(s,r->record_id); if(old)*old=*r; else if(s->record_count<FUM_MAX_RECORDS)s->records[s->record_count++]=*r; else return FUM_ERR_FULL; }
		else
			return FUM_ERR_CORRUPT;
		s->next_sequence = h.sequence + 1;
	}
	return lseek(s->journal_fd,0,SEEK_END)<0?FUM_ERR_IO:FUM_OK;
}
int fum_open(struct fum_service *s, const char *path)
{
	int rc; if(!s||!path||strlen(path)>=sizeof(s->journal_path))return FUM_ERR_ARGUMENT; memset(s,0,sizeof(*s)); s->journal_fd=open(path,O_RDWR|O_CREAT|O_APPEND,0600); if(s->journal_fd<0)return FUM_ERR_IO; strncpy(s->journal_path,path,sizeof(s->journal_path)-1); if(pthread_mutex_init(&s->lock,NULL)){close(s->journal_fd);return FUM_ERR_IO;} s->lock_initialized=1;s->next_record_id=1;s->next_backend_id=1;s->next_sequence=1;rc=fum_replay(s);if(rc)fum_close(s);return rc;
}
void fum_close(struct fum_service *s){if(!s)return;if(s->lock_initialized)pthread_mutex_destroy(&s->lock);s->lock_initialized=0;if(s->journal_fd>=0)close(s->journal_fd);s->journal_fd=-1;}
int fum_register_backend(struct fum_service *s,const char *name,uint32_t kind,struct fum_backend *out)
{
	struct fum_backend b; if(!s||!name||!*name||!out||strlen(name)>=sizeof(b.name))return FUM_ERR_ARGUMENT; pthread_mutex_lock(&s->lock);if(s->backend_count>=FUM_MAX_BACKENDS){pthread_mutex_unlock(&s->lock);return FUM_ERR_FULL;}memset(&b,0,sizeof(b));b.backend_id=s->next_backend_id++;b.kind=kind;b.state=1;strncpy(b.name,name,sizeof(b.name)-1);s->backends[s->backend_count++]=b;if(write_rec(s,FUM_REC_BACKEND,&b,sizeof(b))){s->backend_count--;pthread_mutex_unlock(&s->lock);return FUM_ERR_IO;}*out=b;pthread_mutex_unlock(&s->lock);return FUM_OK;
}
int fum_put(struct fum_service *s,uint32_t cls,const char *key,const char *rel,const char *content,uint64_t now,uint64_t expires,uint64_t prov,uint64_t owner,uint64_t cap,uint32_t conf,uint32_t imp,uint32_t backend,struct fum_record *out)
{
	struct fum_record r; struct fum_backend *b; uint64_t conflict; int rc;
	if(!s||!key||!rel||!content||!out||!cls||strlen(key)>=sizeof(r.key)||strlen(rel)>=sizeof(r.relation)||strlen(content)>=sizeof(r.content))return FUM_ERR_ARGUMENT;
	pthread_mutex_lock(&s->lock); b=find_backend(s,backend); if(backend&&!b){pthread_mutex_unlock(&s->lock);return FUM_ERR_BACKEND;} if(fum_conflict(s,key,content,&conflict)==FUM_OK){pthread_mutex_unlock(&s->lock);return FUM_ERR_CONFLICT;}
	memset(&r,0,sizeof(r));r.record_id=s->next_record_id++;r.version=1;r.created_at_ns=now;r.expires_at_ns=expires;r.provenance_sequence=prov;r.owner_agent_id=owner;r.access_capability=cap;r.memory_class=cls;r.state=FUM_RECORD_ACTIVE;r.confidence_ppm=conf;r.importance_ppm=imp;r.backend_id=backend;r.encrypted=cap!=0;strncpy(r.key,key,sizeof(r.key)-1);strncpy(r.relation,rel,sizeof(r.relation)-1);strncpy(r.content,content,sizeof(r.content)-1);digest(content,r.content_digest);rc=write_rec(s,FUM_REC_RECORD,&r,sizeof(r));if(rc==FUM_OK){s->records[s->record_count++]=r;*out=r;}pthread_mutex_unlock(&s->lock);return rc;
}
int fum_get(const struct fum_service *s,uint64_t id,uint64_t owner,uint64_t cap,struct fum_record *out)
{
	struct fum_service *m=(struct fum_service*)s;struct fum_record *r;if(!s||!out)return FUM_ERR_ARGUMENT;pthread_mutex_lock(&m->lock);r=find_record(m,id);if(!r||r->state!=FUM_RECORD_ACTIVE){pthread_mutex_unlock(&m->lock);return FUM_ERR_NOT_FOUND;}if(r->owner_agent_id!=owner||r->access_capability!=cap){pthread_mutex_unlock(&m->lock);return FUM_ERR_ACCESS;}*out=*r;pthread_mutex_unlock(&m->lock);return FUM_OK;
}
int fum_query(const struct fum_service *s,const struct fum_query *q,struct fum_record *out,size_t n,size_t *found)
{
	struct fum_service *m=(struct fum_service*)s;size_t i,c=0;if(!s||!q||!out||!found)return FUM_ERR_ARGUMENT;pthread_mutex_lock(&m->lock);for(i=0;i<m->record_count&&c<n;i++){struct fum_record *r=&m->records[i];if(!q->include_expired&&r->state!=FUM_RECORD_ACTIVE)continue;if(q->memory_class&&r->memory_class!=q->memory_class)continue;if(q->owner_agent_id&&r->owner_agent_id!=q->owner_agent_id)continue;if(q->now_ns&&r->expires_at_ns&&r->expires_at_ns<=q->now_ns)continue;if(q->key[0]&&strcmp(q->key,r->key))continue;if(q->relation[0]&&strcmp(q->relation,r->relation))continue;out[c++]=*r;}*found=c;pthread_mutex_unlock(&m->lock);return FUM_OK;
}
int fum_supersede(struct fum_service *s,uint64_t id,const char *content,uint64_t now,struct fum_record *out)
{
	struct fum_record *old,*r;int rc;if(!s||!content||!out)return FUM_ERR_ARGUMENT;pthread_mutex_lock(&s->lock);old=find_record(s,id);if(!old){pthread_mutex_unlock(&s->lock);return FUM_ERR_NOT_FOUND;}old->state=FUM_RECORD_SUPERSEDED;write_rec(s,FUM_REC_RECORD,old,sizeof(*old));if(s->record_count>=FUM_MAX_RECORDS){pthread_mutex_unlock(&s->lock);return FUM_ERR_FULL;}r=&s->records[s->record_count++];*r=*old;r->record_id=s->next_record_id++;r->version=old->version+1;r->parent_version=old->record_id;r->created_at_ns=now;r->state=FUM_RECORD_ACTIVE;strncpy(r->content,content,sizeof(r->content)-1);digest(content,r->content_digest);rc=write_rec(s,FUM_REC_RECORD,r,sizeof(*r));if(rc==FUM_OK)*out=*r;pthread_mutex_unlock(&s->lock);return rc;
}
int fum_forget_expired(struct fum_service *s,uint64_t now,uint32_t *forgotten)
{size_t i;uint32_t n=0;if(!s||!forgotten)return FUM_ERR_ARGUMENT;pthread_mutex_lock(&s->lock);for(i=0;i<s->record_count;i++)if(s->records[i].state==FUM_RECORD_ACTIVE&&s->records[i].expires_at_ns&&s->records[i].expires_at_ns<=now){s->records[i].state=FUM_RECORD_EXPIRED;write_rec(s,FUM_REC_RECORD,&s->records[i],sizeof(s->records[i]));n++;}*forgotten=n;pthread_mutex_unlock(&s->lock);return FUM_OK;}
int fum_conflict(const struct fum_service *s,const char *key,const char *content,uint64_t *id)
{struct fum_service*m=(struct fum_service*)s;size_t i;if(!s||!key||!content||!id)return FUM_ERR_ARGUMENT;for(i=0;i<m->record_count;i++)if(m->records[i].state==FUM_RECORD_ACTIVE&&!strcmp(m->records[i].key,key)&&strcmp(m->records[i].content,content)){*id=m->records[i].record_id;return FUM_OK;}return FUM_ERR_NOT_FOUND;}
int fum_test_backend_neutrality(const struct fum_service *s,uint32_t id){struct fum_service*m=(struct fum_service*)s;return !s||(!id||find_backend(m,id))?FUM_OK:FUM_ERR_BACKEND;}
