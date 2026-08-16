#ifndef FAISAL_REPO_ADAPTER_H
#define FAISAL_REPO_ADAPTER_H
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#define FRA_MAX_FILES 256U
#define FRA_MAX_PATH 256U
#define FRA_MAX_DIGEST 32U
#define FRA_MAX_BYTES (1024U*1024U)
#define FRA_MAGIC 0x46524131U
#define FRA_VERSION 1U
enum fra_status { FRA_OK=0,FRA_ERR_ARGUMENT=-1,FRA_ERR_IO=-2,FRA_ERR_CORRUPT=-3,FRA_ERR_FULL=-4,FRA_ERR_NOT_FOUND=-5,FRA_ERR_POLICY=-6,FRA_ERR_CONFLICT=-7 };
struct fra_file { char path[FRA_MAX_PATH]; char backup_path[FRA_MAX_PATH]; uint64_t size,mode,version; uint8_t digest[FRA_MAX_DIGEST]; uint32_t staged,regular; };
struct fra_workspace { uint64_t generation,provenance_sequence; uint32_t file_count,changed_count; uint8_t tree_digest[FRA_MAX_DIGEST]; };
struct fra_service { int fd; uint64_t next_sequence; char root[4096],journal[4096]; struct fra_file files[FRA_MAX_FILES]; size_t file_count; struct fra_workspace workspace; pthread_mutex_t lock; int lock_initialized; };
int fra_open(struct fra_service*,const char*,const char*); void fra_close(struct fra_service*); int fra_replay(struct fra_service*);
int fra_analyze(struct fra_service*,uint64_t,struct fra_workspace*); int fra_query_file(const struct fra_service*,const char*,struct fra_file*);
int fra_stage_write(struct fra_service*,const char*,const void*,size_t,uint64_t,struct fra_file*); int fra_rollback(struct fra_service*,uint64_t,struct fra_workspace*);
int fra_reject_path(const char*); int fra_test_corruption(struct fra_service*);
#endif
