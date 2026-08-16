#ifndef FAISAL_ENGINEERING_SERVICE_H
#define FAISAL_ENGINEERING_SERVICE_H
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#define FEN_MAX_REPOS 16U
#define FEN_MAX_CHANGES 32U
#define FEN_MAX_CHECKS 16U
#define FEN_MAX_NAME 64U
#define FEN_MAX_REASON 160U
#define FEN_DIGEST_SIZE 32U
#define FEN_MAGIC 0x46454e31U
#define FEN_VERSION 1U
enum fen_state { FEN_PROPOSED=1,FEN_ANALYZED,FEN_GENERATED,FEN_TESTING,FEN_CANARY,FEN_DEPLOYED,FEN_ROLLED_BACK,FEN_FAILED };
enum fen_check_kind { FEN_REPOSITORY=1,FEN_DEPENDENCY,FEN_VULNERABILITY,FEN_BUILD,FEN_TEST,FEN_DEBUG,FEN_PERFORMANCE,FEN_REGRESSION };
enum fen_status { FEN_OK=0,FEN_ERR_ARGUMENT=-1,FEN_ERR_IO=-2,FEN_ERR_CORRUPT=-3,FEN_ERR_FULL=-4,FEN_ERR_NOT_FOUND=-5,FEN_ERR_STATE=-6,FEN_ERR_POLICY=-7,FEN_ERR_AUTHORITY=-8,FEN_ERR_CONFLICT=-9 };
struct fen_repo { uint64_t repo_id,generation; uint32_t tenant_id; uint8_t ref_digest[FEN_DIGEST_SIZE]; uint32_t clean; char name[FEN_MAX_NAME]; };
struct fen_check { uint32_t kind,status; uint64_t evidence_sequence; uint8_t evidence_digest[FEN_DIGEST_SIZE]; char reason[FEN_MAX_REASON]; };
struct fen_change { uint64_t change_id,repo_id,agent_id,generation,provenance_sequence; uint32_t state,model_proposed,verified,canary_passed,rollback_reason; uint8_t source_digest[FEN_DIGEST_SIZE],patch_digest[FEN_DIGEST_SIZE],artifact_digest[FEN_DIGEST_SIZE]; struct fen_check checks[FEN_MAX_CHECKS]; uint32_t check_count; char title[FEN_MAX_NAME]; };
struct fen_service { int fd; uint64_t next_repo,next_change,next_sequence; char path[4096]; struct fen_repo repos[FEN_MAX_REPOS]; struct fen_change changes[FEN_MAX_CHANGES]; size_t repo_count,change_count; pthread_mutex_t lock; int lock_initialized; };
int fen_open(struct fen_service*,const char*); void fen_close(struct fen_service*); int fen_replay(struct fen_service*);
int fen_register_repo(struct fen_service*,uint32_t,const char*,const uint8_t[FEN_DIGEST_SIZE],struct fen_repo*);
int fen_propose_change(struct fen_service*,uint64_t,uint64_t,const char*,const uint8_t[FEN_DIGEST_SIZE],const uint8_t[FEN_DIGEST_SIZE],uint32_t,struct fen_change*);
int fen_record_check(struct fen_service*,uint64_t,uint32_t,uint32_t,const uint8_t[FEN_DIGEST_SIZE],const char*,struct fen_change*);
int fen_verify_change(struct fen_service*,uint64_t,uint64_t,struct fen_change*);
int fen_canary(struct fen_service*,uint64_t,uint32_t,struct fen_change*); int fen_deploy(struct fen_service*,uint64_t,uint64_t,struct fen_change*); int fen_rollback(struct fen_service*,uint64_t,uint32_t,struct fen_change*);
int fen_query(const struct fen_service*,uint64_t,struct fen_change*); int fen_test_model_proposal_denial(struct fen_service*,uint64_t);
#endif
