#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../faisal-repo-adapter/faisal_repo_adapter.h"
static void fail(const char*m,int r){printf("M113_FAIL %s rc=%d\n",m,r);exit(1);}
#define OK(x,m) do{int _r=(x);if(_r!=FRA_OK)fail(m,_r);}while(0)
#define EQ(x,e,m) do{int _r=(x);if(_r!=(e))fail(m,_r);}while(0)
int main(void){char root[]="/tmp/faisal-m113-root-XXXXXX",jp[]="/tmp/faisal-m113-journal-XXXXXX";struct fra_service s;struct fra_workspace w;struct fra_file f;int rfd=mkstemp(root),jfd=mkstemp(jp);if(rfd<0||jfd<0)fail("TMP",FRA_ERR_IO);close(rfd);close(jfd);unlink(root);mkdir(root,0700);unlink(jp);char path[4096];snprintf(path,sizeof path,"%s/main.c",root);int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0600);if(fd<0||write(fd,"int main(void){return 0;}\n",26)!=26)fail("SEED",FRA_ERR_IO);close(fd);OK(fra_open(&s,root,jp),"OPEN");OK(fra_analyze(&s,10,&w),"ANALYZE");if(w.file_count!=1||w.generation!=1)fail("ANALYSIS",FRA_ERR_CONFLICT);printf("M113_REAL_REPOSITORY_ANALYSIS_OK files=%u generation=%llu\n",w.file_count,(unsigned long long)w.generation);OK(fra_query_file(&s,"main.c",&f),"QUERY");if(!f.size)fail("DIGEST_SIZE",FRA_ERR_CONFLICT);printf("M113_FILE_DIGEST_PROVENANCE_OK bytes=%llu\n",(unsigned long long)f.size);EQ(fra_reject_path("../escape.c"),FRA_ERR_POLICY,"TRAVERSAL");EQ(fra_reject_path("/absolute.c"),FRA_ERR_POLICY,"ABSOLUTE");EQ(fra_stage_write(&s,"../escape.c","x",1,11,&f),FRA_ERR_POLICY,"STAGE_TRAVERSAL");printf("M113_PATH_AND_WORKSPACE_POLICY_OK\n");const char*replacement="int main(void){return 1;}\n";OK(fra_stage_write(&s,"main.c",replacement,strlen(replacement),12,&f),"STAGE");if(!f.staged||f.version!=1)fail("STAGED_STATE",FRA_ERR_CONFLICT);printf("M113_BOUNDED_CODE_STAGING_OK version=%llu\n",(unsigned long long)f.version);OK(fra_rollback(&s,13,&w),"ROLLBACK");printf("M113_WORKSPACE_ROLLBACK_OK generation=%llu\n",(unsigned long long)w.generation);fra_close(&s);OK(fra_open(&s,root,jp),"REPLAY");OK(fra_query_file(&s,"main.c",&f),"REPLAY_QUERY");printf("M113_REPOSITORY_REPLAY_OK\n");OK(fra_test_corruption(&s),"CORRUPT_APPEND");fra_close(&s);EQ(fra_open(&s,root,jp),FRA_ERR_CORRUPT,"CORRUPTION");printf("M113_REPOSITORY_REPLAY_FAIL_CLOSED_OK\n");unlink(path);rmdir(root);unlink(jp);printf("M113_SELFTEST_EXIT=0\n");return 0;}
