/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_AGI_LIFECYCLE_H
#define _UAPI_LINUX_AGI_LIFECYCLE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define AGI_LC_ABI_VERSION 37
#define AGI_LC_DEVICE_NAME "agi_lifecycle"

#define AGI_LC_EVENT_BEGIN 1
#define AGI_LC_EVENT_END 2
#define AGI_LC_EVENT_REVOKE 3
#define AGI_LC_EVENT_CANCEL 4
#define AGI_LC_EVENT_PHASE 5
#define AGI_LC_EVENT_MEMORY_HINT 6
#define AGI_LC_EVENT_PERF 7
#define AGI_LC_EVENT_GATE 8
#define AGI_LC_EVENT_MESSAGE 9
#define AGI_LC_EVENT_EXPERIENCE 10
#define AGI_LC_EVENT_ACCEL 11
#define AGI_LC_EVENT_CHECKPOINT 12
#define AGI_LC_EVENT_BUDGET 13
#define AGI_LC_EVENT_MEMORY_BUDGET 14
#define AGI_LC_EVENT_HANDOFF 15
#define AGI_LC_EVENT_AGENT 16
#define AGI_LC_EVENT_LEASE 17
#define AGI_LC_EVENT_VERIFY 18
#define AGI_LC_EVENT_SCHED_HINT 19
#define AGI_LC_EVENT_MEMORY_REGION 20
#define AGI_LC_EVENT_MEMORY_SHARE 21
#define AGI_LC_EVENT_MEMORY_SNAPSHOT 22
#define AGI_LC_EVENT_MEMORY_REVOKE 23
#define AGI_LC_EVENT_RESOURCE_DEMAND 24
#define AGI_LC_EVENT_ACCEL_WORKLOAD 25
#define AGI_LC_EVENT_RECOVERY 26
#define AGI_LC_EVENT_LIGHT_AGENT 27
#define AGI_LC_EVENT_SECURITY_CAPABILITY 28
#define AGI_LC_EVENT_PROVENANCE 29
#define AGI_LC_EVENT_IPC 30
#define AGI_LC_EVENT_NETWORK_POLICY 31
#define AGI_LC_EVENT_KNOWLEDGE 32
#define AGI_LC_EVENT_BROWSER 33
#define AGI_LC_EVENT_MEMORY_RECORD 34
#define AGI_LC_EVENT_WORLD_SYNC 35
#define AGI_LC_EVENT_TEMPORAL 36
#define AGI_LC_EVENT_REFLECTION 37
#define AGI_LC_EVENT_OBSERVABILITY 38
#define AGI_LC_EVENT_GRAPH_OPERATION 39
#define AGI_LC_EVENT_POWER_POLICY 40

#define AGI_LC_AGENT_STATE_READY 0
#define AGI_LC_AGENT_STATE_BLOCKED 1
#define AGI_LC_AGENT_STATE_RUNNING 2
#define AGI_LC_AGENT_STATE_WAITING_IO 3
#define AGI_LC_AGENT_STATE_VERIFYING 4
#define AGI_LC_AGENT_STATE_COMPLETED 5
#define AGI_LC_AGENT_STATE_MAX AGI_LC_AGENT_STATE_COMPLETED
#define AGI_LC_SCHED_PRIORITY_MAX 1024
#define AGI_LC_GRAPH_NODE_CREATE 1U
#define AGI_LC_GRAPH_NODE_GET 2U
#define AGI_LC_GRAPH_NODE_COMPLETE 3U
#define AGI_LC_GRAPH_NODE_CANCEL 4U
#define AGI_LC_GRAPH_STATE_PENDING 0U
#define AGI_LC_GRAPH_STATE_READY 1U
#define AGI_LC_GRAPH_STATE_RUNNING 2U
#define AGI_LC_GRAPH_STATE_COMPLETE 3U
#define AGI_LC_GRAPH_STATE_CANCELLED 4U
#define AGI_LC_GRAPH_DEVICE_CPU (1U << 0)
#define AGI_LC_GRAPH_DEVICE_GPU (1U << 1)
#define AGI_LC_GRAPH_DEVICE_NPU (1U << 2)
#define AGI_LC_GRAPH_DEVICE_IO (1U << 3)
#define AGI_LC_GRAPH_DEVICE_ALL ((1U << 4) - 1)
#define AGI_LC_GRAPH_MAX_DEPS 8U
#define AGI_LC_GRAPH_MAX_NODES 64U
#define AGI_LC_CONTEXT_CREATE 1U
#define AGI_LC_CONTEXT_GET 2U
#define AGI_LC_CONTEXT_ATTACH_TASK 3U
#define AGI_LC_CONTEXT_DETACH_TASK 4U
#define AGI_LC_CONTEXT_BIND_REGION 5U
#define AGI_LC_CONTEXT_UNBIND_REGION 6U
#define AGI_LC_CONTEXT_CLOSE 7U
#define AGI_LC_CONTEXT_STATE_ACTIVE 1U
#define AGI_LC_CONTEXT_STATE_CLOSED 2U
#define AGI_LC_CONTEXT_DEVICE_CPU (1U << 0)
#define AGI_LC_CONTEXT_DEVICE_GPU (1U << 1)
#define AGI_LC_CONTEXT_DEVICE_NPU (1U << 2)
#define AGI_LC_CONTEXT_DEVICE_IO (1U << 3)
#define AGI_LC_CONTEXT_DEVICE_ALL ((1U << 4) - 1)
#define AGI_LC_CONTEXT_FABRIC_CPU (1ULL << 0)
#define AGI_LC_CONTEXT_FABRIC_DMA_BUF (1ULL << 1)
#define AGI_LC_CONTEXT_FABRIC_DMA_ENGINE (1ULL << 2)
#define AGI_LC_CONTEXT_FABRIC_IOMMU_SVA (1ULL << 3)
#define AGI_LC_CONTEXT_FABRIC_HMM (1ULL << 4)
#define AGI_LC_CONTEXT_FABRIC_UACCE (1ULL << 5)
#define AGI_LC_CONTEXT_FABRIC_ALL ((1ULL << 6) - 1)
#define AGI_LC_CONTEXT_ADDRESS_SPACE_NONE 0U
#define AGI_LC_CONTEXT_ADDRESS_SPACE_PROCESS 1U
#define AGI_LC_CONTEXT_PROVIDER_NONE 0U
#define AGI_LC_CONTEXT_PROVIDER_CPU 1U
#define AGI_LC_CONTEXT_PROVIDER_DRIVER 2U
#define AGI_LC_CONTEXT_MAX_TASKS 8U
#define AGI_LC_CONTEXT_MAX_REGIONS 8U
#define AGI_LC_CAP_SCOPE_NONE 0U
#define AGI_LC_CAP_SCOPE_TENSOR 1U
#define AGI_LC_CAP_SCOPE_CONTEXT 2U
#define AGI_LC_CAP_SCOPE_MAX AGI_LC_CAP_SCOPE_CONTEXT
#define AGI_LC_SCOPE_READ (1U << 0)
#define AGI_LC_SCOPE_WRITE (1U << 1)
#define AGI_LC_SCOPE_EXECUTE (1U << 2)
#define AGI_LC_SCOPE_ALL (AGI_LC_SCOPE_READ | AGI_LC_SCOPE_WRITE | AGI_LC_SCOPE_EXECUTE)
#define AGI_LC_PROVENANCE_BIND 1U
#define AGI_LC_PROVENANCE_BIND_GET 2U
#define AGI_LC_PROVENANCE_BIND_REVOKE 3U
#define AGI_LC_PROVENANCE_BIND_TENSOR 1U
#define AGI_LC_PROVENANCE_BIND_CONTEXT 2U
#define AGI_LC_TENSOR_TRANSPORT_REGISTER 1U
#define AGI_LC_TENSOR_TRANSPORT_QUERY 2U
#define AGI_LC_TENSOR_TRANSPORT_REVOKE 3U
#define AGI_LC_TRANSPORT_RDMA 1U
#define AGI_LC_TRANSPORT_DMA_BUF 2U
#define AGI_LC_TRANSPORT_SOCKET_RING 3U
#define AGI_LC_TRANSPORT_COLLECTIVE_NONE 0U
#define AGI_LC_TRANSPORT_ALLREDUCE 1U
#define AGI_LC_TRANSPORT_BROADCAST 2U
#define AGI_LC_TRANSPORT_REDUCE_SCATTER 3U
#define AGI_LC_TRANSPORT_ALLGATHER 4U
#define AGI_LC_TRANSPORT_SEND 1U
#define AGI_LC_TRANSPORT_RECV 2U
#define AGI_LC_TRANSPORT_BIDIRECTIONAL 3U
#define AGI_LC_TRANSPORT_REQUIRE_ZERO_COPY (1U << 0)
#define AGI_LC_TRANSPORT_REQUIRE_INTEGRITY (1U << 1)
#define AGI_LC_TRANSPORT_STATE_ACTIVE 1U
#define AGI_LC_TRANSPORT_STATE_REVOKED 2U
#define AGI_LC_EXEC_DOMAIN_CREATE 1U
#define AGI_LC_EXEC_DOMAIN_QUERY 2U
#define AGI_LC_EXEC_DOMAIN_RELEASE 3U
#define AGI_LC_EXEC_DOMAIN_REQUEST_NOHZ_FULL (1U << 0)
#define AGI_LC_EXEC_DOMAIN_REQUEST_IRQ_ISOLATION (1U << 1)
#define AGI_LC_EXEC_DOMAIN_REQUEST_PREEMPT_RT (1U << 2)
#define AGI_LC_EXEC_DOMAIN_REQUIRE_NOHZ_FULL (1U << 3)
#define AGI_LC_EXEC_DOMAIN_REQUIRE_IRQ_ISOLATION (1U << 4)
#define AGI_LC_EXEC_DOMAIN_REQUIRE_PREEMPT_RT (1U << 5)
#define AGI_LC_EXEC_DOMAIN_FEATURE_AFFINITY (1U << 0)
#define AGI_LC_EXEC_DOMAIN_FEATURE_HOUSEKEEPING (1U << 1)
#define AGI_LC_EXEC_DOMAIN_FEATURE_NOHZ_FULL (1U << 2)
#define AGI_LC_EXEC_DOMAIN_FEATURE_IRQ_ISOLATION (1U << 3)
#define AGI_LC_EXEC_DOMAIN_FEATURE_PREEMPT_RT (1U << 4)
#define AGI_LC_EXEC_DOMAIN_FEATURE_SMI_CONTROL (1U << 5)
#define AGI_LC_EXEC_DOMAIN_FEATURE_NMI_CONTROL (1U << 6)
#define AGI_LC_EXEC_DOMAIN_STATE_ACTIVE 1U
#define AGI_LC_EXEC_DOMAIN_STATE_RELEASED 2U
#define AGI_LC_EXEC_DOMAIN_CPU_WORDS 4U

#define AGI_LC_VERIFY_UNVERIFIED 0
#define AGI_LC_VERIFY_MATCHED 1
#define AGI_LC_VERIFY_FAILED 2
#define AGI_LC_KNOWLEDGE_PUBLISH 1
#define AGI_LC_KNOWLEDGE_QUERY 2
#define AGI_LC_KNOWLEDGE_CROSSCHECK 3
#define AGI_LC_KNOWLEDGE_VERIFY 4
#define AGI_LC_KNOWLEDGE_UPDATE 5
#define AGI_LC_KNOWLEDGE_FLAG_PRIMARY (1U << 0)
#define AGI_LC_KNOWLEDGE_FLAG_SECONDARY (1U << 1)
#define AGI_LC_KNOWLEDGE_FLAG_SIGNED (1U << 2)
#define AGI_LC_KNOWLEDGE_FLAG_INTEGRITY_MEASURED (1U << 3)
#define AGI_LC_KNOWLEDGE_FLAG_FRESHNESS_REQUIRED (1U << 4)
#define AGI_LC_KNOWLEDGE_SOURCE_UNKNOWN 0
#define AGI_LC_KNOWLEDGE_SOURCE_PRIMARY 1
#define AGI_LC_KNOWLEDGE_SOURCE_OFFICIAL 2
#define AGI_LC_KNOWLEDGE_SOURCE_CURATED 3
#define AGI_LC_KNOWLEDGE_SOURCE_SECONDARY 4
#define AGI_LC_KNOWLEDGE_VERIFY_UNVERIFIED 0
#define AGI_LC_KNOWLEDGE_VERIFY_VERIFIED 1
#define AGI_LC_KNOWLEDGE_VERIFY_STALE 2
#define AGI_LC_KNOWLEDGE_VERIFY_CONFLICT 3
#define AGI_LC_KNOWLEDGE_VERIFY_REJECTED 4
#define AGI_LC_KNOWLEDGE_CONFLICT_NONE 0
#define AGI_LC_KNOWLEDGE_CONFLICT_DETECTED 1
#define AGI_LC_KNOWLEDGE_CONFLICT_RESOLVED 2
#define AGI_LC_KNOWLEDGE_FRESHNESS_UNKNOWN 0
#define AGI_LC_KNOWLEDGE_FRESH 1
#define AGI_LC_KNOWLEDGE_STALE 2
#define AGI_LC_KNOWLEDGE_EXPIRED 3
#define AGI_LC_KNOWLEDGE_CONFIDENCE_MAX 1000000
#define AGI_LC_KNOWLEDGE_MAX_TTL_NS (30ULL * 24 * 60 * 60 * 1000000000ULL)
#define AGI_LC_BROWSER_OPEN 1
#define AGI_LC_BROWSER_RECORD 2
#define AGI_LC_BROWSER_QUERY 3
#define AGI_LC_BROWSER_CLOSE 4
#define AGI_LC_BROWSER_CANCEL 5
#define AGI_LC_BROWSER_KIND_NAVIGATE 1
#define AGI_LC_BROWSER_KIND_CLICK 2
#define AGI_LC_BROWSER_KIND_TYPE 3
#define AGI_LC_BROWSER_KIND_SCROLL 4
#define AGI_LC_BROWSER_KIND_DOM 5
#define AGI_LC_BROWSER_KIND_ACCESSIBILITY 6
#define AGI_LC_BROWSER_KIND_SCREENSHOT 7
#define AGI_LC_BROWSER_KIND_DOWNLOAD 8
#define AGI_LC_BROWSER_KIND_UPLOAD 9
#define AGI_LC_BROWSER_KIND_PAGE_STATE 10
#define AGI_LC_BROWSER_KIND_VERIFY 11
#define AGI_LC_BROWSER_KIND_MAX AGI_LC_BROWSER_KIND_VERIFY
#define AGI_LC_BROWSER_FLAG_SEMANTIC (1U << 0)
#define AGI_LC_BROWSER_FLAG_COORDINATE_FALLBACK (1U << 1)
#define AGI_LC_BROWSER_FLAG_USER_CONFIRMATION (1U << 2)
#define AGI_LC_BROWSER_FLAG_VERIFIED (1U << 3)
#define AGI_LC_BROWSER_STATE_INACTIVE 0
#define AGI_LC_BROWSER_STATE_OPEN 1
#define AGI_LC_BROWSER_STATE_COMPLETED 2
#define AGI_LC_BROWSER_STATE_CANCELLED 3
#define AGI_LC_BROWSER_MAX_SESSIONS 32
#define AGI_LC_BROWSER_MAX_ACTIONS 65536
#define AGI_LC_MEMORY_RECORD_CREATE 1
#define AGI_LC_MEMORY_RECORD_UPSERT 2
#define AGI_LC_MEMORY_RECORD_QUERY 3
#define AGI_LC_MEMORY_RECORD_CORRECT 4
#define AGI_LC_MEMORY_RECORD_DELETE 5
#define AGI_LC_MEMORY_RECORD_EXPIRE 6
#define AGI_LC_MEMORY_RECORD_RESOLVE 7
#define AGI_LC_MEMORY_RECORD_DEDUP 8
#define AGI_LC_MEMORY_RECORD_REVALIDATE 9
#define AGI_LC_MEMORY_TIER_WORKING 1
#define AGI_LC_MEMORY_TIER_EPISODIC 2
#define AGI_LC_MEMORY_TIER_SEMANTIC 3
#define AGI_LC_MEMORY_TIER_PROCEDURAL 4
#define AGI_LC_MEMORY_TIER_WORLD_MODEL 5
#define AGI_LC_MEMORY_TIER_LONG_TERM 6
#define AGI_LC_MEMORY_TIER_MAX AGI_LC_MEMORY_TIER_LONG_TERM
#define AGI_LC_MEMORY_RECORD_FLAG_DURABLE (1U << 0)
#define AGI_LC_MEMORY_RECORD_FLAG_IMMUTABLE (1U << 1)
#define AGI_LC_MEMORY_RECORD_FLAG_VERIFIED (1U << 2)
#define AGI_LC_MEMORY_RECORD_FLAG_TOMBSTONE (1U << 3)
#define AGI_LC_MEMORY_RECORD_FLAG_EXPIRED (1U << 4)
#define AGI_LC_MEMORY_RECORD_FLAG_CONFLICT (1U << 5)
#define AGI_LC_MEMORY_RECORD_FLAGS_ALL ((1U << 6) - 1)
#define AGI_LC_MEMORY_STATE_ACTIVE 0
#define AGI_LC_MEMORY_STATE_DELETED 1
#define AGI_LC_MEMORY_STATE_EXPIRED 2
#define AGI_LC_MEMORY_STATE_CONFLICT 3
#define AGI_LC_MEMORY_STATE_MAX AGI_LC_MEMORY_STATE_CONFLICT
#define AGI_LC_MEMORY_CONFLICT_NONE 0
#define AGI_LC_MEMORY_CONFLICT_DETECTED 1
#define AGI_LC_MEMORY_CONFLICT_RESOLVED 2
#define AGI_LC_MEMORY_FRESHNESS_UNKNOWN 0
#define AGI_LC_MEMORY_FRESH 1
#define AGI_LC_MEMORY_STALE 2
#define AGI_LC_MEMORY_EXPIRED 3
#define AGI_LC_MEMORY_CONFIDENCE_MAX 1000000
#define AGI_LC_MEMORY_RECORDS 256
#define AGI_LC_WORLD_SYNC_QUERY 1
#define AGI_LC_WORLD_SYNC_ACK 2
#define AGI_LC_WORLD_SYNC_RESYNC 3
#define AGI_LC_WORLD_SYNC_FLAGS_ALL 0U
#define AGI_LC_TEMPORAL_RECORD 1
#define AGI_LC_TEMPORAL_QUERY 2
#define AGI_LC_TEMPORAL_CHECK 3
#define AGI_LC_TEMPORAL_UPDATE 4
#define AGI_LC_TEMPORAL_STATE_ACTIVE 0
#define AGI_LC_TEMPORAL_STATE_SATISFIED 1
#define AGI_LC_TEMPORAL_STATE_VIOLATED 2
#define AGI_LC_TEMPORAL_STATE_EXPIRED 3
#define AGI_LC_TEMPORAL_RESULT_UNKNOWN 0
#define AGI_LC_TEMPORAL_RESULT_OK 1
#define AGI_LC_TEMPORAL_RESULT_VIOLATED 2
#define AGI_LC_TEMPORAL_FLAG_EVENT_REALTIME 0x00000001U
#define AGI_LC_TEMPORAL_FLAG_EVENT_BOOTTIME 0x00000002U
#define AGI_LC_TEMPORAL_FLAG_DEADLINE 0x00000004U
#define AGI_LC_TEMPORAL_FLAG_PARENT 0x00000008U
#define AGI_LC_TEMPORAL_FLAG_REFERENCE 0x00000010U
#define AGI_LC_TEMPORAL_FLAGS_ALL (AGI_LC_TEMPORAL_FLAG_EVENT_REALTIME | \
                                  AGI_LC_TEMPORAL_FLAG_EVENT_BOOTTIME | \
                                  AGI_LC_TEMPORAL_FLAG_DEADLINE | \
                                  AGI_LC_TEMPORAL_FLAG_PARENT | \
                                  AGI_LC_TEMPORAL_FLAG_REFERENCE)
#define AGI_LC_REFLECTION_SNAPSHOT 1
#define AGI_LC_REFLECTION_ACTION_BEGIN 2
#define AGI_LC_REFLECTION_ACTION_END 3
#define AGI_LC_REFLECTION_ACTION_QUERY 4
#define AGI_LC_REFLECTION_DEPENDENCY_BLOCK 5
#define AGI_LC_REFLECTION_DEPENDENCY_QUERY 6
#define AGI_LC_REFLECTION_STATE_ACTIVE 0
#define AGI_LC_REFLECTION_STATE_COMPLETED 1
#define AGI_LC_REFLECTION_STATE_FAILED 2
#define AGI_LC_REFLECTION_STATE_BLOCKED 3
#define AGI_LC_REFLECTION_STATE_CANCELLED 4
#define AGI_LC_REFLECTION_FLAG_DEPENDENCY 0x00000001U
#define AGI_LC_REFLECTION_FLAG_FAILURE 0x00000002U
#define AGI_LC_REFLECTION_FLAGS_ALL (AGI_LC_REFLECTION_FLAG_DEPENDENCY | \
                                     AGI_LC_REFLECTION_FLAG_FAILURE)
#define AGI_LC_OBSERVABILITY_SET 1
#define AGI_LC_OBSERVABILITY_QUERY 2
#define AGI_LC_OBSERVABILITY_RESET 3
#define AGI_LC_OBSERVABILITY_FLAG_ENABLE 0x00000001U
#define AGI_LC_OBSERVABILITY_FLAG_SAMPLE 0x00000002U
#define AGI_LC_OBSERVABILITY_FLAG_TRACEFS_CORRELATION 0x00000004U
#define AGI_LC_OBSERVABILITY_FLAGS_ALL (AGI_LC_OBSERVABILITY_FLAG_ENABLE | \
                                       AGI_LC_OBSERVABILITY_FLAG_SAMPLE | \
                                       AGI_LC_OBSERVABILITY_FLAG_TRACEFS_CORRELATION)
#define AGI_LC_OBSERVABILITY_MAX_SAMPLE_PERIOD 1048576U
#define AGI_LC_GRAPH_TELEMETRY_BEGIN 1U
#define AGI_LC_GRAPH_TELEMETRY_END 2U
#define AGI_LC_GRAPH_TELEMETRY_FAIL 3U
#define AGI_LC_GRAPH_TELEMETRY_CHECKPOINT 4U
#define AGI_LC_GRAPH_TELEMETRY_ANOMALY 5U
#define AGI_LC_GRAPH_TELEMETRY_QUERY 6U
#define AGI_LC_GRAPH_TELEMETRY_STATE_ACTIVE 1U
#define AGI_LC_GRAPH_TELEMETRY_STATE_COMPLETE 2U
#define AGI_LC_GRAPH_TELEMETRY_STATE_FAILED 3U
#define AGI_LC_GRAPH_TELEMETRY_STATE_CHECKPOINTED 4U
#define AGI_LC_GRAPH_TELEMETRY_FLAG_CONTEXT (1U << 0)
#define AGI_LC_GRAPH_TELEMETRY_FLAG_TENSOR (1U << 1)
#define AGI_LC_GRAPH_TELEMETRY_FLAG_TRANSPORT (1U << 2)
#define AGI_LC_GRAPH_TELEMETRY_FLAG_PROVENANCE (1U << 3)
#define AGI_LC_GRAPH_TELEMETRY_FLAG_PROVIDER_MEASURED (1U << 4)
#define AGI_LC_GRAPH_TELEMETRY_FLAG_ANOMALY (1U << 5)
#define AGI_LC_GRAPH_TELEMETRY_FLAGS_ALL ((1U << 6) - 1)
#define AGI_LC_GRAPH_TELEMETRY_MAX_OPERATOR_KIND 4096U
#define AGI_LC_GRAPH_TELEMETRY_MAX_ANOMALY_SCORE 1000000U
#define AGI_LC_MEMORY_MAX_TTL_NS (365ULL * 24 * 60 * 60 * 1000000000ULL)
#define AGI_LC_POWER_POLICY_SET 1U
#define AGI_LC_POWER_POLICY_QUERY 2U
#define AGI_LC_POWER_POLICY_RELEASE 3U
#define AGI_LC_POWER_PROFILE_INFERENCE 1U
#define AGI_LC_POWER_PROFILE_TRAINING 2U
#define AGI_LC_POWER_PROFILE_BACKGROUND 3U
#define AGI_LC_POWER_PROFILE_RECOVERY 4U
#define AGI_LC_POWER_PROFILE_MAX AGI_LC_POWER_PROFILE_RECOVERY
#define AGI_LC_POWER_POLICY_STATE_ACTIVE 1U
#define AGI_LC_POWER_POLICY_STATE_RELEASED 2U
#define AGI_LC_POWER_POLICY_FLAG_CPU_LATENCY_QOS (1U << 0)
#define AGI_LC_POWER_POLICY_FLAG_DEVICE_WAKE_LATENCY (1U << 1)
#define AGI_LC_POWER_POLICY_FLAG_NO_POWER_OFF (1U << 2)
#define AGI_LC_POWER_POLICY_FLAG_POWER_BUDGET (1U << 3)
#define AGI_LC_POWER_POLICY_FLAG_REQUESTED_PROVIDER (1U << 4)
#define AGI_LC_POWER_POLICY_FLAG_REQUIRE_ALL (1U << 5)
#define AGI_LC_POWER_POLICY_FLAGS_ALL ((1U << 6) - 1)
#define AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS (1U << 0)
#define AGI_LC_POWER_POLICY_FEATURE_DEVICE_WAKE_LATENCY (1U << 1)
#define AGI_LC_POWER_POLICY_FEATURE_NO_POWER_OFF (1U << 2)
#define AGI_LC_POWER_POLICY_FEATURE_POWER_BUDGET (1U << 3)
#define AGI_LC_POWER_POLICY_FEATURE_ENERGY_MODEL (1U << 4)
#define AGI_LC_POWER_POLICY_FEATURE_THERMAL_COORDINATION (1U << 5)
#define AGI_LC_POWER_POLICY_FEATURE_ACCELERATOR_PROVIDER (1U << 6)
#define AGI_LC_POWER_POLICY_FEATURES_ALL ((1U << 7) - 1)
#define AGI_LC_POWER_POLICY_MAX_LATENCY_US (60U * 1000U * 1000U)
#define AGI_LC_POWER_POLICY_MAX_BUDGET_UW (1ULL << 40)
#define AGI_LC_POWER_POLICY_CPU_UTIL_MAX 1024U

#define AGI_LC_RECOVERY_NONE 0
#define AGI_LC_RECOVERY_CRASHED 1
#define AGI_LC_RECOVERY_RESTORE_PENDING 2
#define AGI_LC_RECOVERY_RESTORED 3
#define AGI_LC_RECOVERY_CONTINUED 4
#define AGI_LC_RECOVERY_MAX AGI_LC_RECOVERY_CONTINUED

#define AGI_LC_RECOVERY_MARK_CRASH 1
#define AGI_LC_RECOVERY_RESTORE_BEGIN 2
#define AGI_LC_RECOVERY_CONTINUE 3
#define AGI_LC_RECOVERY_ACTION_MAX AGI_LC_RECOVERY_CONTINUE

#define AGI_LC_CHECKPOINT_SCOPE_TASK (1U << 0)
#define AGI_LC_CHECKPOINT_SCOPE_MEMORY (1U << 1)
#define AGI_LC_CHECKPOINT_SCOPE_RESOURCES (1U << 2)
#define AGI_LC_CHECKPOINT_SCOPE_USER_STATE (1U << 3)
#define AGI_LC_CHECKPOINT_SCOPE_OPEN_RESOURCES (1U << 4)
#define AGI_LC_CHECKPOINT_SCOPE_ALL ((1U << 5) - 1)

#define AGI_LC_CHECKPOINT_RESOURCE_USERSPACE (1U << 0)
#define AGI_LC_CHECKPOINT_RESOURCE_UNSUPPORTED (1U << 1)
#define AGI_LC_CHECKPOINT_RESOURCE_FILES (1U << 2)
#define AGI_LC_CHECKPOINT_RESOURCE_SOCKETS (1U << 3)
#define AGI_LC_CHECKPOINT_RESOURCE_ACCELERATOR (1U << 4)
#define AGI_LC_CHECKPOINT_RESOURCE_MAX ((1U << 5) - 1)

#define AGI_LC_CHECKPOINT_REGION_MAX 8

#define AGI_LC_LEASE_MAX 32
#define AGI_LC_LEASE_NETWORK 1
#define AGI_LC_LEASE_STORAGE 2
#define AGI_LC_LEASE_ACCELERATOR 3
#define AGI_LC_LEASE_TOOL 4

#define AGI_LC_MESSAGE_MAX 256
#define AGI_LC_EXPERIENCE_MAX 256
#define AGI_LC_EXPERIENCE_RECORD_MAX 64
#define AGI_LC_EXPERIENCE_ACTION 1
#define AGI_LC_EXPERIENCE_OBSERVATION 2
#define AGI_LC_EXPERIENCE_RESULT 3
#define AGI_LC_EXPERIENCE_FAILURE 4
#define AGI_LC_LEARNING_MEMORY 1
#define AGI_LC_LEARNING_SKILL 2
#define AGI_LC_LEARNING_STRATEGY 3
#define AGI_LC_LEARNING_MODEL_TRAINING 4
#define AGI_LC_DIGEST_SIZE 32
#define AGI_LC_MEMORY_REGION_WORKING (1U << 0)
#define AGI_LC_MEMORY_REGION_SHARED (1U << 1)
#define AGI_LC_MEMORY_REGION_PERSISTENT (1U << 2)
#define AGI_LC_MEMORY_REGION_SNAPSHOTABLE (1U << 3)
#define AGI_LC_TENSOR_POLICY_SET 1U
#define AGI_LC_TENSOR_POLICY_GET 2U
#define AGI_LC_TENSOR_FLAG_READ_MOSTLY (1U << 0)
#define AGI_LC_TENSOR_FLAG_NO_SWAP_PREFERRED (1U << 1)
#define AGI_LC_TENSOR_FLAG_HUGEPAGE_PREFERRED (1U << 2)
#define AGI_LC_TENSOR_FLAG_CONTIGUOUS_VA (1U << 3)
#define AGI_LC_TENSOR_FLAG_PHYSICALLY_CONTIGUOUS (1U << 4)
#define AGI_LC_TENSOR_FLAG_TIER_STRICT (1U << 5)
#define AGI_LC_TENSOR_FLAGS_ALL ((1U << 6) - 1)
#define AGI_LC_TENSOR_TIER_HBM (1U << 0)
#define AGI_LC_TENSOR_TIER_DDR (1U << 1)
#define AGI_LC_TENSOR_TIER_NVME (1U << 2)
#define AGI_LC_TENSOR_TIER_NETWORK (1U << 3)
#define AGI_LC_TENSOR_TIER_FLAGS_ALL ((1U << 4) - 1)
#define AGI_LC_TENSOR_MAX_RANK 8U
#define AGI_LC_TENSOR_MAX_ELEMENT_SIZE 16U
#define AGI_LC_TENSOR_MAX_ALIGNMENT (1ULL << 30)
#define AGI_LC_TENSOR_NUMA_ANY (-1)
#define AGI_LC_MEMORY_ACCESS_READ (1U << 0)
#define AGI_LC_MEMORY_ACCESS_WRITE (1U << 1)

#define AGI_LC_WORLD_EVENT_PROCESS 1
#define AGI_LC_WORLD_EVENT_RESOURCE 2
#define AGI_LC_WORLD_EVENT_FILESYSTEM 3
#define AGI_LC_WORLD_EVENT_NETWORK 4
#define AGI_LC_WORLD_EVENT_DEVICE 5
#define AGI_LC_WORLD_EVENT_MEMORY_PRESSURE 6
#define AGI_LC_WORLD_EVENT_CPU_PRESSURE 7
#define AGI_LC_WORLD_EVENT_ACCELERATOR 8
#define AGI_LC_WORLD_EVENT_SECURITY 9
#define AGI_LC_WORLD_EVENT_TIMER 10
#define AGI_LC_WORLD_EVENT_TASK_STATE 11
#define AGI_LC_WORLD_EVENT_CHECKPOINT 12
#define AGI_LC_WORLD_EVENT_MAX AGI_LC_WORLD_EVENT_CHECKPOINT

#define AGI_LC_WORLD_PRIORITY_LOW 0
#define AGI_LC_WORLD_PRIORITY_NORMAL 1
#define AGI_LC_WORLD_PRIORITY_HIGH 2
#define AGI_LC_WORLD_PRIORITY_CRITICAL 3

#define AGI_LC_WORLD_QUEUE_DROP_NEW 0
#define AGI_LC_WORLD_QUEUE_DROP_OLD 1
#define AGI_LC_WORLD_QUEUE_DROP_LOW 2

#define AGI_LC_SELF_RESOURCE_CGROUP (1U << 0)
#define AGI_LC_SELF_RESOURCE_PSI (1U << 1)
#define AGI_LC_SELF_RESOURCE_UPSTREAM (1U << 2)

#define AGI_LC_RESOURCE_CPU (1U << 0)
#define AGI_LC_RESOURCE_RAM (1U << 1)
#define AGI_LC_RESOURCE_GPU (1U << 2)
#define AGI_LC_RESOURCE_NPU (1U << 3)
#define AGI_LC_RESOURCE_VRAM (1U << 4)
#define AGI_LC_RESOURCE_STORAGE (1U << 5)
#define AGI_LC_RESOURCE_NETWORK (1U << 6)
#define AGI_LC_RESOURCE_IO (1U << 7)
#define AGI_LC_RESOURCE_ALL ((1U << 8) - 1)

#define AGI_LC_WORKLOAD_INFERENCE 1
#define AGI_LC_WORKLOAD_TRAINING 2
#define AGI_LC_WORKLOAD_BROWSER 3
#define AGI_LC_WORKLOAD_RESEARCH 4
#define AGI_LC_WORKLOAD_CODE_EXECUTION 5
#define AGI_LC_WORKLOAD_SIMULATION 6
#define AGI_LC_WORKLOAD_PLANNING 7
#define AGI_LC_WORKLOAD_VERIFICATION 8
#define AGI_LC_WORKLOAD_BACKGROUND_LEARNING 9
#define AGI_LC_WORKLOAD_MAX AGI_LC_WORKLOAD_BACKGROUND_LEARNING

#define AGI_LC_LIGHT_AGENT_MAX 2048
#define AGI_LC_LIGHT_AGENT_MAILBOX_SLOTS 4
#define AGI_LC_LIGHT_AGENT_MESSAGE_MAX 128
#define AGI_LC_LIGHT_AGENT_ROLE_PLANNER 1
#define AGI_LC_LIGHT_AGENT_ROLE_RESEARCHER 2
#define AGI_LC_LIGHT_AGENT_ROLE_CODER 3
#define AGI_LC_LIGHT_AGENT_ROLE_TESTER 4
#define AGI_LC_LIGHT_AGENT_ROLE_SECURITY 5
#define AGI_LC_LIGHT_AGENT_ROLE_BROWSER 6
#define AGI_LC_LIGHT_AGENT_ROLE_VERIFIER 7
#define AGI_LC_LIGHT_AGENT_ROLE_MEMORY 8
#define AGI_LC_LIGHT_AGENT_ROLE_INFRASTRUCTURE 9
#define AGI_LC_LIGHT_AGENT_ROLE_OPTIMIZER 10
#define AGI_LC_LIGHT_AGENT_ROLE_MAX AGI_LC_LIGHT_AGENT_ROLE_OPTIMIZER
#define AGI_LC_LIGHT_AGENT_STATE_READY 0
#define AGI_LC_LIGHT_AGENT_STATE_RUNNING 1
#define AGI_LC_LIGHT_AGENT_STATE_BLOCKED 2
#define AGI_LC_LIGHT_AGENT_STATE_WAITING 3
#define AGI_LC_LIGHT_AGENT_STATE_COMPLETED 4
#define AGI_LC_LIGHT_AGENT_STATE_FAILED 5
#define AGI_LC_LIGHT_AGENT_STATE_MAX AGI_LC_LIGHT_AGENT_STATE_FAILED

#define AGI_LC_CAP_FS_READ (1ULL << 0)
#define AGI_LC_CAP_FS_WRITE (1ULL << 1)
#define AGI_LC_CAP_NET_CONNECT (1ULL << 2)
#define AGI_LC_CAP_NET_LISTEN (1ULL << 3)
#define AGI_LC_CAP_PROCESS_INSPECT (1ULL << 4)
#define AGI_LC_CAP_PROCESS_CONTROL (1ULL << 5)
#define AGI_LC_CAP_DEVICE_USE (1ULL << 6)
#define AGI_LC_CAP_BROWSER_CONTROL (1ULL << 7)
#define AGI_LC_CAP_SECRET_READ (1ULL << 8)
#define AGI_LC_CAP_PRIVILEGED_API (1ULL << 9)
#define AGI_LC_CAP_MEMORY_SHARE (1ULL << 10)
#define AGI_LC_CAP_RESOURCE_DELEGATE (1ULL << 11)
#define AGI_LC_CAP_TENSOR_READ (1ULL << 12)
#define AGI_LC_CAP_TENSOR_WRITE (1ULL << 13)
#define AGI_LC_CAP_COMPUTE_EXECUTE (1ULL << 14)
#define AGI_LC_CAP_RIGHTS_ALL ((1ULL << 15) - 1)
#define AGI_LC_CAP_SANDBOX_USER_NAMESPACE (1U << 0)
#define AGI_LC_CAP_SANDBOX_MOUNT_NAMESPACE (1U << 1)
#define AGI_LC_CAP_SANDBOX_NETWORK_NAMESPACE (1U << 2)
#define AGI_LC_CAP_SANDBOX_CGROUP (1U << 3)
#define AGI_LC_CAP_SANDBOX_LSM_LANDLOCK (1U << 4)
#define AGI_LC_CAP_SANDBOX_SECCOMP (1U << 5)
#define AGI_LC_CAP_SANDBOX_MEMORY (1U << 6)
#define AGI_LC_CAP_SANDBOX_ALL ((1U << 7) - 1)
#define AGI_LC_CAP_STATUS_ACTIVE 0
#define AGI_LC_CAP_STATUS_DENIED 1
#define AGI_LC_CAP_STATUS_REVOKED 2
#define AGI_LC_PROVENANCE_PUBLISH_ACTION 1
#define AGI_LC_PROVENANCE_PUBLISH_RESULT 2
#define AGI_LC_PROVENANCE_RECORD_MAX 128
#define AGI_LC_KNOWLEDGE_RECORDS 128
#define AGI_LC_IPC_CHANNEL_MAX 64
#define AGI_LC_IPC_QUEUE_MAX 64
#define AGI_LC_IPC_INLINE_MAX 256
#define AGI_LC_IPC_PRIORITY_MAX 3
#define AGI_LC_IPC_MSG_NONBLOCK (1U << 0)
#define AGI_LC_IPC_MSG_STREAM_BEGIN (1U << 1)
#define AGI_LC_IPC_MSG_STREAM_MORE (1U << 2)
#define AGI_LC_IPC_MSG_STREAM_END (1U << 3)
#define AGI_LC_IPC_MSG_LARGE (1U << 4)
#define AGI_LC_CANCEL_NONBLOCK (1U << 0)
#define AGI_LC_CANCEL_CONTROL_REQUEST (1U << 0)
#define AGI_LC_CANCEL_CONTROL_QUERY (1U << 1)
#define AGI_LC_CANCEL_CONTROL_ESCALATE (1U << 2)
#define AGI_LC_CANCEL_CONTROL_ACKNOWLEDGE (1U << 3)
#define AGI_LC_CANCEL_FLAG_CHECKPOINT (1U << 0)
#define AGI_LC_CANCEL_FLAG_REVOKE_RESOURCES (1U << 1)
#define AGI_LC_CANCEL_FLAG_DEPRIORITIZE (1U << 2)
#define AGI_LC_CANCEL_MODE_GRACEFUL 0
#define AGI_LC_CANCEL_MODE_FORCED 1
#define AGI_LC_CANCEL_SCOPE_TASK 0
#define AGI_LC_CANCEL_SCOPE_CHILDREN 1
#define AGI_LC_CANCEL_SCOPE_LINEAGE 2
#define AGI_LC_CANCEL_SCOPE_DEPENDENTS 3
#define AGI_LC_CANCEL_DEPENDENCY_NONE 0
#define AGI_LC_CANCEL_DEPENDENCY_CHILDREN 1
#define AGI_LC_CANCEL_DEPENDENCY_AGENT_TREE 2
#define AGI_LC_CANCEL_STATE_REQUESTED 0
#define AGI_LC_CANCEL_STATE_PROPAGATING 1
#define AGI_LC_CANCEL_STATE_GRACEFUL 2
#define AGI_LC_CANCEL_STATE_FORCED 3
#define AGI_LC_CANCEL_STATE_COMPLETED 4
#define AGI_LC_CANCEL_STATE_EXPIRED 5
#define AGI_LC_CANCEL_STATE_FAILED 6

#define AGI_LC_NET_POLICY_APPLY (1U << 0)
#define AGI_LC_NET_POLICY_QUERY (1U << 1)
#define AGI_LC_NET_POLICY_REVOKE (1U << 2)
#define AGI_LC_NET_POLICY_OP_SOCKET (1U << 0)
#define AGI_LC_NET_POLICY_OP_CONNECT (1U << 1)
#define AGI_LC_NET_POLICY_OP_LISTEN (1U << 2)
#define AGI_LC_NET_POLICY_OP_SEND (1U << 3)
#define AGI_LC_NET_POLICY_OP_RECV (1U << 4)
#define AGI_LC_NET_POLICY_OP_BIND (1U << 5)
#define AGI_LC_NET_POLICY_FLAG_AUDIT (1U << 0)
#define AGI_LC_NET_POLICY_FLAG_DENY_RAW (1U << 1)
#define AGI_LC_NET_POLICY_FLAG_DENY_LISTEN (1U << 2)
#define AGI_LC_NET_POLICY_FLAG_ACCOUNT_BYTES (1U << 3)
#define AGI_LC_NET_POLICY_STATE_INACTIVE 0
#define AGI_LC_NET_POLICY_STATE_ACTIVE 1
#define AGI_LC_NET_POLICY_STATE_REVOKED 2
#define AGI_LC_NET_POLICY_MAX_SOCKETS 4096
#define AGI_LC_NET_POLICY_MAX_FAMILY 63

#define AGI_LC_RESOURCE_STATUS_REQUESTED 0
#define AGI_LC_RESOURCE_STATUS_PARTIAL 1
#define AGI_LC_RESOURCE_STATUS_ENFORCED 2
#define AGI_LC_RESOURCE_STATUS_UNSUPPORTED 3

#define AGI_LC_ACCEL_TYPE_GPU 1
#define AGI_LC_ACCEL_TYPE_NPU 2
#define AGI_LC_ACCEL_TYPE_COMPUTE 3
#define AGI_LC_ACCEL_TYPE_DMA 4
#define AGI_LC_ACCEL_TYPE_OTHER 5
#define AGI_LC_ACCEL_TYPE_MAX AGI_LC_ACCEL_TYPE_OTHER

#define AGI_LC_ACCEL_CAP_SVA (1U << 0)
#define AGI_LC_ACCEL_CAP_PASID (1U << 1)
#define AGI_LC_ACCEL_CAP_PAGE_FAULTS (1U << 2)
#define AGI_LC_ACCEL_CAP_PREEMPTION (1U << 3)
#define AGI_LC_ACCEL_CAP_DEVICE_MEMORY (1U << 4)
#define AGI_LC_ACCEL_CAP_SHARED_MEMORY (1U << 5)
#define AGI_LC_ACCEL_CAP_VIRTUALIZATION (1U << 6)
#define AGI_LC_ACCEL_CAP_POWER_CONTROL (1U << 7)
#define AGI_LC_ACCEL_CAP_MAX ((1U << 8) - 1)

#define AGI_LC_ACCEL_ACCOUNT_COMPUTE (1U << 0)
#define AGI_LC_ACCEL_ACCOUNT_MEMORY (1U << 1)
#define AGI_LC_ACCEL_ACCOUNT_SUBMISSIONS (1U << 2)
#define AGI_LC_ACCEL_ACCOUNT_EXACT (1U << 3)
#define AGI_LC_ACCEL_ACCOUNT_MAX ((1U << 4) - 1)

#define AGI_LC_ACCEL_ISOLATION_IOMMU (1U << 0)
#define AGI_LC_ACCEL_ISOLATION_SVA (1U << 1)
#define AGI_LC_ACCEL_ISOLATION_EXCLUSIVE (1U << 2)
#define AGI_LC_ACCEL_ISOLATION_DRIVER (1U << 3)
#define AGI_LC_ACCEL_ISOLATION_MAX ((1U << 4) - 1)

#define AGI_LC_ACCEL_COORD_SCHEDULER (1U << 0)
#define AGI_LC_ACCEL_COORD_FENCE (1U << 1)
#define AGI_LC_ACCEL_COORD_MEMORY (1U << 2)
#define AGI_LC_ACCEL_COORD_POWER (1U << 3)
#define AGI_LC_ACCEL_COORD_MAX ((1U << 4) - 1)

#define AGI_LC_ACCEL_WORKLOAD_BOUND 1

#define AGI_LC_RESOURCE_ENERGY_AVAILABLE (1U << 0)

#define AGI_LC_PHASE_IDLE 0
#define AGI_LC_PHASE_PLAN 1
#define AGI_LC_PHASE_EXECUTE 2
#define AGI_LC_PHASE_OBSERVE 3
#define AGI_LC_PHASE_VERIFY 4
#define AGI_LC_PHASE_RECOVER 5
#define AGI_LC_PHASE_WAIT 6
#define AGI_LC_PHASE_STOP 7
#define AGI_LC_PHASE_MAX AGI_LC_PHASE_STOP

#define AGI_LC_REVOKE_USER 1
#define AGI_LC_REVOKE_CLOSE 2

struct agi_lc_create {
	__u32 size;
	__u32 flags;
	__u64 session_id;
	__u64 reserved[2];
};

struct agi_lc_event {
	__u32 size;
	__u16 type;
	__u16 flags;
	__s32 status;
	__u32 reserved;
	__u64 correlation;
	__u64 metadata;
};

struct agi_lc_verify {
	__u32 size;
	__u32 flags;
	__s32 status;
	__u32 state;
	__u64 checkpoint_id;
	__u64 checkpoint_sequence;
	__u64 parent_sequence;
	__u8 state_digest[AGI_LC_DIGEST_SIZE];
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_handoff {
	__u32 size;
	__u32 flags;
	__u64 checkpoint_id;
	__u64 checkpoint_sequence;
	__u64 parent_sequence;
	__u32 phase;
	__u32 gate_open;
	__u64 event_mask;
	__u64 cpu_budget_ns;
	__u64 memory_limit_pages;
	__u8 state_digest[AGI_LC_DIGEST_SIZE];
	__u64 correlation;
	__u32 validated;
	__u32 reserved;
	__u64 reserved2[2];
};

struct agi_lc_checkpoint_manifest {
	__u32 size;
	__u32 flags;
	__u64 checkpoint_id;
	__u64 checkpoint_sequence;
	__u64 parent_sequence;
	__u64 lineage_id;
	__u64 agent_id;
	__u32 phase;
	__u32 recovery_state;
	__u32 scope_flags;
	__u32 resource_policy;
	__u64 cpu_budget_ns;
	__u64 memory_limit_pages;
	__u32 region_count;
	__u32 reserved32;
	__u64 region_ids[AGI_LC_CHECKPOINT_REGION_MAX];
	__u64 region_generations[AGI_LC_CHECKPOINT_REGION_MAX];
	__u8 user_state_digest[AGI_LC_DIGEST_SIZE];
	__u8 manifest_digest[AGI_LC_DIGEST_SIZE];
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_recovery {
	__u32 size;
	__u32 action;
	__s32 status;
	__u32 state;
	__u64 checkpoint_id;
	__u64 checkpoint_sequence;
	__u64 recovery_sequence;
	__u64 parent_sequence;
	__u64 lineage_id;
	__u64 agent_id;
	__u32 phase;
	__u32 flags;
	__u32 scope_flags;
	__u32 resource_policy;
	__u64 cpu_budget_ns;
	__u64 memory_limit_pages;
	__u32 region_count;
	__u32 reserved32;
	__u64 region_ids[AGI_LC_CHECKPOINT_REGION_MAX];
	__u64 region_generations[AGI_LC_CHECKPOINT_REGION_MAX];
	__u8 user_state_digest[AGI_LC_DIGEST_SIZE];
	__u8 manifest_digest[AGI_LC_DIGEST_SIZE];
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_memory_budget {
	__u32 size;
	__u32 flags;
	__u64 limit_pages;
	__u64 current_pages;
	__u32 exceeded;
	__u32 reserved;
	__u64 correlation;
	__u64 reserved2[2];
};

struct agi_lc_budget {
	__u32 size;
	__u32 flags;
	__u64 cpu_time_ns;
	__u64 elapsed_ns;
	__u32 exhausted;
	__u32 reserved;
	__u64 correlation;
	__u64 reserved2[2];
};

struct agi_lc_checkpoint {
	__u32 size;
	__u32 flags;
	__s32 status;
	__u32 reserved;
	__u64 checkpoint_id;
	__u64 parent_sequence;
	__u64 checkpoint_sequence;
	__u8 state_digest[AGI_LC_DIGEST_SIZE];
	__u64 correlation;
	__u64 reserved2[2];
};

struct agi_lc_subscribe {
	__u32 size;
	__u32 flags;
	__u64 event_mask;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_accel {
	__u32 size;
	__u32 flags;
	__u64 compute_ns;
	__u64 memory_bytes;
	__u64 submissions;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_experience {
	__u32 size;
	__u32 flags;
	__s32 status;
	__u32 length;
	__u64 correlation;
	__u64 parent_sequence;
	__u64 experience_sequence;
	__u8 digest[AGI_LC_DIGEST_SIZE];
	__u8 payload[AGI_LC_EXPERIENCE_MAX];
};

struct agi_lc_experience_record {
	__u32 size;
	__u32 flags;
	__u32 kind;
	__u32 verification_state;
	__s32 status;
	__u32 failure_code;
	__u64 correlation;
	__u64 parent_sequence;
	__u64 experience_sequence;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 pid;
	__u64 tgid;
	__u64 started_at_ns;
	__u64 finished_at_ns;
	__u64 cpu_time_ns;
	__u64 memory_bytes;
	__u8 action_digest[AGI_LC_DIGEST_SIZE];
	__u8 observation_digest[AGI_LC_DIGEST_SIZE];
	__u8 result_digest[AGI_LC_DIGEST_SIZE];
	__u64 reserved[2];
};

struct agi_lc_experience_query {
	__u32 size;
	__u32 flags;
	__u64 experience_sequence;
	__u64 next_sequence;
	__u64 dropped;
	struct agi_lc_experience_record record;
	__u64 reserved[2];
};

struct agi_lc_learning_artifact {
	__u32 size;
	__u32 flags;
	__u32 kind;
	__s32 status;
	__u64 artifact_id;
	__u64 experience_sequence;
	__u64 source_lineage;
	__u64 source_agent;
	__u64 created_at_ns;
	__u64 capability;
	__u8 source_digest[AGI_LC_DIGEST_SIZE];
	__u8 artifact_digest[AGI_LC_DIGEST_SIZE];
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_message {
	__u32 size;
	__u32 flags;
	__u32 length;
	__u32 reserved;
	__u64 timeout_ns;
	__u64 correlation;
	__u64 sender_lineage;
	__u64 sender_agent;
	__u64 target_agent;
	__s32 sender_pid;
	__s32 sender_tgid;
	__u8 payload[AGI_LC_MESSAGE_MAX];
};

struct agi_lc_agent {
	__u32 size;
	__u32 flags;
	__u64 agent_id;
	__u64 parent_agent;
	__u64 correlation;
	__u64 reserved[2];
};
struct agi_lc_agent_query {
	__u32 size;
	__u32 flags;
	__u64 agent_id;
	__u64 parent_agent;
	__u64 owner_tgid;
	__u32 active;
	__u32 reserved;
	__u64 correlation;
	__u64 reserved2[2];
};

struct agi_lc_sched_hint {
	__u32 size;
	__u32 flags;
	__u64 agent_id;
	__u32 priority;
	__u32 state;
	__u32 dependency_count;
	__u32 unblock_credit;
	__u64 deadline_ns;
	__u32 latency_sensitive;
	__u32 util_min;
	__u32 util_max;
	__u32 reserved;
	__u64 correlation;
	__u64 reserved2[2];
};

struct agi_lc_accel_device {
	__u32 size;
	__u32 flags;
	__u64 device_id;
	__u32 type;
	__u32 capabilities;
	__u32 accounting_flags;
	__u32 isolation_flags;
	__u32 coordination_flags;
	__u32 online;
	__u64 total_memory_bytes;
	__u64 available_memory_bytes;
	__u64 compute_capacity;
	__u64 compute_ns;
	__u64 memory_bytes;
	__u64 submissions;
	__u64 next_device_id;
	char name[32];
	char driver[32];
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_accel_workload {
	__u32 size;
	__u32 flags;
	__u64 device_id;
	__u64 agent_id;
	__u32 workload;
	__u32 queue_class;
	__u32 priority;
	__u32 latency_sensitive;
	__u64 deadline_ns;
	__u32 isolation_flags;
	__u32 coordination_flags;
	__u32 state;
	__u32 reserved32;
	__u64 compute_ns;
	__u64 memory_bytes;
	__u64 submissions;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_accel_device_account {
	__u32 size;
	__u32 flags;
	__u64 device_id;
	__u64 compute_ns;
	__u64 memory_bytes;
	__u64 submissions;
	__u64 agent_id;
	__u32 status;
	__u32 reserved32;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_resource_demand {
	__u32 size;
	__u32 flags;
	__u64 agent_id;
	__u32 workload;
	__u32 resource_mask;
	__u32 priority;
	__u32 latency_sensitive;
	__u64 deadline_ns;
	__u32 cpu_util_min;
	__u32 cpu_util_max;
	__u64 memory_min_bytes;
	__u64 memory_max_bytes;
	__u64 accel_min_bytes;
	__u64 accel_max_bytes;
	__u64 storage_bytes_sec;
	__u64 network_bytes_sec;
	__u64 io_bytes_sec;
	__u32 status;
	__u32 enforced_mask;
	__u32 unsupported_mask;
	__u32 reserved32;
	__u64 observed_cpu_time_ns;
	__u64 observed_memory_bytes;
	__u64 observed_accel_compute_ns;
	__u64 observed_accel_memory_bytes;
	__u64 observed_accel_submissions;
	__u64 generation;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_resource_snapshot {
	__u32 size;
	__u32 flags;
	__u64 session_id;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 task_id;
	__u64 tgid;
	__u64 sampled_at_ns;
	__u64 generation;
	__u32 measured_mask;
	__u32 unavailable_mask;
	__u32 unsupported_mask;
	__u32 accelerator_type;
	__u32 energy_flags;
	__u32 reserved32;
	__u64 cpu_time_ns;
	__u64 cpu_budget_ns;
	__u64 cpu_elapsed_ns;
	__u64 memory_rss_bytes;
	__u64 memory_limit_bytes;
	__u64 memory_current_bytes;
	__u64 network_tx_bytes;
	__u64 network_rx_bytes;
	__u64 network_socket_creates;
	__u64 network_denied;
	__u64 storage_read_bytes;
	__u64 storage_write_bytes;
	__u64 storage_cancelled_write_bytes;
	__u64 io_read_chars;
	__u64 io_write_chars;
	__u64 io_read_syscalls;
	__u64 io_write_syscalls;
	__u64 accel_compute_ns;
	__u64 accel_memory_bytes;
	__u64 accel_submissions;
	__u64 energy_uj;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_light_agent {
	__u32 size;
	__u32 flags;
	__u64 agent_id;
	__u64 parent_agent;
	__u64 parent_capability;
	__u64 capability;
	__u32 role;
	__u32 state;
	__u32 workload;
	__u32 priority;
	__u32 resource_mask;
	__u32 reserved32;
	__u64 event_mask;
	__u64 generation;
	__u64 messages_sent;
	__u64 messages_received;
	__u64 dropped_messages;
	__u64 events_delivered;
	__u64 last_event_sequence;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_light_message {
	__u32 size;
	__u32 flags;
	__u32 length;
	__u32 reserved32;
	__u64 sender_agent;
	__u64 sender_capability;
	__u64 target_agent;
	__u64 target_capability;
	__u64 timeout_ns;
	__u64 sequence;
	__u64 correlation;
	__u8 payload[AGI_LC_LIGHT_AGENT_MESSAGE_MAX];
	__u64 reserved[2];
};

struct agi_lc_light_wait {
	__u32 size;
	__u32 flags;
	__u64 agent_id;
	__u64 capability;
	__u64 expected_generation;
	__u64 timeout_ns;
	__u64 generation;
	__u32 state;
	__u32 status;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_light_list {
	__u32 size;
	__u32 flags;
	__u64 cursor;
	__u64 agent_id;
	__u64 next_agent_id;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_ipc_channel {
	__u32 size;
	__u32 flags;
	__u64 channel_id;
	__u64 channel_capability;
	__u64 source_agent;
	__u64 source_capability;
	__u64 target_agent;
	__u64 target_capability;
	__u32 max_queue;
	__u32 queue_depth;
	__u64 generation;
	__u64 messages_sent;
	__u64 messages_received;
	__u64 messages_cancelled;
	__u64 messages_dropped;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_ipc_message {
	__u32 size;
	__u32 flags;
	__u32 length;
	__u32 priority;
	__u32 type;
	__u32 schema;
	__s32 status;
	__u32 reserved32;
	__u64 channel_id;
	__u64 channel_capability;
	__u64 sender_agent;
	__u64 sender_capability;
	__u64 target_agent;
	__u64 target_capability;
	__u64 message_id;
	__u64 sequence;
	__u64 correlation;
	__u64 parent_message_id;
	__u64 stream_id;
	__u64 stream_sequence;
	__u64 memory_region_id;
	__u64 memory_capability;
	__u64 memory_offset;
	__u64 timeout_ns;
	__u8 payload[AGI_LC_IPC_INLINE_MAX];
	__u64 reserved[2];
};

struct agi_lc_ipc_cancel {
	__u32 size;
	__u32 flags;
	__u64 channel_id;
	__u64 channel_capability;
	__u64 sender_agent;
	__u64 sender_capability;
	__u64 message_id;
	__s32 status;
	__u32 reserved32;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_capability_grant {
	__u32 size;
	__u32 flags;
	__u64 grant_id;
	__u64 agent_id;
	__u64 agent_capability;
	__u64 capability;
	__u64 rights;
	__u32 sandbox_flags;
	__u32 enforced_sandbox_flags;
	__u32 status;
	__u32 reserved32;
	__u64 generation;
	__u64 created_at_ns;
	__u64 revoked_at_ns;
	__u64 last_check_sequence;
	__u32 scope_kind;
	__u32 scope_access;
	__u64 scope_id;
	__u64 scope_capability;
	__u64 scope_generation;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_capability_check {
	__u32 size;
	__u32 flags;
	__u64 grant_id;
	__u64 capability;
	__u64 agent_id;
	__u64 agent_capability;
	__u64 requested_rights;
	__u64 allowed_rights;
	__u32 sandbox_flags;
	__u32 status;
	__u32 scope_kind;
	__u32 scope_access;
	__u64 scope_id;
	__u64 scope_capability;
	__u64 scope_generation;
	__u64 audit_sequence;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_identity {
	__u32 size;
	__u32 flags;
	__u64 session_id;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 parent_agent;
	__u64 agent_capability;
	__u64 task_id;
	__u64 tgid;
	__u64 parent_task_id;
	__u64 parent_tgid;
	__u64 creator_pid;
	__u64 creator_tgid;
	__u32 creator_uid;
	__u32 creator_euid;
	__u64 capabilities_effective;
	__u64 capabilities_permitted;
	__u64 capabilities_inheritable;
	__u64 capabilities_bounding;
	__u64 authority_rights;
	__u64 authority_generation;
	__u64 active_grants;
	__u64 cpu_budget_ns;
	__u64 cpu_elapsed_ns;
	__u64 memory_limit_pages;
	__u64 memory_current_pages;
	__u64 security_context_id;
	__u32 sandbox_flags;
	__u32 phase;
	__u32 state;
	__u32 cancelled;
	__u32 budget_exhausted;
	__u32 memory_exceeded;
	__u32 reserved32;
	__u64 sampled_at_ns;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_attribution {
	__u32 size;
	__u32 flags;
	__u64 sequence;
	__u16 action_type;
	__u16 reserved16;
	__s32 status;
	__u32 phase;
	__u64 session_id;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 parent_agent;
	__u64 task_id;
	__u64 tgid;
	__u64 parent_task_id;
	__u64 parent_tgid;
	__u64 creator_pid;
	__u64 creator_tgid;
	__u32 creator_uid;
	__u32 creator_euid;
	__u64 capabilities_effective;
	__u64 capabilities_permitted;
	__u64 authority_rights;
	__u64 authority_generation;
	__u64 active_grants;
	__u64 cpu_budget_ns;
	__u64 cpu_elapsed_ns;
	__u64 memory_limit_pages;
	__u64 memory_current_pages;
	__u64 security_context_id;
	__u32 sandbox_flags;
	__u32 state;
	__u64 correlation;
	__u64 metadata;
	__u64 recorded_at_ns;
	__u64 reserved[2];
};

struct agi_lc_provenance {
	__u32 size;
	__u32 operation;
	__s32 status;
	__u32 flags;
	__u64 provenance_id;
	__u64 action_sequence;
	__u64 result_sequence;
	__u64 parent_sequence;
	__u64 session_id;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 parent_agent;
	__u64 task_id;
	__u64 tgid;
	__u64 parent_task_id;
	__u64 parent_tgid;
	__u64 creator_pid;
	__u64 creator_tgid;
	__u32 creator_uid;
	__u32 creator_euid;
	__u64 authority_rights;
	__u64 authority_generation;
	__u64 active_grants;
	__u64 action_cpu_budget_ns;
	__u64 action_cpu_elapsed_ns;
	__u64 action_memory_limit_pages;
	__u64 action_memory_current_pages;
	__u64 action_accel_compute_ns;
	__u64 action_accel_memory_bytes;
	__u64 action_accel_submissions;
	__u64 result_task_id;
	__u64 result_tgid;
	__u64 result_cpu_elapsed_ns;
	__u64 result_memory_current_pages;
	__u64 result_accel_compute_ns;
	__u64 result_accel_memory_bytes;
	__u64 result_accel_submissions;
	__u64 capabilities_effective;
	__u64 capabilities_permitted;
	__u64 sandbox_flags;
	__u32 phase;
	__u32 state;
	__s32 result_status;
	__u32 result_kind;
	__u8 action_digest[AGI_LC_DIGEST_SIZE];
	__u8 result_digest[AGI_LC_DIGEST_SIZE];
	__u64 action_recorded_at_ns;
	__u64 result_recorded_at_ns;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_verified_knowledge {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__s32 status;
	__u64 record_id;
	__u64 related_record_id;
	__u64 source_id;
	__u64 source_uri_hash;
	__u32 source_rank;
	__u32 source_kind;
	__u32 verification_state;
	__u32 conflict_state;
	__u32 freshness_state;
	__u32 confidence_ppm;
	__u64 retrieval_realtime_ns;
	__u64 retrieval_boottime_ns;
	__u64 publication_realtime_ns;
	__u64 freshness_ttl_ns;
	__u64 expires_realtime_ns;
	__u64 checked_realtime_ns;
	__u64 crosscheck_count;
	__u64 conflict_count;
	__u64 provenance_sequence;
	__u64 evidence_sequence;
	__u64 parent_record_id;
	__u64 generation;
	__u64 session_id;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 task_id;
	__u64 tgid;
	__u64 creator_pid;
	__u64 creator_tgid;
	__u32 creator_uid;
	__u32 creator_euid;
	__u8 source_digest[AGI_LC_DIGEST_SIZE];
	__u8 content_digest[AGI_LC_DIGEST_SIZE];
	__u8 evidence_digest[AGI_LC_DIGEST_SIZE];
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_browser_session {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__s32 status;
	__u64 session_id;
	__u64 action_id;
	__u64 authority_grant_id;
	__u64 authority_capability;
	__u64 authority_agent_capability;
	__u32 interaction_kind;
	__u32 interaction_flags;
	__u32 state;
	__u32 reserved32;
	__u64 action_count;
	__u64 semantic_count;
	__u64 coordinate_fallback_count;
	__u64 download_count;
	__u64 upload_count;
	__u64 navigation_count;
	__u64 dom_count;
	__u64 screenshot_count;
	__u64 page_state_count;
	__u64 started_realtime_ns;
	__u64 started_boottime_ns;
	__u64 finished_realtime_ns;
	__u64 finished_boottime_ns;
	__u64 deadline_ns;
	__u64 generation;
	__u64 last_event_sequence;
	__u64 page_id;
	__u64 locator_hash;
	__u64 input_hash;
	__u64 observation_hash;
	__u64 result_hash;
	__u64 artifact_id;
	__s32 target_pid;
	__s32 target_tgid;
	__u64 agent_id;
	__u64 lineage_id;
	__u64 creator_pid;
	__u64 creator_tgid;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_lease {
	__u32 size;
	__u32 flags;
	__u32 resource;
	__u32 active;
	__u64 lease_id;
	__u64 owner_agent;
	__u64 expires_ns;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_persistent_memory {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 tier;
	__u32 state;
	__u32 conflict_state;
	__u64 record_id;
	__u64 related_record_id;
	__u64 memory_region_id;
	__u64 authority_capability;
	__u64 scope_id;
	__u64 parent_record_id;
	__u64 provenance_sequence;
	__u64 artifact_id;
	__u32 confidence_ppm;
	__u32 importance_ppm;
	__u32 freshness_state;
	__u32 reserved32;
	__u64 created_realtime_ns;
	__u64 retrieved_realtime_ns;
	__u64 published_realtime_ns;
	__u64 expires_realtime_ns;
	__u64 checked_realtime_ns;
	__u64 updated_realtime_ns;
	__u64 deleted_realtime_ns;
	__u64 generation;
	__u64 correction_count;
	__u64 deletion_count;
	__u64 expiration_count;
	__u64 conflict_count;
	__u64 dedup_count;
	__u64 revalidation_count;
	__u64 owner_lineage;
	__u64 owner_agent;
	__u64 owner_tgid;
	__u64 creator_pid;
	__u64 creator_tgid;
	__u32 creator_uid;
	__u32 creator_euid;
	__u8 content_digest[AGI_LC_DIGEST_SIZE];
	__u8 source_digest[AGI_LC_DIGEST_SIZE];
	__u8 relationship_digest[AGI_LC_DIGEST_SIZE];
	__u64 correlation;
	__u64 reserved[2];
};
struct agi_lc_memory_region {
	__u32 size;
	__u32 flags;
	__s32 backing_fd;
	__u32 access;
	__u64 region_id;
	__u64 size_bytes;
	__u64 generation;
	__u64 snapshot_sequence;
	__u64 owner_agent;
	__u64 capability;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_graph_node {
 __u32 size; __u32 operation; __u32 flags; __u32 state;
 __u64 graph_id; __u64 node_id; __u64 agent_id; __u64 authority_capability;
 __u32 workload; __u32 device_mask; __u32 queue_class; __u32 dependency_count;
 __u64 dependencies[AGI_LC_GRAPH_MAX_DEPS];
 __u32 priority; __u32 latency_sensitive; __u64 deadline_ns; __u64 expected_runtime_ns;
 __u64 criticality; __u64 observed_runtime_ns; __u32 ready; __u32 completed_dependencies;
 __u32 generation; __u32 reserved32; __u64 correlation; __u64 reserved[2];
};
struct agi_lc_compute_context {
__u32 size;
__u32 operation;
__u32 flags;
__u32 state;
__u64 context_id;
__u64 context_capability;
__u64 graph_id;
__u64 agent_id;
__u32 device_mask;
__u32 attached_tasks;
__u32 bound_regions;
__u32 active_device_mask;
__u32 unsupported_device_mask;
__u32 generation;
__u64 task_id;
__u64 region_id;
__u64 region_capability;
__u32 region_access;
__s32 status;
__u64 bytes_referenced;
__u64 provenance_binding_id;
__u64 provenance_id;
__u64 provenance_sequence;
__u64 provenance_generation;
__u64 requested_fabric;
__u64 active_fabric;
__u64 unsupported_fabric;
__u32 address_space_mode;
__u32 provider_kind;
__u64 bytes_accounted;
__u64 transfer_bytes;
__u64 compute_ns;
__u64 state_sequence;
__u64 correlation;
__u64 reserved[2];
};
struct agi_lc_tensor_policy {
__u32 size;
__u32 operation;
__u32 flags;
__u32 rank;
__u32 element_size;
__s32 preferred_numa_node;
__u32 tier_mask;
__u32 reserved0;
__u64 region_id;
__u64 capability;
__u64 total_bytes;
__u64 alignment;
__u64 generation;
__u64 dimensions[AGI_LC_TENSOR_MAX_RANK];
__u64 strides[AGI_LC_TENSOR_MAX_RANK];
__u64 provenance_binding_id;
__u64 provenance_id;
__u64 provenance_sequence;
__u64 provenance_generation;
__u64 correlation;
__u64 reserved[2];
};
struct agi_lc_provenance_binding {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 scope_kind;
	__s32 status;
	__u32 reserved32;
	__u64 binding_id;
	__u64 resource_id;
	__u64 resource_capability;
	__u64 resource_generation;
	__u64 provenance_id;
	__u64 provenance_sequence;
	__u64 binding_generation;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_execution_domain {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 state;
	__s32 status;
	__u32 reserved32;
	__u64 domain_id;
	__u64 capability;
	__u64 generation;
	__u64 owner_agent;
	__u64 owner_tgid;
	__u64 requested_features;
	__u64 available_features;
	__u64 unsupported_features;
	__u64 requested_cpus[AGI_LC_EXEC_DOMAIN_CPU_WORDS];
	__u64 applied_cpus[AGI_LC_EXEC_DOMAIN_CPU_WORDS];
	__u64 housekeeping_cpus[AGI_LC_EXEC_DOMAIN_CPU_WORDS];
	__u64 jitter_sequence;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_tensor_transport {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 transport_kind;
	__u32 collective_kind;
	__u32 direction;
	__u32 state;
	__s32 status;
	__u32 participants;
	__u32 participant_index;
	__u64 transport_id;
	__u64 capability;
	__u64 region_id;
	__u64 region_capability;
	__u64 region_generation;
	__u64 source_device_id;
	__u64 target_device_id;
	__u64 bytes;
	__u64 chunk_bytes;
	__u64 generation;
	__u64 completion_sequence;
	__u64 provenance_id;
	__u64 provenance_sequence;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_memory_share {
	__u32 size;
	__u32 flags;
	__u64 region_id;
	__u64 owner_capability;
	__u64 target_agent;
	__u32 access;
	__u32 reserved;
	__u64 share_capability;
	__u64 correlation;
	__u64 reserved2[2];
};

struct agi_lc_memory_attach {
	__u32 size;
	__u32 flags;
	__s32 backing_fd;
	__u32 access;
	__u64 region_id;
	__u64 capability;
	__u64 agent_id;
	__u64 size_bytes;
	__u64 generation;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_memory_snapshot {
	__u32 size;
	__u32 flags;
	__s32 status;
	__u32 reserved;
	__u64 region_id;
	__u64 owner_capability;
	__u64 parent_generation;
	__u64 generation;
	__u64 snapshot_sequence;
	__u8 digest[AGI_LC_DIGEST_SIZE];
	__u64 correlation;
	__u64 reserved2[2];
};

struct agi_lc_memory_revoke {
	__u32 size;
	__u32 flags;
	__u64 region_id;
	__u64 owner_capability;
	__u64 target_agent;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_gate {
	__u32 size;
	__u32 open;
	__u64 timeout_ns;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_memory_hint {
	__u32 size;
	__u32 behavior;
	__u64 start;
	__u64 length;
	__u32 flags;
	__u32 reserved;
	__u64 correlation;
	__u64 reserved2[2];
};

struct agi_lc_perf {
	__u32 size;
	__u32 flags;
	__u32 util_min;
	__u32 util_max;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_phase {
	__u32 size;
	__u32 phase;
	__u32 flags;
	__u32 reserved;
	__u64 correlation;
	__u64 reserved2[2];
};

struct agi_lc_cancel {
	__u32 size;
	__s32 pid;
	__s32 signal;
	__u32 flags;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_network_policy {
	__u32 size;
	__u32 flags;
	__u64 policy_id;
	__s32 target_pid;
	__s32 target_tgid;
	__u64 target_agent;
	__u64 authority_grant_id;
	__u64 authority_capability;
	__u64 authority_agent_capability;
	__u64 family_mask;
	__u64 type_mask;
	__u64 operation_mask;
	__u32 policy_flags;
	__u32 max_sockets;
	__u64 max_tx_bytes;
	__u64 max_rx_bytes;
	__u64 socket_count;
	__u32 state;
	__s32 status;
	__u64 generation;
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 socket_creates;
	__u64 denied;
	__u64 audit_sequence;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_cancel_control {
	__u32 size;
	__u32 flags;
	__u64 request_id;
	__u64 parent_request_id;
	__s32 target_pid;
	__s32 target_tgid;
	__u64 target_agent;
	__u64 authority_grant_id;
	__u64 authority_capability;
	__u64 authority_agent_capability;
	__u32 mode;
	__u32 scope;
	__u32 dependency_policy;
	__u32 cancel_flags;
	__u32 priority;
	__u32 state;
	__u64 deadline_ns;
	__u64 escalation_deadline_ns;
	__u32 propagated;
	__u32 resources_revoked;
	__u32 checkpoint_requested;
	__u32 reserved32;
	__u64 checkpoint_sequence;
	__u64 generation;
	__s32 creator_pid;
	__s32 creator_tgid;
	__u32 creator_uid;
	__u32 creator_euid;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_revoke {
	__u32 size;
	__u32 reason;
	__u64 reserved[2];
};

struct agi_lc_stats {
	__u32 size;
	__u32 abi_version;
	__u64 session_id;
	__u64 process_count;
	__u64 thread_count;
	__u64 cpu_time_ns;
	__u64 voluntary_context_switches;
	__u64 involuntary_context_switches;
	__u64 minor_faults;
	__u64 major_faults;
	__u64 sampled_at_ns;
	__u64 reserved[2];
};

struct agi_lc_self_state {
	__u32 size;
	__u32 flags;
	__u64 session_id;
	__u64 sampled_at_ns;
	__u64 change_generation;
	__u64 last_event_sequence;
	__u64 last_failure_sequence;
	__u64 process_count;
	__u64 thread_count;
	__u64 runnable_count;
	__u64 blocked_count;
	__u64 failed_count;
	__u64 cancelled_count;
	__u64 cpu_time_ns;
	__u64 memory_bytes;
	__u64 memory_limit_pages;
	__u64 memory_current_pages;
	__u64 cpu_budget_ns;
	__u64 cpu_elapsed_ns;
	__u64 accel_compute_ns;
	__u64 accel_memory_bytes;
	__u64 accel_submissions;
	__u64 voluntary_context_switches;
	__u64 involuntary_context_switches;
	__u64 minor_faults;
	__u64 major_faults;
	__u64 agent_count;
	__u64 active_agent_count;
	__u64 lease_count;
	__u64 active_lease_count;
	__u64 lease_resource_mask;
	__u64 dropped_records;
	__u64 world_delivered;
	__u64 world_filtered;
	__u64 world_dropped;
	__u64 capabilities_effective;
	__u64 capabilities_permitted;
	__u64 capabilities_inheritable;
	__u64 capabilities_bounding;
	__u64 top_cpu_pid;
	__u64 top_cpu_time_ns;
	__u64 top_memory_tgid;
	__u64 top_memory_bytes;
	__u64 current_pid;
	__u64 current_tgid;
	__u64 current_lineage;
	__u64 current_agent;
	__u32 current_phase;
	__u32 current_state;
	__u32 current_cancelled;
	__u32 current_budget_exhausted;
	__u32 current_memory_exceeded;
	__u32 online_cpus;
	__u32 possible_cpus;
	__u32 resource_flags;
	__u32 reserved32;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_info {
	__u32 size;
	__u32 abi_version;
	__u64 session_id;
	__u64 owner_pid;
	__u64 owner_tgid;
	__u64 dropped_records;
	__u64 reserved[2];
};
struct agi_lc_domain {
	__u32 size;
	__u32 flags;
	__u64 cgroup_id;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_world_subscription {
	__u32 size;
	__u32 flags;
	__u64 class_mask;
	__u64 lineage_id;
	__u64 agent_id;
	__u32 min_priority;
	__u32 queue_policy;
	__u64 delivered;
	__u64 filtered;
	__u64 dropped;
	__u64 last_loss_sequence;
	__u64 correlation;
	__u64 reserved[2];
};

struct agi_lc_world_sync {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 resync_required;
	__u64 consumer_id;
	__u64 ack_sequence;
	__u64 resync_sequence;
	__u64 next_sequence;
	__u64 oldest_sequence;
	__u64 newest_sequence;
	__u64 queued;
	__u64 generation;
	__u64 delivered;
	__u64 filtered;
	__u64 dropped;
	__u64 last_loss_sequence;
	__u64 correlation;
	__u64 reserved[2];
};
struct agi_lc_temporal {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 state;
	__u32 constraint_result;
	__u32 status;
	__u64 record_id;
	__u64 authority_capability;
	__u64 event_sequence;
	__u64 parent_sequence;
	__u64 reference_sequence;
	__u64 min_sequence;
	__u64 max_sequence;
	__u64 event_realtime_ns;
	__u64 event_boottime_ns;
	__u64 observation_realtime_ns;
	__u64 observation_boottime_ns;
	__u64 deadline_boottime_ns;
	__u64 checkpoint_id;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 task_id;
	__u64 generation;
	__u64 correlation;
	__u64 reserved[2];
};
struct agi_lc_reflection {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 state;
	__s32 status;
	__u32 dependency_reason;
	__u64 action_id;
	__u64 authority_capability;
	__u64 parent_action_id;
	__u64 dependency_id;
	__u64 event_sequence;
	__u64 parent_sequence;
	__u64 start_realtime_ns;
	__u64 start_boottime_ns;
	__u64 end_realtime_ns;
	__u64 end_boottime_ns;
	__u64 cpu_start_ns;
	__u64 cpu_end_ns;
	__u64 cpu_delta_ns;
	__u64 memory_start_pages;
	__u64 memory_end_pages;
	__s64 memory_delta_pages;
	__u64 cpu_budget_ns;
	__u64 memory_limit_pages;
	__u64 accel_compute_ns;
	__u64 accel_memory_bytes;
	__u64 accel_submissions;
	__u64 sampled_realtime_ns;
	__u64 sampled_boottime_ns;
	__u64 last_failure_sequence;
	__u64 failure_count;
	__u64 blocked_count;
	__u64 change_generation;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 task_id;
	__u64 tgid;
	__u64 checkpoint_id;
	__u64 result_code;
	__u64 generation;
	__u64 correlation;
	__u64 reserved[2];
};
struct agi_lc_observability {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 enabled;
	__u64 event_mask;
	__u32 sample_period;
	__u32 reserved32;
	__u64 emitted;
	__u64 filtered;
	__u64 sampled;
	__u64 dropped;
	__u64 last_sequence;
	__u64 generation;
	__u64 lineage_id;
	__u64 agent_id;
	__u64 task_id;
	__u64 correlation;
	__u64 reserved[2];
};
struct agi_lc_power_policy {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 profile;
	__u32 state;
	__s32 status;
	__u64 policy_id;
	__u64 capability;
	__u64 agent_id;
	__u64 task_id;
	__u64 requested_features;
	__u64 available_features;
	__u64 unsupported_features;
	__u64 applied_features;
	__u64 requested_cpus[AGI_LC_EXEC_DOMAIN_CPU_WORDS];
	__u32 min_cpu_util;
	__u32 max_cpu_util;
	__u32 cpu_latency_us;
	__u32 reserved32;
	__u64 device_id;
	__u64 power_budget_uw;
	__u64 power_window_us;
	__u64 sampled_power_uw;
	__u64 sampled_energy_uj;
	__u64 generation;
	__u64 correlation;
	__u64 reserved[2];
};
struct agi_lc_graph_telemetry {
	__u32 size;
	__u32 operation;
	__u32 flags;
	__u32 state;
	__s32 status;
	__u32 device_mask;
	__u64 telemetry_id;
	__u64 telemetry_capability;
	__u64 graph_id;
	__u64 node_id;
	__u64 agent_id;
	__u64 task_id;
	__u64 context_id;
	__u64 context_capability;
	__u64 tensor_region_id;
	__u64 tensor_capability;
	__u64 transport_id;
	__u64 transport_capability;
	__u64 provenance_id;
	__u64 provenance_sequence;
	__u32 operator_kind;
	__u32 dependency_count;
	__u64 start_ns;
	__u64 end_ns;
	__u64 duration_ns;
	__u64 queue_delay_ns;
	__u64 observed_runtime_ns;
	__u64 bytes_in;
	__u64 bytes_out;
	__u64 provider_sequence;
	__u32 anomaly_score;
	__u32 anomaly_flags;
	__u64 generation;
	__u64 correlation;
	__u64 reserved[2];
};
struct agi_lc_record {
	__u64 sequence;
	__u64 timestamp_ns;
	__u64 session_id;
	__u64 pid;
	__u64 tgid;
	__u16 type;
	__u16 flags;
	__s32 status;
	__u32 reserved;
	__u64 correlation;
	__u64 metadata;
	__u64 lineage_id;
};

#define AGI_LC_IOC_MAGIC 'A'
#define AGI_LC_CREATE _IOWR(AGI_LC_IOC_MAGIC, 0x01, struct agi_lc_create)
#define AGI_LC_BEGIN _IOW(AGI_LC_IOC_MAGIC, 0x02, struct agi_lc_event)
#define AGI_LC_END _IOW(AGI_LC_IOC_MAGIC, 0x03, struct agi_lc_event)
#define AGI_LC_REVOKE _IOW(AGI_LC_IOC_MAGIC, 0x04, struct agi_lc_revoke)
#define AGI_LC_GET_INFO _IOR(AGI_LC_IOC_MAGIC, 0x05, struct agi_lc_info)
#define AGI_LC_GET_DOMAIN _IOWR(AGI_LC_IOC_MAGIC, 0x20, struct agi_lc_domain)
#define AGI_LC_VERIFY_CHECKPOINT _IOWR(AGI_LC_IOC_MAGIC, 0x21, struct agi_lc_verify)
#define AGI_LC_GET_AGENT _IOWR(AGI_LC_IOC_MAGIC, 0x22, struct agi_lc_agent_query)
#define AGI_LC_SET_SCHED_HINT _IOWR(AGI_LC_IOC_MAGIC, 0x23, struct agi_lc_sched_hint)
#define AGI_LC_GET_SCHED_HINT _IOWR(AGI_LC_IOC_MAGIC, 0x24, struct agi_lc_sched_hint)
#define AGI_LC_MEMORY_REGION_CREATE _IOWR(AGI_LC_IOC_MAGIC, 0x25, struct agi_lc_memory_region)
#define AGI_LC_MEMORY_REGION_SHARE _IOWR(AGI_LC_IOC_MAGIC, 0x26, struct agi_lc_memory_share)
#define AGI_LC_MEMORY_REGION_ATTACH _IOWR(AGI_LC_IOC_MAGIC, 0x27, struct agi_lc_memory_attach)
#define AGI_LC_MEMORY_REGION_GET _IOWR(AGI_LC_IOC_MAGIC, 0x28, struct agi_lc_memory_region)
#define AGI_LC_MEMORY_REGION_SNAPSHOT _IOWR(AGI_LC_IOC_MAGIC, 0x29, struct agi_lc_memory_snapshot)
#define AGI_LC_MEMORY_REGION_REVOKE _IOW(AGI_LC_IOC_MAGIC, 0x2a, struct agi_lc_memory_revoke)
#define AGI_LC_TENSOR_POLICY _IOWR(AGI_LC_IOC_MAGIC, 0x5b, struct agi_lc_tensor_policy)
#define AGI_LC_GRAPH_NODE _IOWR(AGI_LC_IOC_MAGIC, 0x5c, struct agi_lc_graph_node)
#define AGI_LC_COMPUTE_CONTEXT _IOWR(AGI_LC_IOC_MAGIC, 0x5d, struct agi_lc_compute_context)
#define AGI_LC_PROVENANCE_BINDING _IOWR(AGI_LC_IOC_MAGIC, 0x5e, struct agi_lc_provenance_binding)
#define AGI_LC_TENSOR_TRANSPORT _IOWR(AGI_LC_IOC_MAGIC, 0x5f, struct agi_lc_tensor_transport)
#define AGI_LC_EXECUTION_DOMAIN _IOWR(AGI_LC_IOC_MAGIC, 0x60, struct agi_lc_execution_domain)
#define AGI_LC_GRAPH_TELEMETRY _IOWR(AGI_LC_IOC_MAGIC, 0x61, struct agi_lc_graph_telemetry)
#define AGI_LC_POWER_POLICY _IOWR(AGI_LC_IOC_MAGIC, 0x62, struct agi_lc_power_policy)
#define AGI_LC_RECORD_EXPERIENCE _IOWR(AGI_LC_IOC_MAGIC, 0x2b, struct agi_lc_experience_record)
#define AGI_LC_GET_EXPERIENCE _IOWR(AGI_LC_IOC_MAGIC, 0x2c, struct agi_lc_experience_query)
#define AGI_LC_PUBLISH_ARTIFACT _IOWR(AGI_LC_IOC_MAGIC, 0x2d, struct agi_lc_learning_artifact)
#define AGI_LC_GET_ARTIFACT _IOWR(AGI_LC_IOC_MAGIC, 0x2e, struct agi_lc_learning_artifact)
#define AGI_LC_GET_SELF_STATE _IOWR(AGI_LC_IOC_MAGIC, 0x31, struct agi_lc_self_state)
#define AGI_LC_SET_RESOURCE_DEMAND _IOWR(AGI_LC_IOC_MAGIC, 0x32, struct agi_lc_resource_demand)
#define AGI_LC_GET_RESOURCE_DEMAND _IOWR(AGI_LC_IOC_MAGIC, 0x33, struct agi_lc_resource_demand)
#define AGI_LC_ACCEL_REGISTER _IOWR(AGI_LC_IOC_MAGIC, 0x34, struct agi_lc_accel_device)
#define AGI_LC_ACCEL_UNREGISTER _IOW(AGI_LC_IOC_MAGIC, 0x35, struct agi_lc_accel_device)
#define AGI_LC_ACCEL_GET_DEVICE _IOWR(AGI_LC_IOC_MAGIC, 0x36, struct agi_lc_accel_device)
#define AGI_LC_ACCEL_SET_WORKLOAD _IOWR(AGI_LC_IOC_MAGIC, 0x37, struct agi_lc_accel_workload)
#define AGI_LC_ACCEL_GET_WORKLOAD _IOWR(AGI_LC_IOC_MAGIC, 0x38, struct agi_lc_accel_workload)
#define AGI_LC_ACCEL_DEVICE_ACCOUNT _IOWR(AGI_LC_IOC_MAGIC, 0x39, struct agi_lc_accel_device_account)
#define AGI_LC_CHECKPOINT_MANIFEST _IOWR(AGI_LC_IOC_MAGIC, 0x3a, struct agi_lc_checkpoint_manifest)
#define AGI_LC_RECOVERY _IOWR(AGI_LC_IOC_MAGIC, 0x3b, struct agi_lc_recovery)
#define AGI_LC_LIGHT_AGENT_REGISTER _IOWR(AGI_LC_IOC_MAGIC, 0x3c, struct agi_lc_light_agent)
#define AGI_LC_LIGHT_AGENT_UNREGISTER _IOW(AGI_LC_IOC_MAGIC, 0x3d, struct agi_lc_light_agent)
#define AGI_LC_LIGHT_AGENT_GET _IOWR(AGI_LC_IOC_MAGIC, 0x3e, struct agi_lc_light_agent)
#define AGI_LC_LIGHT_AGENT_UPDATE _IOWR(AGI_LC_IOC_MAGIC, 0x3f, struct agi_lc_light_agent)
#define AGI_LC_LIGHT_AGENT_SEND _IOWR(AGI_LC_IOC_MAGIC, 0x40, struct agi_lc_light_message)
#define AGI_LC_LIGHT_AGENT_RECV _IOWR(AGI_LC_IOC_MAGIC, 0x41, struct agi_lc_light_message)
#define AGI_LC_LIGHT_AGENT_WAIT _IOWR(AGI_LC_IOC_MAGIC, 0x42, struct agi_lc_light_wait)
#define AGI_LC_LIGHT_AGENT_LIST _IOWR(AGI_LC_IOC_MAGIC, 0x43, struct agi_lc_light_list)
#define AGI_LC_CAPABILITY_GRANT _IOWR(AGI_LC_IOC_MAGIC, 0x44, struct agi_lc_capability_grant)
#define AGI_LC_CAPABILITY_REVOKE _IOW(AGI_LC_IOC_MAGIC, 0x45, struct agi_lc_capability_grant)
#define AGI_LC_CAPABILITY_GET _IOWR(AGI_LC_IOC_MAGIC, 0x46, struct agi_lc_capability_grant)
#define AGI_LC_CAPABILITY_CHECK _IOWR(AGI_LC_IOC_MAGIC, 0x47, struct agi_lc_capability_check)
#define AGI_LC_GET_IDENTITY _IOWR(AGI_LC_IOC_MAGIC, 0x48, struct agi_lc_identity)
#define AGI_LC_GET_ATTRIBUTION _IOWR(AGI_LC_IOC_MAGIC, 0x49, struct agi_lc_attribution)
#define AGI_LC_PROVENANCE_PUBLISH _IOWR(AGI_LC_IOC_MAGIC, 0x4a, struct agi_lc_provenance)
#define AGI_LC_PROVENANCE_QUERY _IOWR(AGI_LC_IOC_MAGIC, 0x4b, struct agi_lc_provenance)
#define AGI_LC_IPC_CHANNEL_CREATE _IOWR(AGI_LC_IOC_MAGIC, 0x4c, struct agi_lc_ipc_channel)
#define AGI_LC_IPC_CHANNEL_CLOSE _IOW(AGI_LC_IOC_MAGIC, 0x4d, struct agi_lc_ipc_channel)
#define AGI_LC_IPC_SEND _IOWR(AGI_LC_IOC_MAGIC, 0x4e, struct agi_lc_ipc_message)
#define AGI_LC_IPC_RECV _IOWR(AGI_LC_IOC_MAGIC, 0x4f, struct agi_lc_ipc_message)
#define AGI_LC_IPC_CANCEL _IOWR(AGI_LC_IOC_MAGIC, 0x50, struct agi_lc_ipc_cancel)
#define AGI_LC_CANCEL_CONTROL _IOWR(AGI_LC_IOC_MAGIC, 0x51, struct agi_lc_cancel_control)
#define AGI_LC_NETWORK_POLICY _IOWR(AGI_LC_IOC_MAGIC, 0x52, struct agi_lc_network_policy)
#define AGI_LC_KNOWLEDGE _IOWR(AGI_LC_IOC_MAGIC, 0x53, struct agi_lc_verified_knowledge)
#define AGI_LC_BROWSER _IOWR(AGI_LC_IOC_MAGIC, 0x54, struct agi_lc_browser_session)
#define AGI_LC_MEMORY_RECORD _IOWR(AGI_LC_IOC_MAGIC, 0x55, struct agi_lc_persistent_memory)
#define AGI_LC_WORLD_SYNC _IOWR(AGI_LC_IOC_MAGIC, 0x56, struct agi_lc_world_sync)
#define AGI_LC_TEMPORAL _IOWR(AGI_LC_IOC_MAGIC, 0x57, struct agi_lc_temporal)
#define AGI_LC_REFLECTION _IOWR(AGI_LC_IOC_MAGIC, 0x58, struct agi_lc_reflection)
#define AGI_LC_OBSERVABILITY _IOWR(AGI_LC_IOC_MAGIC, 0x59, struct agi_lc_observability)
#define AGI_LC_GET_RESOURCE_SNAPSHOT _IOWR(AGI_LC_IOC_MAGIC, 0x5a, struct agi_lc_resource_snapshot)
#define AGI_LC_SET_WORLD_SUBSCRIPTION _IOWR(AGI_LC_IOC_MAGIC, 0x2f, struct agi_lc_world_subscription)
#define AGI_LC_GET_WORLD_SUBSCRIPTION _IOWR(AGI_LC_IOC_MAGIC, 0x30, struct agi_lc_world_subscription)
#define AGI_LC_ATTACH_TASK _IO(AGI_LC_IOC_MAGIC, 0x06)
#define AGI_LC_DETACH_TASK _IO(AGI_LC_IOC_MAGIC, 0x07)
#define AGI_LC_CANCEL _IOW(AGI_LC_IOC_MAGIC, 0x08, struct agi_lc_cancel)
#define AGI_LC_GET_STATS _IOR(AGI_LC_IOC_MAGIC, 0x09, struct agi_lc_stats)
#define AGI_LC_SET_PHASE _IOW(AGI_LC_IOC_MAGIC, 0x0a, struct agi_lc_phase)
#define AGI_LC_MEMORY_HINT _IOW(AGI_LC_IOC_MAGIC, 0x0b, struct agi_lc_memory_hint)
#define AGI_LC_SET_PERF _IOW(AGI_LC_IOC_MAGIC, 0x0c, struct agi_lc_perf)
#define AGI_LC_SET_GATE _IOW(AGI_LC_IOC_MAGIC, 0x0d, struct agi_lc_gate)
#define AGI_LC_WAIT_GATE _IOWR(AGI_LC_IOC_MAGIC, 0x0e, struct agi_lc_gate)
#define AGI_LC_SEND _IOW(AGI_LC_IOC_MAGIC, 0x0f, struct agi_lc_message)
#define AGI_LC_RECV _IOWR(AGI_LC_IOC_MAGIC, 0x10, struct agi_lc_message)
#define AGI_LC_EXPERIENCE _IOWR(AGI_LC_IOC_MAGIC, 0x11, struct agi_lc_experience)
#define AGI_LC_ACCEL_ACCOUNT _IOW(AGI_LC_IOC_MAGIC, 0x12, struct agi_lc_accel)
#define AGI_LC_ACCEL_GET _IOR(AGI_LC_IOC_MAGIC, 0x13, struct agi_lc_accel)
#define AGI_LC_SUBSCRIBE _IOW(AGI_LC_IOC_MAGIC, 0x14, struct agi_lc_subscribe)
#define AGI_LC_CHECKPOINT _IOWR(AGI_LC_IOC_MAGIC, 0x15, struct agi_lc_checkpoint)
#define AGI_LC_SET_BUDGET _IOW(AGI_LC_IOC_MAGIC, 0x16, struct agi_lc_budget)
#define AGI_LC_GET_BUDGET _IOR(AGI_LC_IOC_MAGIC, 0x17, struct agi_lc_budget)
#define AGI_LC_SET_MEMORY_BUDGET _IOW(AGI_LC_IOC_MAGIC, 0x18, struct agi_lc_memory_budget)
#define AGI_LC_GET_MEMORY_BUDGET _IOR(AGI_LC_IOC_MAGIC, 0x19, struct agi_lc_memory_budget)
#define AGI_LC_EXPORT_CHECKPOINT _IOR(AGI_LC_IOC_MAGIC, 0x1a, struct agi_lc_handoff)
#define AGI_LC_IMPORT_CHECKPOINT _IOWR(AGI_LC_IOC_MAGIC, 0x1b, struct agi_lc_handoff)
#define AGI_LC_SET_AGENT _IOWR(AGI_LC_IOC_MAGIC, 0x1c, struct agi_lc_agent)
#define AGI_LC_LEASE_ACQUIRE _IOWR(AGI_LC_IOC_MAGIC, 0x1d, struct agi_lc_lease)
#define AGI_LC_LEASE_CHECK _IOWR(AGI_LC_IOC_MAGIC, 0x1e, struct agi_lc_lease)
#define AGI_LC_LEASE_REVOKE _IOW(AGI_LC_IOC_MAGIC, 0x1f, struct agi_lc_lease)

#endif /* _UAPI_LINUX_AGI_LIFECYCLE_H */
