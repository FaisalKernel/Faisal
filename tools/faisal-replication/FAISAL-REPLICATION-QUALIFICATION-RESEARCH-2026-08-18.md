# FAISAL replication qualification research — 2026-08-18

## gRPC authentication

Source: https://grpc.io/docs/guides/auth/

The gRPC documentation identifies SSL/TLS as a built-in authentication mechanism and notes that clients can provide certificates for mutual authentication. The fixture must therefore validate both server authentication and client certificate identity, not only encrypted transport.

## Raft consensus

Source: https://raft.github.io/

The Raft project describes consensus as agreement among multiple servers with progress on a majority and no incorrect result when a minority fails. Replicated state-machine safety requires identical ordered commands at each position; a minority partition must stop progress rather than commit independently.

## FAISAL qualification implication

The existing loopback socket fault fixture is not a complete qualification of the gRPC replication service: it proves TLS stream interruption/reconnection only. A full fixture must start the actual gRPC daemon instances, use distinct mTLS certificates with replica identities, exercise RequestVote and AppendEntries, verify durable state and ReadCommit, reject invalid identities/signatures/chain data, and demonstrate that a minority partition cannot obtain a quorum commit. The current protobuf has no authenticated quorum certificate field; any commit authority conveyed only by `leader_commit` is unsafe for a production claim and must be guarded or explicitly treated as a fixture limitation.
