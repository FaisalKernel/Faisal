import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "faisal-replication"))
import faisal_replication_pb2 as pb2
import faisal_replication_pb2_grpc as pb2_grpc


class ReplicationBindingTests(unittest.TestCase):
    def test_vote_and_append_round_trip(self):
        vote = pb2.VoteRequest(
            candidate=pb2.JournalIdentity(
                cluster_id=9,
                replica_id=2,
                term=4,
                last_sequence=72,
                chain_digest=b"a" * 32,
                key_id="kms/faisal",
                key_generation=8,
            ),
            election_deadline_ns=1234,
        )
        parsed_vote = pb2.VoteRequest.FromString(vote.SerializeToString())
        self.assertEqual(parsed_vote.candidate.replica_id, 2)
        certificate = pb2.QuorumCertificate(
            cluster_id=9,
            leader_replica_id=2,
            term=4,
            commit_sequence=72,
            commit_digest=b"a" * 32,
            votes=[pb2.QuorumVote(voter_replica_id=1, key_id="test", key_generation=1, signature=b"s")],
        )
        append = pb2.AppendRequest(
            leader=parsed_vote.candidate,
            records=[pb2.JournalRecord(sequence=73, previous_digest=b"a" * 32, payload=b"x")],
            leader_commit=72,
            quorum_certificate=certificate,
        )
        parsed_append = pb2.AppendRequest.FromString(append.SerializeToString())
        self.assertEqual(parsed_append.records[0].sequence, 73)
        self.assertEqual(parsed_append.quorum_certificate.commit_sequence, 72)
        self.assertEqual(parsed_append.quorum_certificate.votes[0].voter_replica_id, 1)
        self.assertTrue(hasattr(pb2_grpc, "JournalReplicationStub"))
        self.assertTrue(hasattr(pb2_grpc, "JournalReplicationServicer"))
        self.assertIn("AppendEntries", pb2_grpc.JournalReplicationStub.__init__.__code__.co_names)
        self.assertIn("AppendJournal", pb2_grpc.JournalReplicationStub.__init__.__code__.co_names)


if __name__ == "__main__":
    unittest.main()
