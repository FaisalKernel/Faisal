#!/usr/bin/env python3
from __future__ import annotations

import copy
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_route_budget import BudgetError, BudgetRequest, BudgetWindow, RouteBudgetLedger, Usage


ROUTE = "sha256:" + "1" * 64


class RouteBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.windows = (
            BudgetWindow("hour", max_cost_milli=100, max_input_tokens=1000, max_output_tokens=500, max_concurrency=2),
            BudgetWindow("day", max_cost_milli=500, max_input_tokens=5000, max_output_tokens=2500, max_concurrency=4),
        )
        self.ledger = RouteBudgetLedger(self.windows)
        self.request = BudgetRequest("r-1", "req-1", ROUTE, 7, 40, 300, 100, 100)

    def test_reserve_settle_and_authority_boundary(self) -> None:
        reservation = self.ledger.reserve(self.request, current_generation=7, nonce="reserve")
        settled = self.ledger.settle(reservation, Usage(35, 280, 90, 110), current_generation=7, nonce="settle")
        self.assertEqual(settled["status"], "settled")
        self.assertFalse(settled["authority"]["budget_is_execution"])
        self.assertFalse(settled["authority"]["model_output_is_authority"])

    def test_multi_window_capacity_is_fail_closed(self) -> None:
        self.ledger.reserve(self.request, current_generation=7, nonce="a")
        with self.assertRaises(BudgetError):
            self.ledger.reserve(BudgetRequest("r-2", "req-2", ROUTE, 7, 70, 300, 100, 100), current_generation=7, nonce="b")
        with self.assertRaises(BudgetError):
            self.ledger.reserve(BudgetRequest("r-3", "req-3", ROUTE, 7, 1, 800, 100, 100), current_generation=7, nonce="c")

    def test_release_returns_reserved_capacity(self) -> None:
        reservation = self.ledger.reserve(self.request, current_generation=7, nonce="reserve")
        released = self.ledger.release(reservation, now=101, current_generation=7, nonce="release")
        self.assertEqual(released["status"], "released")
        replacement = self.ledger.reserve(BudgetRequest("r-2", "req-2", ROUTE, 7, 100, 1000, 500, 101), current_generation=7, nonce="replacement")
        self.assertEqual(replacement["status"], "reserved")

    def test_overrun_expiry_generation_and_replay_fail_closed(self) -> None:
        reservation = self.ledger.reserve(self.request, current_generation=7, nonce="reserve")
        with self.assertRaises(BudgetError):
            self.ledger.settle(reservation, Usage(41, 300, 100, 110), current_generation=7, nonce="overrun")
        with self.assertRaises(BudgetError):
            self.ledger.settle(reservation, Usage(35, 280, 90, 200), current_generation=7, nonce="expired")
        with self.assertRaises(BudgetError):
            self.ledger.settle(reservation, Usage(35, 280, 90, 110), current_generation=8, nonce="generation")
        settled = self.ledger.settle(reservation, Usage(35, 280, 90, 110), current_generation=7, nonce="settle")
        with self.assertRaises(BudgetError):
            self.ledger.settle(settled, Usage(30, 200, 50, 111), current_generation=7, nonce="replay")

    def test_tampered_reservation_and_route_digest_validation(self) -> None:
        reservation = self.ledger.reserve(self.request, current_generation=7, nonce="reserve")
        tampered = copy.deepcopy(reservation)
        tampered["reserved"]["cost"] = 0
        with self.assertRaises(BudgetError):
            self.ledger.settle(tampered, Usage(1, 1, 1, 110), current_generation=7, nonce="tamper")
        with self.assertRaises(BudgetError):
            BudgetRequest("bad", "req", "sha256:" + "2" * 64, 7, 1, 1, 1, 100, ttl_seconds=0)

    def test_replay_and_stale_generation_admission(self) -> None:
        with self.assertRaises(BudgetError):
            self.ledger.reserve(self.request, current_generation=8, nonce="stale")
        self.ledger.reserve(self.request, current_generation=7, nonce="reserve")
        with self.assertRaises(BudgetError):
            self.ledger.reserve(self.request, current_generation=7, nonce="reserve-again")
        with self.assertRaises(BudgetError):
            self.ledger.reserve(BudgetRequest("r-2", "req-2", ROUTE, 7, 1, 1, 1, 100), current_generation=7, nonce="reserve")


if __name__ == "__main__":
    unittest.main(verbosity=2)
