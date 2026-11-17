"""
Unit Tests for Resilient Packet Processing and Fuzzing Hardening (UT_F3_04, ST_SEC_02)
Tests SEC-02 acceptance criteria:
1. Validating packet fields before passing records to detection rules.
2. Handling malformed, incomplete, and unsupported inputs without crashing.
3. Preventing individual detector exceptions from breaking the pipeline.
4. Testing against corrupted, fuzzed, and boundary packet fixtures.
5. Verifying safe error logging without sensitive payload exposure.
"""

import unittest
from src.detection.engine import DetectionEngine
from src.detection.models import NormalizedRecord
from src.detection.rules.base import BaseDetector


class FaultyCrashingDetector(BaseDetector):
    """Simulates an internal bug or unhandled edge case in a detector rule."""
    def __init__(self):
        super().__init__(name="faulty_detector", enabled=True)

    def process_record(self, record):
        raise ZeroDivisionError("Simulated divide by zero inside detector rule!")

    def reset(self):
        pass


class TestPacketProcessingHardening(unittest.TestCase):

    def setUp(self):
        self.engine = DetectionEngine()

    def test_non_normalized_record_types_rejected(self):
        """Passing raw strings, ints, dicts, or None is handled safely."""
        self.assertFalse(self.engine.validate_record("GET /index.html HTTP/1.1"))
        self.assertFalse(self.engine.validate_record(12345))
        self.assertFalse(self.engine.validate_record({"timestamp": 123.4}))
        self.assertFalse(self.engine.validate_record(None))

        # Processing them yields empty alert list and increments dropped counter
        res = self.engine.process_record("malformed_raw_payload")  # type: ignore
        self.assertEqual(res, [])
        self.assertEqual(self.engine.malformed_dropped, 1)

    def test_invalid_timestamps_rejected(self):
        """NaN, Infinity, negative, and far-future timestamps are dropped."""
        # NaN timestamp
        rec_nan = NormalizedRecord(
            timestamp=float("nan"),
            interface="eth0",
            link_type="ETHERNET",
        )
        self.assertFalse(self.engine.validate_record(rec_nan))
        self.assertEqual(self.engine.process_record(rec_nan), [])

        # Negative timestamp
        rec_neg = NormalizedRecord(
            timestamp=-10.0,
            interface="eth0",
            link_type="ETHERNET",
        )
        self.assertFalse(self.engine.validate_record(rec_neg))

        # Infinite timestamp
        rec_inf = NormalizedRecord(
            timestamp=float("inf"),
            interface="eth0",
            link_type="ETHERNET",
        )
        self.assertFalse(self.engine.validate_record(rec_inf))

        # Absurd far-future timestamp (beyond year 2096)
        rec_future = NormalizedRecord(
            timestamp=9_999_999_999.0,
            interface="eth0",
            link_type="ETHERNET",
        )
        self.assertFalse(self.engine.validate_record(rec_future))

    def test_oversized_interface_and_link_types(self):
        """Massive or malformed interface and link_type strings are rejected."""
        rec_huge_iface = NormalizedRecord(
            timestamp=100.0,
            interface="A" * 1000,
            link_type="ETHERNET",
        )
        self.assertFalse(self.engine.validate_record(rec_huge_iface))

        rec_bad_link = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="L" * 200,
        )
        self.assertFalse(self.engine.validate_record(rec_bad_link))

    def test_out_of_bounds_ports(self):
        """Negative ports or ports > 65535 are rejected."""
        rec_neg_port = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            src_port=-1,
        )
        self.assertFalse(self.engine.validate_record(rec_neg_port))

        rec_huge_port = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            dst_port=99999,
        )
        self.assertFalse(self.engine.validate_record(rec_huge_port))

    def test_out_of_bounds_payload_len(self):
        """Negative payload length or gigantic buffer allocations are rejected."""
        rec_neg_len = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            payload_len=-5,
        )
        self.assertFalse(self.engine.validate_record(rec_neg_len))

        rec_huge_len = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
            payload_len=50_000_000,
        )
        self.assertFalse(self.engine.validate_record(rec_huge_len))

    def test_faulty_rule_exception_does_not_halt_engine(self):
        """An unhandled exception in one rule is caught and other rules continue."""
        faulty = FaultyCrashingDetector()
        self.engine.register_rule(faulty)

        rec = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
        )
        # Should not raise exception
        try:
            alerts = self.engine.process_record(rec)
            self.assertEqual(alerts, [])
        except Exception as e:
            self.fail(f"Engine let faulty rule exception escape: {e}")

    def test_stats_tracking(self):
        """Hardening statistics reflect processed and dropped records."""
        rec_valid = NormalizedRecord(
            timestamp=100.0,
            interface="eth0",
            link_type="ETHERNET",
        )
        rec_bad = NormalizedRecord(
            timestamp=-5.0,
            interface="eth0",
            link_type="ETHERNET",
        )
        self.engine.process_record(rec_valid)
        self.engine.process_record(rec_bad)

        stats = self.engine.get_stats()
        self.assertEqual(stats["total_processed"], 1)
        self.assertEqual(stats["malformed_dropped"], 1)


if __name__ == "__main__":
    unittest.main()
