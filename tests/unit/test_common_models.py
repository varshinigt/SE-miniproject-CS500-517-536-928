
"""Unit tests for the common NormalizedRecord data model."""

import unittest

from src.common.models import NormalizedRecord


class TestNormalizedRecord(unittest.TestCase):

    def test_metadata_initializes_empty_dict_when_details_is_none(self):
        record = NormalizedRecord(
            timestamp=1.0,
            interface="eth0",
            link_type="Ethernet",
            details=None,
        )

        self.assertEqual(record.metadata, {})
        self.assertEqual(record.details, {})

    def test_metadata_returns_existing_details(self):
        record = NormalizedRecord(
            timestamp=1.0,
            interface="eth0",
            link_type="Ethernet",
            details={"key": "value"},
        )

        self.assertEqual(record.metadata, {"key": "value"})

    def test_metadata_setter_updates_details(self):
        record = NormalizedRecord(
            timestamp=1.0,
            interface="eth0",
            link_type="Ethernet",
        )

        record.metadata = {"protocol": "TCP"}

        self.assertEqual(record.details, {"protocol": "TCP"})
        self.assertEqual(record.metadata, {"protocol": "TCP"})

    def test_payload_len_returns_length(self):
        record = NormalizedRecord(
            timestamp=1.0,
            interface="eth0",
            link_type="Ethernet",
            length=128,
        )

        self.assertEqual(record.payload_len, 128)

    def test_to_dict_uses_srs_field_names(self):
        record = NormalizedRecord(
            timestamp=1.0,
            interface="eth0",
            link_type="Ethernet",
            protocol="TCP",
            length=128,
            details={"key": "value"},
        )

        result = record.to_dict()

        self.assertEqual(result["payload_len"], 128)
        self.assertEqual(result["metadata"], {"key": "value"})
        self.assertNotIn("length", result)
        self.assertNotIn("details", result)

    def test_to_dict_handles_missing_details(self):
        record = NormalizedRecord(
            timestamp=1.0,
            interface="eth0",
            link_type="Ethernet",
            details=None,
        )

        self.assertEqual(record.to_dict()["metadata"], {})


if __name__ == "__main__":
    unittest.main()
