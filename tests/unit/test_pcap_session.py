"""Unit tests for F1 PCAP sessions (UT_F1_03, UT_F1_04)."""

import os

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

from src.capture.session import PcapSession, replay_pcap


def make_packet(index):
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(
        sport=1000 + index, dport=53
    )


class FakeClock:
    def __init__(self, start=1_700_000_000.0):
        self.now = start

    def __call__(self):
        return self.now


def test_session_writes_timestamped_pcap_readable_by_scapy(tmp_path):
    with PcapSession(str(tmp_path)) as session:
        for i in range(3):
            session.write(make_packet(i))
    assert len(session.files) == 1
    name = os.path.basename(session.files[0])
    assert name.startswith("capture_") and name.endswith(".pcap")
    assert len(rdpcap(session.files[0])) == 3


def test_rotates_when_size_limit_reached(tmp_path):
    packet = make_packet(0)
    per_packet = 16 + len(packet)
    # room for the header plus two packets per file
    limit = 24 + 2 * per_packet
    with PcapSession(str(tmp_path), max_bytes=limit) as session:
        for i in range(5):
            session.write(make_packet(i))
    assert len(session.files) == 3
    counts = [len(rdpcap(f)) for f in session.files]
    assert counts == [2, 2, 1]


def test_rotates_when_duration_limit_reached(tmp_path):
    clock = FakeClock()
    with PcapSession(str(tmp_path), max_seconds=60, clock=clock) as session:
        session.write(make_packet(0))
        clock.now += 30
        session.write(make_packet(1))
        clock.now += 31
        session.write(make_packet(2))
    assert len(session.files) == 2
    assert [len(rdpcap(f)) for f in session.files] == [2, 1]


def test_filenames_are_unique_within_the_same_second(tmp_path):
    clock = FakeClock()
    with PcapSession(str(tmp_path), max_bytes=100, clock=clock) as session:
        for i in range(4):
            session.write(make_packet(i))
    assert len(set(session.files)) == len(session.files)


def test_oversized_packet_does_not_rotate_forever(tmp_path):
    with PcapSession(str(tmp_path), max_bytes=10) as session:
        session.write(make_packet(0))
        session.write(make_packet(1))
    assert session.packets_written == 2
    assert len(session.files) == 2


def test_invalid_limits_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        PcapSession(str(tmp_path), max_bytes=0)
    with pytest.raises(ValueError):
        PcapSession(str(tmp_path), max_seconds=-1)


def test_output_directory_is_created(tmp_path):
    target = tmp_path / "sessions" / "run1"
    with PcapSession(str(target)) as session:
        session.write(make_packet(0))
    assert target.is_dir()


def test_replay_delivers_same_packets_in_same_order(tmp_path):
    with PcapSession(str(tmp_path)) as session:
        for i in range(10):
            session.write(make_packet(i))
    received = []
    count = replay_pcap(
        session.files[0], lambda p, iface: received.append((p, iface))
    )
    assert count == 10
    assert [p[UDP].sport for p, _ in received] == [1000 + i for i in range(10)]
    assert all(iface == "replay" for _, iface in received)


def test_replay_uses_given_interface_name(tmp_path):
    with PcapSession(str(tmp_path)) as session:
        session.write(make_packet(0))
    seen = []
    replay_pcap(session.files[0], lambda p, i: seen.append(i), interface="eth0")
    assert seen == ["eth0"]


def test_replay_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        replay_pcap(str(tmp_path / "nope.pcap"), lambda p, i: None)
