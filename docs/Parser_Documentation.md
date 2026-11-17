# F2 Protocol Parsing and Zeek Integration

## 1. Overview

The F2 module is responsible for decoding network packets, converting different protocol frames into a common data structure, and ingesting Zeek log events into SQLite.

It supports Ethernet, Wi-Fi (802.11), BLE, network-layer protocols, transport protocols, and DNS.

## 2. Architecture

The parser uses a pluggable architecture based on an abstract `ProtocolParser` interface.

Main components:

| File | Responsibility |
| :--- | :--- |
| `src/parser/base.py` | Defines the abstract parser interface |
| `src/parser/protocol_parser.py` | Implements Scapy-based Ethernet, Wi-Fi and BLE parsing |
| `src/parser/registry.py` | Registers parsers and dispatches packets to matching parsers |
| `src/parser/zeek_ingest.py` | Parses Zeek JSON and TSV logs and supports file following |
| `src/common/models.py` | Defines the normalized packet record |
| `src/common/zeek_models.py` | Defines the Zeek event model |
| `src/storage/sqlite_store.py` | Stores normalized packets and Zeek events |

## 3. Protocol Parsing

The implementation uses Scapy to identify and decode supported packet layers.

Supported protocols include:

- Ethernet and ARP
- IPv4 and IPv6
- TCP and UDP
- DNS
- IEEE 802.11 Wi-Fi frames
- Bluetooth Low Energy advertisement frames

The Wi-Fi parser handles the different ToDS and FromDS address combinations. The BLE parser extracts advertisement information when available.

## 4. Normalization

Parsed packets are converted into the common `NormalizedRecord` model.

The record can contain:

- Timestamp and interface
- Link type and packet length
- Source and destination MAC addresses
- Source and destination IP addresses
- Protocol and port information
- Protocol-specific details

This common representation allows downstream components to process packets without depending on the original frame type.

## 5. Parser Registry

`ParserRegistry` maintains an ordered collection of parser implementations.

The registry:

1. Registers parser instances implementing `ProtocolParser`.
2. Checks whether each parser supports an incoming packet.
3. Dispatches the packet to the first matching parser.
4. Returns a safe fallback record if no parser matches or parsing fails.

New protocol parsers can be added by implementing the abstract interface and registering the new parser.

## 6. Zeek Log Ingestion

The Zeek ingestion module supports JSON and TSV log records.

Features include:

- Parsing JSON records.
- Reading Zeek TSV headers and field definitions.
- Handling optional and missing values.
- Skipping blank lines and header records.
- Recording malformed input errors without stopping the entire file-processing operation.
- Reading completed log files.
- Following growing log files for newly appended records.

Valid records are converted into `ZeekEvent` objects.

The current implementation handles Zeek log ingestion; launching and managing the Zeek process itself is outside this module.

## 7. SQLite Storage

Zeek events are stored in the `zeek_events` table.

The table stores:

- Timestamp
- Log type
- UID
- Source and destination IP addresses
- Source and destination ports
- Protocol
- Additional metadata

Indexes are provided for timestamp, log type and UID. The storage layer also provides methods to save, retrieve and list Zeek events.

## 8. Bounded Packet Processing Queue

The packet-processing queue is implemented in `src/capture/packet_queue.py`.

Its features include:

- Configurable maximum queue size (default: 1,000 packets).
- Non-blocking packet submission.
- Background worker-based packet processing.
- Processed, dropped and error counters.
- Graceful shutdown with pending packets drained.

This supports NFR-PERF-02, which specifies a maximum queue depth below 10,000 records.

## 9. Verification

The Sprint 2 implementation was tested using automated unit tests.

- Line coverage: 91.90%.
- Branch coverage: 85.37%.
- Synthetic performance test: 5,000 packets processed, with zero drops and zero errors.

The synthetic throughput measurement is not an end-to-end live network throughput measurement.

## 10. Current Limitations

- Zeek process orchestration is not implemented in the ingestion module.
- Live hardware and end-to-end network performance require further validation.
- Wi-Fi monitor-mode and BLE capture depend on suitable hardware and capture configuration.
