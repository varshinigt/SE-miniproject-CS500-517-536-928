\# Packet Queue Performance Benchmark



\## Objective

Evaluate the throughput and bounded queue behavior of the asynchronous packet-processing queue implemented for NFR-PERF-02.



\## Test Configuration

\- Environment: Windows 11, Python 3.12.10

\- Test framework: pytest

\- Packet count: 5,000 synthetic packets

\- Queue capacity: 5,000 packets

\- Processing mode: Asynchronous background worker

\- Handler: Lightweight in-memory packet handler

\- Measurement: `time.perf\_counter()`



\## Observed Results



| Metric | Observed value |

|---|---:|

| Packets submitted | 5,000 |

| Packets processed | 5,000 |

| Packets dropped | 0 |

| Processing errors | 0 |

| Elapsed time | 0.0112 seconds |

| Throughput | 446,703.76 packets/second |



\## Result

The benchmark completed successfully. All 5,000 submitted packets were processed without drops or handler errors. The queue returned to zero depth after processing.



\## Limitations

\- The benchmark uses synthetic packets and a lightweight handler.

\- It measures queue-processing throughput, not end-to-end network capture performance.

\- Real-world throughput depends on packet size, protocol parsing complexity, hardware, and capture conditions.

\- The benchmark was run on Windows 11 using Python 3.12.10.



\## Reproduction



Run:



```powershell

pytest -s -v tests\\performance\\test\_packet\_queue\_performance.py

```



