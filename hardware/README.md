# Raspberry Pi Deployment (NFR-PORT-01)

How to run Pocket Packet Sniffer on a Raspberry Pi 4 (Raspberry Pi OS 64-bit) so it starts by itself at boot and can be viewed from a phone.

Two services run on the Pi:

| Service | What it does | Port |
| :--- | :--- | :--- |
| Dashboard | Web UI and REST/WebSocket API (F4) | TCP 8000 |
| Capture | Captures from Ethernet, WiFi, BLE and ESP32 probes into rotating PCAP files in `data/pcaps/` (F1) | UDP 5555 for ESP32 |

Choose **one** of the two install options below.

## Option A: Docker Compose (one command)

Requires Docker with the compose plugin.

```bash
git clone https://github.com/varshinigt/SE-miniproject-CS500-517-536-928.git
cd SE-miniproject-CS500-517-536-928
docker compose up -d --build
```

This builds the image and starts `dashboard` and `capture`. Both use `restart: unless-stopped`, so Docker restarts them after a crash and starts them again at boot (enable Docker at boot with `sudo systemctl enable docker`).

- Different Ethernet interface: `PPS_ETH_IFACE=enx001122 docker compose up -d`
- Logs: `docker compose logs -f capture`
- Tests in the container: `docker compose run --rm tests`

## Option B: systemd (no Docker)

```bash
sudo ./scripts/install_pi.sh
```

The script copies the code to `/opt/pocket-packet-sniffer`, creates a virtual environment, and installs and enables two units:

- `pocket-packet-sniffer.service` runs the dashboard
- `pocket-packet-capture.service` runs `python -m src.capture`

Both have `Restart=always`, so systemd restarts them if they crash. By default capture runs on `eth0` plus the ESP32 listener. To change the sources, create `/etc/default/pocket-packet-sniffer`:

```bash
PPS_CAPTURE_ARGS=--ethernet eth0 --wifi wlan0mon --ble hci0 --esp32 --output-dir /opt/pocket-packet-sniffer/data/pcaps
```

then run `sudo systemctl restart pocket-packet-capture`.

## Capture options

```
python -m src.capture [--ethernet IFACE] [--wifi IFACE] [--ble HCI] [--esp32 [PORT]]
                      [--output-dir DIR] [--max-mb 50] [--max-minutes 15]
```

A source whose interface is missing is logged and skipped; the others keep running. If no source can start, the process exits with code 1 and systemd retries after 5 seconds.

## WiFi monitor mode

The Pi's built-in WiFi does not support monitor mode. Use a USB adapter that does, then create the monitor interface before starting capture:

```bash
sudo iw dev wlan1 interface add wlan0mon type monitor
sudo ip link set wlan0mon up
```

## Checking the acceptance criteria

1. **One-command start:** `docker compose up -d --build`, or `sudo ./scripts/install_pi.sh`.
2. **Capturing within 60 s of power-on, restarted on crash:**
   - Reboot, then run `systemd-analyze` and `journalctl -b -u pocket-packet-capture | head`. The "Started capture source" line's timestamp, compared with boot time, gives the start-up time.
   - Crash test: `sudo pkill -9 -f "src.capture"`, wait 5 s, then `systemctl status pocket-packet-capture` should show it running again.
3. **Dashboard from a phone:** connect the phone to the same network and open `http://<pi-ip>:8000` (`hostname -I` shows the Pi's IP).

## ESP32 probe format

ESP32 sniffer nodes send one UDP datagram per frame to the Pi on port 5555:

| Bytes | Field | Type |
| :--- | :--- | :--- |
| 0-3 | Magic `ESP1` | ASCII |
| 4 | RSSI | int8 |
| 5 | Channel | uint8 |
| 6-7 | Payload length | uint16, big-endian |
| 8- | Raw 802.11 frame | bytes |
