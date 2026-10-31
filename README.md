Vulnfin

Command-line offensive security toolkit for Linux.

Install

Requires Linux and Python 3.11 or newer.

bash bootstrap.sh
vulnfin -h

The installer places the command in /usr/local/bin and the application in /usr/local/lib/vulnfin. It uses system Python and distro-managed dependencies. On Arch Linux, missing Python dependencies are installed through pacman. The old project environment is removed after the installed command passes its launch check. Re-run the installer after updating the source.

Required system tools on Arch Linux:
sudo pacman -S --needed iw iproute2 ethtool pciutils usbutils util-linux bluez-utils tcpdump wireshark-cli

Wi-Fi

vulnfin recon wifi -i wlan1
vulnfin recon wifi -i wlan1 -P
vulnfin recon wifi -i wlan1 -c
vulnfin recon wifi -i wlan1 -S LabNet -j
vulnfin recon wifi -i wlan1 -B 02:11:22:33:44:55
vulnfin recon wifi -i wlan1 -o wifi.json
vulnfin target show 02:11:22:33:44:55 -I wifi.json
vulnfin monitor wifi -i wlan1 --duration 60 --interval 5
vulnfin capture wifi -i wlan1 --channel 6 --duration 30 -B 02:11:22:33:44:55 -o capture.pcap

Active discovery is the default. -P selects passive scanning; -c reads cached results. Filters apply after collection. A BSSID filter selects the recorded address, not a physical device identity. Protected interfaces are kept out of fresh scans and capture.

Monitoring repeats managed-mode scans. Its table retains networks observed during the watch and shows their reported age when available. -j streams JSON lines; -o saves the final Wi-Fi report. Monitoring does not capture packets.

Packet capture switches a dedicated adapter to monitor mode. It refuses a connected adapter, records to the requested PCAP, then restores the prior mode, administrative state and NetworkManager ownership. It stops at the requested duration or near --max-mb, which defaults to 64. Capture uses one channel unless another program changes it; there is no automatic channel hopping. Cleanup failures are reported. A force kill or power loss cannot run cleanup.

Packet inspection

vulnfin inspect wifi capture.pcap
vulnfin inspect wifi capture.pcap --limit 1000 --filter 'wlan.fc.type == 0' -j
vulnfin inspect wifi capture.pcap --limit 1000 -o decoded.json

Inspection uses TShark offline and does not open the radio. The entire capture is read by default. --limit explicitly bounds input frames, including frames rejected by the display filter. Every decoded matching row is displayed. JSON includes frame types, transmitter, receiver, source, destination, BSSID, SSID bytes and text, radio metadata, protection/retry flags and exposed network headers. PCAP and PCAPNG input are accepted. Names and addresses are decoded only when present; data is not decrypted. A capture contains activity from the channel and period recorded, not a full device inventory.

ESP32

Requires an ESP32-S3 and Arduino CLI with Espressif core 3.3.12. Firmware is included; flashing is explicit.

vulnfin device ports
vulnfin device flash --port /dev/ttyACM0
vulnfin device info --port /dev/ttyACM0
vulnfin recon espwifi --port /dev/ttyACM0
vulnfin recon espwifi --port /dev/ttyACM0 -A -o esp-wifi.json
vulnfin recon ble --port /dev/ttyACM0 --duration 10
vulnfin recon ble --port /dev/ttyACM0 --duration 10 -A -j
vulnfin recon nrf --port /dev/ttyACM0 --samples 64

Board settings target ESP32-S3 N16R8. Native USB JTAG/serial and common USB-UART bridges are detected before flashing; CDC settings follow the selected connection. Unknown connections require --fqbn. Flashing is not automatic. Auto port selection is used only when exactly one USB serial port is present; firmware identity is checked after opening it.

ESP Wi-Fi scans cover 2.4 GHz. ESP Wi-Fi and BLE discovery are passive unless -A is supplied. BLE output includes advertising names, service UUIDs, manufacturer data and raw payloads in JSON. Addresses retain their public or random type; an advertised name is optional. Detailed decoding includes 16-, 32- and 128-bit service UUIDs, service data, flags, appearance and advertised transmit power when present. It does not connect to GATT services. Dropped advertisements are reported.

nRF wiring: CE 4, CSN 5, SCK 18, MOSI 17, MISO 16, VCC 3.3 V and common GND. Channel activity uses receive-only RPD sampling. It is not a calibrated power measurement, a packet decoder or device identification. A successful register check confirms the SPI path, not RF performance. The table shows every channel with detector hits; -d or -j includes all 126 channel records, including zero-hit channels. Names and MAC addresses cannot be inferred from power-detector hits.

The device stops work after a missing host heartbeat. Wi-Fi, BLE and nRF operations run sequentially on one agent. Simultaneous peak throughput is not claimed.

Network

vulnfin recon hardware
vulnfin recon network
vulnfin recon services 192.168.1.10 -p 22,80,443,554
vulnfin recon services 192.168.1.0/24 -p 80,443,554 -o services.json
vulnfin recon cameras --address 192.168.1.20 --duration 5 -o onvif.json
vulnfin correlate wifi.json esp-wifi.json -j

Service discovery uses TCP connections on explicit IP targets, up to 256 addresses and 256 ports. Open ports are distinct from verified protocol responses. HTTP, RTSP, SSH and TLS evidence is collected when available. A port number alone does not establish a service or camera identity. TLS certificate verification is not performed during identification and is labelled accordingly.

Camera discovery sends a local ONVIF probe through the supplied local IPv4 address. It reports responding video-transmitter advertisements; it does not open streams or authenticate to devices. No response does not prove that cameras are absent. Neighbour-cache output retains IP addresses, MAC addresses, interfaces and reachability states.

Correlation matches addresses across explicit saved reports. Matching Wi-Fi BSSIDs from Linux and ESP observations are grouped. BLE address types remain separate. Neighbour-cache MAC matches are reported as address evidence rather than proof of a physical device identity. Shared SSIDs are not merged as devices.

Output

-h shows command help. -j prints JSON, -d shows detailed evidence, -v sends progress to stderr and -o saves to a new file. Existing files are kept. Empty scans, missing permissions, unavailable hardware and incomplete results remain distinct.

Commands run directly from any directory. Radio operations request administrative access when needed; passwords are handled by Linux. Existing credentials are reused, and noninteractive runs fail clearly if administrative access is unavailable.

Results stay in memory unless explicitly saved. There are no sessions, history databases, automatic reports or backups. Firmware build files are temporary. Optional interface settings are read from ~/.config/vulnfin/config.toml, or XDG_CONFIG_HOME when set. Resource locks use Linux abstract sockets and leave no lock files.

Use only on devices and networks you own or are authorized to assess. Discovery records observations; it does not confirm exploitation. Raw packet injection, replay, Wi-Fi client disruption, BLE GATT operations and nRF protocol decoding are not implemented.
