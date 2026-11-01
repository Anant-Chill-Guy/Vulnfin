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

Assessment

vulnfin assess checks
vulnfin assess report wifi.json services.json
vulnfin assess wifi -i wlan1 -B 02:11:22:33:44:55
vulnfin assess wifi -I wifi.json
vulnfin assess services 192.168.1.10 -p 22,80,443,445,3389,5900 --nmap
vulnfin assess services -I services.json
vulnfin assess services 192.168.1.10 -p 8081 --protocol http --path /app/
vulnfin assess services 192.168.1.10 -p 443 --server-name device.example
vulnfin assess cameras 192.168.1.10 --port 80 --path /onvif/device_service
vulnfin assess ble -I ble.json
vulnfin assess ble --scan --port auto --duration 10
vulnfin assess ble --address 02:11:22:33:44:55 --type random
vulnfin assess ble --address 02:11:22:33:44:55 --type random --read 2a19
vulnfin assess packets capture.pcap
vulnfin assess report wifi.json -j -o findings.json

Report analysis is offline. It accepts 1–8 recon or inspect.wifi JSON reports, up to 32 MiB each and 100000 input records overall. It preserves observation times, source hashes and incomplete-source warnings. Network, hardware and nRF reports provide context; they do not establish vulnerabilities. Saved service reports can be supplied to assess services to explicitly request live checks on their recorded open endpoints. Report analysis itself never follows endpoints or sends requests.

Wi-Fi checks analyse advertised legacy protocols, ciphers, open-link settings and SAE/OWE PMF context. ESP Wi-Fi reports provide only the security classification available from the SDK. BLE advertisement analysis reports available identifiers and malformed fields without treating normal advertising as a vulnerability. Packet analysis looks for unprotected non-EAPOL data frames and decoded cleartext protocol metadata. It does not decrypt content or validate handshakes.

Service assessment accepts explicit IP addresses or CIDRs, up to 2048 address/port pairs. It uses TCP only. Supported native checks cover HTTP/HTTPS, TLS, SSH banners, FTP FEAT, SMTP EHLO, RTSP OPTIONS, Redis PING and MQTT clean-session CONNECT. The protocol override handles nonstandard ports. The intended server name is used for TLS identity validation, SNI and HTTP Host without resolving another target. HTTP redirects are not followed.

HTTP checks examine the selected base path and its .git/HEAD path using bounded GET requests. They review Basic authentication over HTTP, cookie attributes, reflected credentialed CORS, relevant browser headers, directory listings and diagnostic markers. Bodies are limited to 64 KiB and not saved. Cookie values are omitted. Encoded or incomplete bodies are reported as limited coverage. TLS checks use the system trust store and try deprecated TLS versions separately; a failed negotiation is not automatically proof that the server rejects that version.

The --nmap option adds Nmap service detection on the supplied endpoints. Focused scripts are selected on TCP ports 22, 445, 3389 and 5900 for SSH algorithms, SMB signing, RDP encryption and VNC authentication types. Only these four script names are requested, with bounded execution times. General exploit, brute-force and wildcard vulnerability script sets are not used. Nmap may run its normal version-detection probes. No supplied credentials or exploit payloads are used.

Optional assessment tools on Arch Linux:
sudo pacman -S --needed nmap python-bleak

Live BLE GATT checks use the laptop Bluetooth adapter through Bleak 3.x, not the ESP32 serial agent. They require an explicit address and public/random address type, enumerate services and characteristic properties, and read only UUIDs supplied with --read. At most 16 UUIDs are accepted. Values are omitted; only returned byte counts are recorded. Existing paired or connected targets are left untouched because they cannot provide an unpaired baseline. The command does not request pairing, write characteristics or subscribe to notifications. A successful read does not establish data sensitivity or the absence of link encryption.

Camera assessment sends only GetDeviceInformation to the explicit IP, port and path. Successful metadata access without supplied credentials is reported for policy review; it does not establish stream access or administrative control. Generic HTML and SOAP faults are not treated as successful device-information responses.

Optional --advisories reads a local JSON object with an advisories list. Each entry requires id, product, versions, title, reference and conditions; severity is optional and defaults to medium. versions contains exact version strings, reference is a source URL, and conditions describes prerequisites still to verify. Recognized product keys are openssh, apache_http_server, nginx, iis, python, vsftpd and proftpd. Matches remain candidates because banners can be inaccurate and vendors backport fixes. No online CVE feed, bundled vulnerability database or automatic version-range inference is included.

Assessment findings show the affected endpoint, severity, confidence, evidence, meaning and next check. Observed configurations, potential weaknesses and advisory candidates remain distinct; findings are not labelled confirmed vulnerabilities. Observed Wi-Fi and BLE names are kept with their addresses. A missing BLE name is shown as unavailable, and an empty advertised SSID is shown as hidden. Service names, supplied DNS names and observed camera models are kept separately. Each shared issue is explained once, followed by every affected endpoint; no target rows are capped. All findings are displayed. -d also shows individual evidence, confidence, source and every check record; -j includes the complete check results and provenance. Unsupported checks and inconclusive results are shown explicitly. Exit 1 means checks were incomplete, unavailable or could not run; findings alone do not cause a failure exit. Ctrl-C exits with 130. No assessment file is created unless -o is supplied, and existing files are never overwritten.

Targets and verification

vulnfin assess wifi -i wlan1 -o assessment.json
vulnfin target list -I assessment.json
vulnfin target list -I assessment.json --findings-only --severity medium -d
vulnfin target map -I assessment.json -I services-assessment.json --context wifi.json --context network.json -d
vulnfin target select 02:11:22:33:44:55 --protocol wifi -I assessment.json -o selected.json
vulnfin target select 192.168.1.10 -p 443 -I services-assessment.json -o selected-service.json
vulnfin target select 02:11:22:33:44:55 --protocol ble --type random -I ble-assessment.json -o selected-ble.json
vulnfin target verify -I selected.json -i wlan1 -o verified.json
vulnfin target verify -I selected-service.json -d
vulnfin target verify -I selected-ble.json --port auto --adapter hci0

Target list and map accept assessment JSON, not raw recon reports. Repeat -I for up to eight inputs. Rows represent exact Wi-Fi BSSIDs, typed BLE addresses or IP/TCP-port endpoints. Shared names never merge devices. --name filters observed names, --protocol chooses the endpoint family, --severity filters findings at that level or above, and --findings-only excludes endpoints without matching findings. -d shows finding IDs for selecting individual checks. Optional --context reads recon reports for tentative MAC/IP address links; these are not proof of physical identity.

Selection is explicit and has no persistent active-target state. An ambiguous address requires a TCP port, protocol or BLE address type. Repeated --finding ID selects specific findings; otherwise all findings attached to that endpoint are selected. The selection retains names, resource paths, original findings, observation times, source hashes and incomplete-evidence notes. Inputs with conflicting finding IDs or evidence attached to another endpoint are rejected.

Verification refreshes the selected endpoint and reruns supported conditions. Wi-Fi verification uses a fresh adapter scan, not the kernel cache, and reports changed names or missing BSSIDs without claiming the weakness is fixed. BLE advertising targets are refreshed through the ESP32; selected GATT reads use the Linux adapter and only the original characteristic UUIDs. Service verification uses the original IP, TCP port, path and supplied DNS identity. Results from different HTTP paths, ONVIF endpoints or TLS names stay separate, even when they share an IP and port. It does not follow advertised camera URLs or redirects to other hosts.

Git metadata verification checks the exact path and a random control path to detect wildcard responses. CORS verification checks two distinct origins. A reproduced result confirms the observed condition, not successful exploitation or unintended data access. Not seen this time describes the new response only. Debug-page markers, PMF transition-mode context and exact-version advisory matches may still need manual prerequisite or policy review. Unknown checks remain unsupported, and failed or incomplete probes cannot produce a clean verification result.

Packet findings can be rechecked only with an explicit --capture PCAP path. They remain historical capture evidence and do not establish current radio reachability. A mixed Wi-Fi/packet selection checks the live settings and supplied capture separately. Failed or partial radio scans cannot verify a condition as reproduced. At most 64 findings and 16 distinct service-resource jobs are accepted per verification; larger selections must be narrowed explicitly. Verification output includes the new evidence, individual outcomes and verified conditions for later preparation. No exploits are prepared or delivered by these commands.

Files remain optional. Standard input is accepted as -I - for assessment mapping, selection and verification. This example carries JSON between commands without saving a report:

vulnfin assess wifi -i wlan1 -j | vulnfin target select 02:11:22:33:44:55 --protocol wifi -I - -j | vulnfin target verify -I - -i wlan1

Privileged scans in a pipeline need administrative credentials already available to the terminal; otherwise they fail clearly. File-based commands can request Linux authentication normally. All JSON exports are created atomically and refuse existing destinations. Interrupted exports leave no partial JSON report. Verification returns 0 when the selected supported condition checks complete, 1 when conditions remain unresolved or need review, and 130 on interruption. No files are created without -o.

Output

-h shows command help. -j prints JSON, -d shows detailed evidence, -v sends progress to stderr and -o saves to a new file. Existing files are kept. Empty scans, missing permissions, unavailable hardware and incomplete results remain distinct.

Commands run directly from any directory. Radio operations request administrative access when needed; passwords are handled by Linux. Existing credentials are reused, and noninteractive runs fail clearly if administrative access is unavailable.

Results stay in memory unless explicitly saved. There are no sessions, history databases, automatic reports or backups. Firmware build files are temporary. Optional interface settings are read from ~/.config/vulnfin/config.toml, or XDG_CONFIG_HOME when set. Resource locks use Linux abstract sockets and leave no lock files.

Use only on devices and networks you own or are authorized to assess. Discovery records observations; it does not confirm exploitation. Raw packet injection, replay, Wi-Fi client disruption, BLE GATT writes and nRF protocol decoding are not implemented.
