Vulnfin

Command-line offensive security toolkit for Linux.

Install

Requires Linux and Python 3.11 or newer.

bash bootstrap.sh
source .venv-vulnfin/bin/activate
sudo pacman -S --needed iw iproute2 ethtool pciutils usbutils util-linux bluez-utils

Commands

vulnfin -h
vulnfin help recon wifi
vulnfin info
vulnfin recon host
vulnfin recon hardware
vulnfin recon network
vulnfin recon wifi -i wlan1
vulnfin recon wifi -i wlan1 -c
vulnfin recon wifi -i wlan1 -A
vulnfin recon wifi -i wlan1 -P
vulnfin recon wifi -i wlan1 -S LabNet
vulnfin recon wifi -i wlan1 -B 02:11:22:33:44:55
vulnfin recon wifi -i wlan1 -f
vulnfin recon wifi -i wlan1 -S LabNet -j
vulnfin recon wifi -i wlan1 -S LabNet -o wifi.json
vulnfin target show 02:11:22:33:44:55 -i wlan1
vulnfin target show 02:11:22:33:44:55 -I wifi.json
vulnfin plugins list

Usage

Wi-Fi discovery uses an active scan by default, sending probe requests. -A explicitly selects active discovery, -P requests a passive scan and -c reads cached results. Live scans request a cache flush to reduce stale results. Busy or aborted requests are retried up to twice within the scan timeout. Fresh scans on the configured protected interface are blocked. Run sudo -v before a scan that needs elevated permissions.

Each matching BSSID gets its own row. -S filters by SSID, -B selects an exact BSSID and -f selects networks with security findings. These options filter the results after collection; they do not restrict radio reception. Filters apply to the table, detailed output, JSON and exported access-point records. Hardware and regulatory metadata describe the interface as a whole.

-j prints JSON. -d shows detailed evidence. -v sends progress to stderr. -o saves a JSON report to a new file in an existing directory. With -B, the display or JSON stdout describes the selected target, while -o saves a Wi-Fi report that target show -I can read.

Target inspection scans again unless -I supplies a saved report. A saved report describes an earlier observation, not current reachability. Findings describe advertised settings; they do not confirm exploitation.

Results stay in memory unless explicitly exported. There are no saved sessions, scan history or automatic command artifacts. Optional interface settings are read from ~/.config/vulnfin/config.toml, or from XDG_CONFIG_HOME when set.

Current scope

Host, hardware, local network and Wi-Fi discovery are implemented. ESP32 communication, BLE/nRF discovery, packet capture and exploitation are future work.
