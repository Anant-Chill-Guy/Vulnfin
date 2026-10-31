#include <Arduino.h>
#include <ctype.h>
#include <WiFi.h>
#include <SPI.h>
#include <freertos/queue.h>
#include <esp_wifi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

struct BleRecord {
  char address[18];
  uint8_t addressType;
  int rssi;
  uint8_t length;
  uint8_t payload[62];
};

QueueHandle_t bleQueue;
volatile bool bleDone = false;
volatile bool bleLimit = false;
volatile uint32_t dropped = 0;
volatile uint8_t job = 0;
BLEScan *bleScanner = nullptr;
String jobId;
String input;
uint32_t contact = 0;
uint32_t started = 0;
uint32_t seconds = 10;
bool activeScan = false;
uint16_t samples = 64;
uint16_t rounds = 0;
uint16_t wifiIndex = 0;
uint8_t rfChannel = 0;
bool receiving = false;
uint32_t receiveUntil = 0;
uint16_t hits[126];
uint8_t saved[5];
const uint8_t registersToSave[5] = {0, 1, 2, 5, 6};
const uint8_t cePin = 4;
const uint8_t csPin = 5;

String quoted(const String &value) {
  String result = "\"";
  for (size_t i = 0; i < value.length(); ++i) {
    uint8_t c = value[i];
    if (c == '"' || c == '\\') {
      result += '\\';
      result += char(c);
    } else if (c < 32 || c >= 127) {
      char text[7];
      snprintf(text, sizeof(text), "\\u%04x", c);
      result += text;
    } else result += char(c);
  }
  return result + '"';
}

String hexBytes(const uint8_t *data, size_t length) {
  String text;
  text.reserve(length * 2);
  const char *digits = "0123456789abcdef";
  for (size_t i = 0; i < length; ++i) {
    text += digits[data[i] >> 4];
    text += digits[data[i] & 15];
  }
  return text;
}

void emit(const String &id, const char *type, const String &fields = "") {
  Serial.print("{\"id\":");
  Serial.print(quoted(id));
  Serial.print(",\"type\":");
  Serial.print(quoted(type));
  if (fields.length()) {
    Serial.print(',');
    Serial.print(fields);
  }
  Serial.println('}');
}

uint8_t readRegister(uint8_t reg) {
  SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
  digitalWrite(csPin, LOW);
  SPI.transfer(reg & 31);
  uint8_t value = SPI.transfer(255);
  digitalWrite(csPin, HIGH);
  SPI.endTransaction();
  return value;
}

void writeRegister(uint8_t reg, uint8_t value) {
  SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));
  digitalWrite(csPin, LOW);
  SPI.transfer(0x20 | (reg & 31));
  SPI.transfer(value);
  digitalWrite(csPin, HIGH);
  SPI.endTransaction();
}

bool nrfPresent() {
  uint8_t channel = readRegister(5);
  writeRegister(5, 37);
  bool present = readRegister(5) == 37;
  writeRegister(5, channel);
  return present && readRegister(5) == channel;
}

void restoreNrf() {
  digitalWrite(cePin, LOW);
  for (int i = 4; i >= 0; --i) writeRegister(registersToSave[i], saved[i]);
  receiving = false;
}

void finish(bool cancelled = false) {
  if (!job) return;
  uint8_t previous = job;
  job = 0;
  if (previous == 1) {
    esp_wifi_scan_stop();
    WiFi.scanDelete();
    WiFi.mode(WIFI_OFF);
  }
  if (previous == 2) {
    if (bleScanner && bleScanner->isScanning()) bleScanner->stop();
    bleDone = false;
  }
  if (previous == 3) restoreNrf();
  emit(jobId, "done", "\"cancelled\":" + String(cancelled ? "true" : "false") + ",\"dropped\":" + String(dropped));
  jobId = "";
}

class ScanCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice device) override {
    if (job != 2 || !bleQueue) return;
    BleRecord record = {};
    snprintf(record.address, sizeof(record.address), "%s", device.getAddress().toString().c_str());
    record.addressType = device.getAddressType();
    record.rssi = device.getRSSI();
    record.length = min(size_t(62), device.getPayloadLength());
    if (record.length) memcpy(record.payload, device.getPayload(), record.length);
    if (xQueueSend(bleQueue, &record, 0) != pdTRUE) ++dropped;
    if (bleScanner->getResults()->getCount() >= 256) bleLimit = true;
  }
};

ScanCallbacks scanCallbacks;

void scanComplete(BLEScanResults results) {
  if (job == 2) bleDone = true;
}

bool initializeBle() {
  if (!bleQueue) return false;
  if (bleScanner) return true;
  if (!BLEDevice::init("")) return false;
  bleScanner = BLEDevice::getScan();
  if (!bleScanner) return false;
  bleScanner->setAdvertisedDeviceCallbacks(&scanCallbacks, true, false);
  bleScanner->setInterval(50);
  bleScanner->setWindow(30);
  return true;
}

const char *authName(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA-PSK";
    case WIFI_AUTH_WPA2_PSK: return "WPA2-PSK";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2-PSK";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Enterprise";
    case WIFI_AUTH_WPA3_PSK: return "WPA3-SAE";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    case WIFI_AUTH_OWE: return "OWE";
    default: return "Unknown";
  }
}

bool validId(const String &id) {
  if (id.length() != 8) return false;
  for (size_t i = 0; i < id.length(); ++i) if (!isxdigit(id[i])) return false;
  return true;
}

void handleCommand(String line) {
  char name[16] = {};
  char identity[16] = {};
  unsigned long value = 10;
  unsigned int active = 0;
  if (sscanf(line.c_str(), "%15s %15s %lu %u", name, identity, &value, &active) < 2) return;
  String id(identity);
  if (!validId(id)) return;
  if (!strcmp(name, "PING")) {
    if (job && id == jobId) contact = millis();
    return;
  }
  if (!strcmp(name, "STOP")) {
    if (job && id == jobId) finish(true);
    return;
  }
  if (job) {
    emit(id, "error", "\"message\":\"Device busy\"");
    return;
  }
  if (!strcmp(name, "HELLO")) {
    String caps = "\"capabilities\":{\"wifi\":true,\"ble\":true,\"nrf\":" + String(nrfPresent() ? "true" : "false") + '}';
    emit(id, "hello", "\"agent\":\"Vulnfin\",\"protocol\":1,\"chip\":" + quoted(ESP.getChipModel()) +
         ",\"flash_bytes\":" + String(ESP.getFlashChipSize()) + ",\"psram_bytes\":" + String(ESP.getPsramSize()) + ',' + caps);
    emit(id, "done");
    return;
  }
  if ((!strcmp(name, "NRF") && (value < 1 || value > 512)) || (strcmp(name, "NRF") && (value < 1 || value > 300))) {
    emit(id, "error", "\"message\":\"Invalid duration or samples\"");
    return;
  }
  jobId = id;
  contact = started = millis();
  dropped = 0;
  seconds = value;
  activeScan = active != 0;
  if (!strcmp(name, "WIFI")) {
    job = 1;
    wifiIndex = 0;
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    int result = WiFi.scanNetworks(true, true, !activeScan, 300);
    if (result == WIFI_SCAN_FAILED) {
      emit(id, "error", "\"message\":\"Wi-Fi scan could not start\"");
      finish();
    }
  } else if (!strcmp(name, "BLE")) {
    job = 2;
    bleDone = bleLimit = false;
    if (bleQueue) xQueueReset(bleQueue);
    if (!initializeBle()) {
      emit(id, "error", "\"message\":\"BLE initialization failed\"");
      finish();
      return;
    }
    bleScanner->setActiveScan(activeScan);
    if (!bleScanner->start(seconds, scanComplete, false)) {
      emit(id, "error", "\"message\":\"BLE scan could not start\"");
      finish();
    }
  } else if (!strcmp(name, "NRF")) {
    if (!nrfPresent()) {
      emit(id, "error", "\"message\":\"nRF24 not responding; check wiring and power\"");
      jobId = "";
      return;
    }
    for (int i = 0; i < 5; ++i) saved[i] = readRegister(registersToSave[i]);
    memset(hits, 0, sizeof(hits));
    samples = value;
    rounds = 0;
    rfChannel = 0;
    receiving = false;
    writeRegister(1, 0);
    writeRegister(2, 1);
    writeRegister(6, 0x06);
    writeRegister(0, 0x03);
    delay(5);
    job = 3;
  } else {
    emit(id, "error", "\"message\":\"Unknown command\"");
    jobId = "";
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(cePin, OUTPUT);
  pinMode(csPin, OUTPUT);
  digitalWrite(cePin, LOW);
  digitalWrite(csPin, HIGH);
  SPI.begin(18, 16, 17, csPin);
  bleQueue = xQueueCreate(64, sizeof(BleRecord));
  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  WiFi.mode(WIFI_OFF);
}

void loop() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n') {
      handleCommand(input);
      input = "";
    } else if (c != '\r') {
      if (input.length() < 128) input += c;
      else input = "";
    }
  }
  if (job && millis() - contact > 4000) finish(true);
  if (job == 1) {
    int count = WiFi.scanComplete();
    if (count >= 0) {
      int limit = min(count, 255);
      for (int batch = 0; batch < 4 && wifiIndex < limit; ++batch) {
        int i = wifiIndex++;
        String ssid = WiFi.SSID(i);
        emit(jobId, "wifi", "\"address\":" + quoted(WiFi.BSSIDstr(i)) + ",\"ssid\":" + quoted(ssid) +
             ",\"ssid_hex\":" + quoted(hexBytes((const uint8_t *)ssid.c_str(), ssid.length())) +
             ",\"channel\":" + String(WiFi.channel(i)) + ",\"rssi\":" + String(WiFi.RSSI(i)) +
             ",\"security\":" + quoted(authName(WiFi.encryptionType(i))));
      }
      if (wifiIndex >= limit) {
        dropped = count - limit;
        finish();
      }
    } else if (count == WIFI_SCAN_FAILED || millis() - started > 20000) {
      emit(jobId, "error", "\"message\":\"Wi-Fi scan failed or timed out\"");
      finish();
    }
  } else if (job == 2) {
    BleRecord record;
    for (int batch = 0; batch < 8 && xQueueReceive(bleQueue, &record, 0) == pdTRUE; ++batch) {
      emit(jobId, "ble", "\"address\":" + quoted(String(record.address)) + ",\"address_type\":" + String(record.addressType) +
           ",\"rssi\":" + String(record.rssi) + ",\"payload_hex\":" + quoted(hexBytes(record.payload, record.length)));
    }
    if (bleLimit) {
      emit(jobId, "error", "\"message\":\"BLE result limit reached; use a shorter scan\"");
      finish();
    } else if (bleDone && uxQueueMessagesWaiting(bleQueue) == 0) finish();
    else if (millis() - started > (seconds + 5) * 1000) {
      emit(jobId, "error", "\"message\":\"BLE scan timed out\"");
      finish();
    }
  } else if (job == 3) {
    if (!receiving) {
      writeRegister(5, rfChannel);
      digitalWrite(cePin, HIGH);
      receiveUntil = micros() + 180;
      receiving = true;
    } else if ((int32_t)(micros() - receiveUntil) >= 0) {
      hits[rfChannel] += readRegister(9) & 1;
      digitalWrite(cePin, LOW);
      receiving = false;
      if (++rfChannel == 126) {
        rfChannel = 0;
        if (++rounds >= samples) {
          for (int i = 0; i < 126; ++i)
            emit(jobId, "nrf", "\"channel\":" + String(i) + ",\"frequency_mhz\":" + String(2400 + i) +
                 ",\"hits\":" + String(hits[i]) + ",\"samples\":" + String(samples));
          finish();
        }
      }
    }
  }
  if (job == 3 && (rfChannel & 15)) delayMicroseconds(20);
  else delay(1);
}
