/*
 * Proje: İHA Yer İstasyonu - AES-128 Şifreli ve Frekans Atlamalı Kablosuz Haberleşme Sistemi
 *
 * Bu kod, bir ESP32 mikrodenetleyicisi ve nRF24L01 radyo modülü kullanarak İHA (UAV) ile 
 * güvenli ve kesintisiz çift yönlü veri haberleşmesi kuran yer istasyonu (Ground Station / Slave) yazılımıdır.
 * Sistem, belirlenen 8 farklı frekans kanalı (75, 25, 49, 81, 50, 76, 80, 77) arasında her 5 saniyede bir 
 * atlama (Frequency Hopping) yaparak parazitlerden korunur.
 * Önce kanalları tarayarak İHA'yı bulur, 
 * İHA'nın mikrosaniye hassasiyetindeki saatine kilitlenerek frekans atlamalarını eşzamanlı 
 * takip eder ve olası sinyal kesintilerinde bir süre tahmini takibi sürdürür.
 * Havadan gelen 32 baytlık paketlerin şifresini AES-128 ECB algoritmasıyla çözerken, aynı anda onay 
 * paketinin içine kendi komut verisini şifreleyip İHA'ya geri gönderir ve paket kayıp oranlarını raporlar.
 */

// Ground station side (slave): finds the UAV, locks to its clock and follows its hops.
// States: SCAN -> LOCKED <-> HOLDOVER -> SCAN. Sends its own data back in the ACK payload.

#include <SPI.h>
#include <RF24.h>
#include <string.h>
#include <stdio.h>
#include "esp_timer.h"
#include "mbedtls/aes.h"

// Pin definitions
#define PIN_SCK   18
#define PIN_MISO  19
#define PIN_MOSI  23
#define PIN_CSN   5
#define PIN_CE    22

// Radio configuration (must be identical on both devices)
const byte LINK_ADDRESS[6] = "UAV01";
const uint8_t PAYLOAD_SIZE = 32;   // 32 bytes = 2 AES blocks
const rf24_pa_dbm_e PA_LEVEL = RF24_PA_LOW;   // LOW for desk tests, MAX for range tests

// AES-128 key
const uint8_t AES_KEY[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Frequency hopping configuration (must be identical on both devices)
const uint8_t CHANNELS[8] = {75, 25, 49, 81, 50, 76, 80, 77};  // Gaps between WiFi channels 1, 6, 11
const uint8_t NUM_CHANNELS = sizeof(CHANNELS);
const int64_t HOP_INTERVAL_US = 5000000LL;   // Hop every 5 s

// Link timing
const uint32_t SCAN_DWELL_MS = 25;           // Time spent on each channel while scanning
const uint32_t HOLDOVER_AFTER_MS = 500;      // LOCKED -> HOLDOVER after 500 ms without packets
const uint32_t SCAN_AFTER_MS = 15000;        // HOLDOVER -> SCAN after 15 s (3 slots) without packets
const uint32_t REPORT_INTERVAL_MS = 1000;    // Status line once per second

// Packet types
#define PKT_DATA  1
#define PKT_ACK   2

// UAV -> ground station
struct __attribute__((packed)) DataPacket {
  uint8_t type;
  uint16_t sessionId;   // Random per boot, changes when the UAV restarts
  uint32_t seq;         // Increments on every packet
  int64_t timeUs;       // UAV clock in microseconds
  char payload[17];
};

// Ground station -> UAV (carried in the ACK payload)
struct __attribute__((packed)) AckPacket {
  uint8_t type;
  uint32_t seq;
  char payload[27];
};

static_assert(sizeof(DataPacket) == PAYLOAD_SIZE, "DataPacket must be 32 bytes");
static_assert(sizeof(AckPacket) == PAYLOAD_SIZE, "AckPacket must be 32 bytes");

// Link states
enum LinkState { SCAN, LOCKED, HOLDOVER };
const char* STATE_NAMES[] = {"SCAN", "LOCKED", "HOLDOVER"};

// RF24 radio instance: CE, CSN, 2 MHz SPI clock
RF24 radio(PIN_CE, PIN_CSN, 2000000UL);

uint8_t rxBuffer[PAYLOAD_SIZE];   // Encrypted DATA packet
uint8_t ackBuffer[PAYLOAD_SIZE];  // Encrypted ACK payload

LinkState state = SCAN;
int64_t offsetUs = 0;             // UAV clock = local clock + offset
uint16_t sessionId = 0;
uint32_t lastSeq = 0;
uint32_t ackSeq = 1;              // Seq of the next ACK payload
bool ackQueued = false;           // An ACK payload is queued and not sent yet
uint8_t currentChannel = 255;
uint8_t scanIndex = 0;
uint32_t lastScanHopMs = 0;
uint32_t lastRxMs = 0;

// Packet statistics: received and lost (from seq gaps) UAV packets
struct Stats {
  uint32_t rx;
  uint32_t lost;
};
Stats secStats = {0, 0};     // Last second
Stats slotStats = {0, 0};    // Current slot (one channel)
Stats totalStats = {0, 0};   // Since boot
uint32_t lastReportMs = 0;
char lastUavPayload[sizeof(DataPacket::payload) + 1] = "-";

// Loss ratio in percent
float lossPct(const Stats& s) {
  uint32_t total = s.rx + s.lost;
  return total ? 100.0f * s.lost / total : 0.0f;
}

void countPacket(uint32_t lost) {
  Stats* all[] = {&secStats, &slotStats, &totalStats};
  for (Stats* s : all) {
    s->rx++;
    s->lost += lost;
  }
}

// Encrypt 32 bytes with AES-128 ECB
void aesEncryptECB(const uint8_t* in, uint8_t* out) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);
  for (uint8_t i = 0; i < PAYLOAD_SIZE; i += 16) {
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, in + i, out + i);
  }
  mbedtls_aes_free(&aes);
}

// Decrypt 32 bytes with AES-128 ECB
void aesDecryptECB(const uint8_t* in, uint8_t* out) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, AES_KEY, 128);
  for (uint8_t i = 0; i < PAYLOAD_SIZE; i += 16) {
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, in + i, out + i);
  }
  mbedtls_aes_free(&aes);
}

// UAV clock estimated from the local clock
int64_t uavNowUs() {
  return esp_timer_get_time() + offsetUs;
}

// Queue the next ground station message; it is sent inside the ACK of the next UAV packet.
// The radio removes a sent ACK payload only when the following packet arrives, so right after
// a packet the FIFO still holds the one just sent. Exactly one new message is queued per packet.
void loadAckPayload() {
  if (ackQueued || radio.isFifo(true) == RF24_FIFO_FULL) return;

  AckPacket ack;
  memset(&ack, 0, sizeof(ack));
  ack.type = PKT_ACK;
  ack.seq = ackSeq++;
  snprintf(ack.payload, sizeof(ack.payload), "GS %lu", (unsigned long)ack.seq);

  aesEncryptECB((uint8_t*)&ack, ackBuffer);
  radio.writeAckPayload(1, ackBuffer, PAYLOAD_SIZE);
  ackQueued = true;
}

// Change the channel and keep listening there
void tuneTo(uint8_t ch) {
  // Change the channel in standby mode, then return to RX so the PLL relocks
  radio.stopListening();
  radio.setChannel(ch);
  radio.startListening();
  currentChannel = ch;

  // stopListening() flushes the ACK FIFO; the unsent message is queued again with the same seq
  if (ackQueued) {
    ackSeq--;
    ackQueued = false;
  }
  loadAckPayload();
}

void setState(LinkState next) {
  if (next == state) return;
  Serial.printf("State %s -> %s\n", STATE_NAMES[state], STATE_NAMES[next]);
  state = next;
}

// SCAN: step through the channels. LOCKED/HOLDOVER: follow the UAV's hop sequence.
void updateChannel() {
  if (state == SCAN) {
