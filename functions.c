#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <openssl/des.h>



struct Config{
  uint16_t pnr;
  uint16_t tsid;
  uint16_t pmt_pid;
  uint16_t pcr_pid;
  uint16_t emm_pid;
  uint16_t ecm_pid;
  uint16_t cas;
};

struct Subscription{
    uint32_t serial_no;
    uint32_t start;
    uint32_t finish;
    uint32_t access_criteria;
};


// 4 bytes to uint32_t
uint32_t b2long(const uint8_t *bytes) {
    return (uint32_t)bytes[3] | ((uint32_t)bytes[2] << 8) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[0] << 24);
}

// 2 bytes to uint16_t
uint16_t b2int(const uint8_t *bytes, bool pid) {
    return (uint16_t)(bytes[1]) | ((uint16_t)(bytes[0] & (pid ? 0x1F : 0xFF)) << 8);
}

void dec2gost(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *plaintext) {
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock key1, key2, key3;
    memcpy(key1, key, 8);         // Первые 8 байт ключа 
    memcpy(key2, key + 8, 8);     // Вторые 8 байт ключа
    memcpy(key3, key + 16, 8);    // Третьи 8 байт ключа
    DES_set_key((DES_cblock *)key1, &ks1);
    DES_set_key((DES_cblock *)key2, &ks2);
    DES_set_key((DES_cblock *)key3, &ks3);
    for (int i = 0; i < ciphertext_len; i += 8) {
        DES_ecb3_encrypt((DES_cblock *)(ciphertext + i), (DES_cblock *)(plaintext + i), &ks1, &ks2, &ks3, DES_DECRYPT);
    }
} 

unsigned char CryptTable[] = {
    0xDA, 0x26, 0xE8, 0x72, 0x11, 0x52, 0x3E, 0x46,
    0x32, 0xFF, 0x8C, 0x1E, 0xA7, 0xBE, 0x2C, 0x29,
    0x5F, 0x86, 0x7E, 0x75, 0x0A, 0x08, 0xA5, 0x21,
    0x61, 0xFB, 0x7A, 0x58, 0x60, 0xF7, 0x81, 0x4F,
    0xE4, 0xFC, 0xDF, 0xB1, 0xBB, 0x6A, 0x02, 0xB3,
    0x0B, 0x6E, 0x5D, 0x5C, 0xD5, 0xCF, 0xCA, 0x2A,
    0x14, 0xB7, 0x90, 0xF3, 0xD9, 0x37, 0x3A, 0x59,
    0x44, 0x69, 0xC9, 0x78, 0x30, 0x16, 0x39, 0x9A,
    0x0D, 0x05, 0x1F, 0x8B, 0x5E, 0xEE, 0x1B, 0xC4,
    0x76, 0x43, 0xBD, 0xEB, 0x42, 0xEF, 0xF9, 0xD0,
    0x4D, 0xE3, 0xF4, 0x57, 0x56, 0xA3, 0x0F, 0xA6,
    0x50, 0xFD, 0xDE, 0xD2, 0x80, 0x4C, 0xD3, 0xCB,
    0xF8, 0x49, 0x8F, 0x22, 0x71, 0x84, 0x33, 0xE0,
    0x47, 0xC2, 0x93, 0xBC, 0x7C, 0x3B, 0x9C, 0x7D,
    0xEC, 0xC3, 0xF1, 0x89, 0xCE, 0x98, 0xA2, 0xE1,
    0xC1, 0xF2, 0x27, 0x12, 0x01, 0xEA, 0xE5, 0x9B,
    0x25, 0x87, 0x96, 0x7B, 0x34, 0x45, 0xAD, 0xD1,
    0xB5, 0xDB, 0x83, 0x55, 0xB0, 0x9E, 0x19, 0xD7,
    0x17, 0xC6, 0x35, 0xD8, 0xF0, 0xAE, 0xD4, 0x2B,
    0x1D, 0xA0, 0x99, 0x8A, 0x15, 0x00, 0xAF, 0x2D,
    0x09, 0xA8, 0xF5, 0x6C, 0xA1, 0x63, 0x67, 0x51,
    0x3C, 0xB2, 0xC0, 0xED, 0x94, 0x03, 0x6F, 0xBA,
    0x3F, 0x4E, 0x62, 0x92, 0x85, 0xDD, 0xAB, 0xFE,
    0x10, 0x2E, 0x68, 0x65, 0xE7, 0x04, 0xF6, 0x0C,
    0x20, 0x1C, 0xA9, 0x53, 0x40, 0x77, 0x2F, 0xA4,
    0xFA, 0x6D, 0x73, 0x28, 0xE2, 0xCD, 0x79, 0xC8,
    0x97, 0x66, 0x8E, 0x82, 0x74, 0x06, 0xC7, 0x88,
    0x1A, 0x4A, 0x6B, 0xCC, 0x41, 0xE9, 0x9D, 0xB8,
    0x23, 0x9F, 0x3D, 0xBF, 0x8D, 0x95, 0xC5, 0x13,
    0xB9, 0x24, 0x5A, 0xDC, 0x64, 0x18, 0x38, 0x91,
    0x7F, 0x5B, 0x70, 0x54, 0x07, 0xB6, 0x4B, 0x0E,
    0x36, 0xAC, 0x31, 0xE6, 0xD6, 0x48, 0xAA, 0xB4
};

void XRotateLeft8Byte(uint8_t *buf) {
    uint8_t t1 = buf[7];
    uint8_t t2;
    for (int k = 0; k <= 7; k++) {
        t2 = t1;
        t1 = buf[k];
        buf[k] = (buf[k] << 1) | (t2 >> 7);
    }
}

void SessionKeyDecrypt(uint8_t *key) {
    uint8_t boxkey[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    
    uint8_t tmp1, tmp2;
    for (uint8_t idx1 = 0; idx1 < 8; idx1++) {
        for (uint8_t idx2 = 0; idx2 < 8; idx2++) {
            tmp1 = CryptTable[key[7] ^ boxkey[idx2] ^ idx1];
            tmp2 = key[0];
            memmove(&key[0], &key[1], 6);  // Сдвиг всех байтов влево
            key[5] ^= tmp1;
            key[6] = key[7];
            key[7] = tmp1 ^ tmp2;
        }
        XRotateLeft8Byte(boxkey);  // Ротация boxkey
    }
}

uint8_t csum(uint8_t *bytes) {
	uint8_t cs = 0x00;
	for (int i=0; i < 47; i++) {
		cs += bytes[i];
	}
	return cs;
}

void echo(const char *format, ...) {
    va_list args;
    va_start(args, format);
    pct(); 
    vprintf(format, args);
    va_end(args);
}


// print_current_time
void pct() {  
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info;
    tm_info = localtime(&tv.tv_sec);
    char buffer[30];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("%s.%03ld ", buffer, tv.tv_usec / 1000);
}

void dump(const struct Config *s) {
    const char *arr[] = {"PNR", "TSID", "PMT pid", "EMM pid", "ECM pid", "CAS", "PCR pid"};
    const uint16_t *values[] = {&s->pnr, &s->tsid, &s->pmt_pid, &s->emm_pid, &s->ecm_pid, &s->cas, &s->pcr_pid};
    
    int numFields = sizeof(arr) / sizeof(arr[0]);
    for (int j = 0; j < numFields; j++) {
        pct();
        printf("[%s] 0x%04X (%u)\n", arr[j], *values[j], *values[j]);
    }
}

uint16_t get_pid(const uint8_t *packet) {
    return ((packet[1] & 0x1F) << 8) | packet[2];
}


bool get_bit(unsigned char byte, int position) {
    if (position < 0 || position > 7) return false;
    return (byte >> position) & 1;
}

void set_bit(unsigned char *byte, int position, bool value) {
    if (position < 0 || position > 7) return;
    if (value) {
        *byte |= (1 << position); // 1
    } else {
        *byte &= ~(1 << position); // 0
    }
}


// to convert one character from hex to number
unsigned char hex_to_byte(char hex) {
    if (hex >= '0' && hex <= '9') return hex - '0';
    if (hex >= 'a' && hex <= 'f') return hex - 'a' + 10;
    if (hex >= 'A' && hex <= 'F') return hex - 'A' + 10;
    return 0;
}

// to convert hex string to byte array
void hex_string_to_bytes(const char *hex_string, unsigned char *byte_array) {
    size_t len = strlen(hex_string);
    for (size_t i = 0; i < len; i += 2) {
        byte_array[i / 2] = (hex_to_byte(hex_string[i]) << 4) | hex_to_byte(hex_string[i + 1]);
    }
}