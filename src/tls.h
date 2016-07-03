/* Copyright 2015 Marco Bellaccini (marco.bellaccini[at!]gmail.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

/* This is mostly from TLS RFCs */

#include <inttypes.h>


//1-byte alignment for structures: inefficient but makes life easier for network stuff
#pragma pack(1)

typedef uint8_t uint8;
typedef uint8_t opaque;
typedef uint16_t uint16;
typedef struct {
	uint8_t msb;
	uint8_t nsb;
	uint8_t lsb;
} uint24;
typedef uint32_t uint32;

typedef struct {
       uint8 major;
       uint8 minor;
} ProtocolVersion;

ProtocolVersion version;
ProtocolVersion version30 = { 3, 0 };     // SSL 3.0
ProtocolVersion version10 = { 3, 1 };     // TLS 1.0
ProtocolVersion version11 = { 3, 2 };     // TLS 1.1
ProtocolVersion version12 = { 3, 3 };     // TLS 1.2

   
/* Alert Messages */


// AlertLevel

#define AL_WARNING 1
#define AL_FATAL 2

// AlertDescription

#define AD_CLOSE_NOTIFY 0
#define AD_UNEXPECTED_MESSAGE 10
#define AD_BAD_RECORD_MAC 20
#define AD_DECRYPTION_FAILED_RESERVED 21
#define AD_RECORD_OVERFLOW 22
#define AD_DECOMPRESSION_FAILURE 30
#define AD_HANDSHAKE_FAILURE 40
#define AD_NO_CERTIFICATE_RESERVED 41
#define AD_BAD_CERTIFICATE 42
#define AD_UNSUPPORTED_CERTIFICATE 43
#define AD_CERTIFICATE_REVOKED 44
#define AD_CERTIFICATE_EXPIRED 45
#define AD_CERTIFICATE_UNKNOWN 46
#define AD_ILLEGAL_PARAMETER 47
#define AD_UNKNOWN_CA 48
#define AD_ACCESS_DENIED 49
#define AD_DECODE_ERROR 50
#define AD_DECRYPT_ERROR 51
#define AD_EXPORT_RESTRICTION_RESERVED 60
#define AD_PROTOCOL_VERSION 70
#define AD_INSUFFICIENT_SECURITY 71
#define AD_INTERNAL_ERROR 80
#define AD_USER_CANCELED 90
#define AD_NO_RENEGOTIATION 100
#define AD_UNSUPPORTED_EXTENSION 110

typedef struct {
       uint8 level;
       uint8 description;
} Alert;
   
   
/* Hello Messages */
typedef struct { } HelloRequest;

typedef struct {
	uint32 gmt_unix_time;
	opaque random_bytes[28];
} Random;


typedef struct {
	uint8 a;
	uint8 b;
} CipherSuite;

typedef uint8_t CompressionMethod;

/* TLS Extensions for Hello Messages */

typedef struct {
	uint16 type;
	uint16 length;
} Extension;

// server_name extension data
typedef struct {
	uint16 list_length;
	uint16 name_type;
	uint8 name_length;
	char* name;
} ServerNameExData;

// elliptic curves extension data
typedef struct {
	uint16 ECLength;
	uint16* curves; // beware, you fixed 35 elements!!!
} ECExData;

// elliptic curves point formats extension data
typedef struct {
	uint8 formats_length;
	uint8* formats; // beware, you fixed 1 element!!!
} ECPFExData;

// TLS Extensions
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_SIGN_ALG 0x000d
#define TLS_EXT_EC 0x000a
#define TLS_EXT_EC_PF 0x000b

// server name
#define TLS_EXT_SERVER_NAME_HOSTNAME 0x0000

// signature algorithm hashes
#define TLS_EXT_SIGN_ALG_H_NONE 0
#define TLS_EXT_SIGN_ALG_H_MD5 1
#define TLS_EXT_SIGN_ALG_H_SHA1 2
#define TLS_EXT_SIGN_ALG_H_SHA224 3
#define TLS_EXT_SIGN_ALG_H_SHA256 4
#define TLS_EXT_SIGN_ALG_H_SHA384 5
#define TLS_EXT_SIGN_ALG_H_SHA512 6

// signature algorithms
#define TLS_EXT_SIGN_ALG_S_ANON 0
#define TLS_EXT_SIGN_ALG_S_RSA 1
#define TLS_EXT_SIGN_ALG_S_DSA 2
#define TLS_EXT_SIGN_ALG_S_ECDSA 3

// signature and hash alg ext
typedef struct {
	uint8 hash;
	uint8 signature;
} SignatureAndHashAlgorithm;

typedef struct {
	uint16 length;
	SignatureAndHashAlgorithm* data;
} SigExData;
      

// elliptic curves
/*
#define TLS_EXT_EC_SECT163K1 1
#define TLS_EXT_EC_SECT163R1 2
#define TLS_EXT_EC_SECT163R2 3
#define TLS_EXT_EC_SECT193R1 4
#define TLS_EXT_EC_SECT193R2 5
#define TLS_EXT_EC_SECT233K1 6
#define TLS_EXT_EC_SECT233R1 7
#define TLS_EXT_EC_SECT239K1 8
#define TLS_EXT_EC_SECT283K1 9
#define TLS_EXT_EC_SECT283R1 10
#define TLS_EXT_EC_SECT409K1 11
#define TLS_EXT_EC_SECT409R1 12
#define TLS_EXT_EC_SECT571K1 13
#define TLS_EXT_EC_SECT571R1 14
#define TLS_EXT_EC_SECP160K1 15
#define TLS_EXT_EC_SECP160R1 16
#define TLS_EXT_EC_SECP160R2 17
#define TLS_EXT_EC_SECP192K1 18
#define TLS_EXT_EC_SECP192R1 19
#define TLS_EXT_EC_SECP224K1 20
#define TLS_EXT_EC_SECP224R1 21
#define TLS_EXT_EC_SECP256K1 22
#define TLS_EXT_EC_SECP256R1 23
#define TLS_EXT_EC_SECP384R1 24
#define TLS_EXT_EC_SECP521R1 25
#define TLS_EXT_EC_BRAINPOOLP256R1 26
#define TLS_EXT_EC_BRAINPOOLP384R1 27
#define TLS_EXT_EC_BRAINPOOLP512R1 28
#define TLS_EXT_EC_FFDHE2048 256
#define TLS_EXT_EC_FFDHE3072 257
#define TLS_EXT_EC_FFDHE4096 258
#define TLS_EXT_EC_FFDHE6144 259
#define TLS_EXT_EC_FFDHE8192 260
#define TLS_EXT_EC_ARB_EXP_PRIME_CURV 65281
#define TLS_EXT_EC_ARB_EXP_CHAR2_CURV 65282
*/


// elliptic curves point formats
#define TLS_EXT_EC_PF_UN 0
   

typedef struct {
	ProtocolVersion client_version;
	Random random;
	uint8 session_id;
	uint16 cipher_suites_length;
	CipherSuite* cipher_suites;
	uint8 compression_methods_length;
	CompressionMethod* compression_methods;
	uint16 extensions_length;
} ClientHello;


// Compression Methods

#define CM_NO_COMPRESSION 0


/* Handshake Protocol */
typedef uint8_t HandshakeType;
   
// HandshakeType

#define HT_HELLO_REQUEST 0
#define HT_CLIENT_HELLO 1
#define HT_SERVER_HELLO 2
#define HT_CERTIFICATE 11
#define HT_SERVER_KEY_EXCHANGE  12
#define HT_CERTIFICATE_REQUEST 13
#define HT_SERVER_HELLO_DONE 14
#define HT_CERTIFICATE_VERIFY 15
#define HT_CLIENT_KEY_EXCHANGE 16
#define HT_FINISHED 20

typedef struct {
	HandshakeType msg_type;
	uint24 length;
} HandshakeClientHello;
   
   
/* Record Layer */

// ContentType

#define CT_CHANGE_CIPHER_SPEC 20
#define CT_ALERT 21
#define CT_HANDSHAKE 22
#define CT_APPLICATION_DATA 23

typedef struct {
	uint8 type;
	ProtocolVersion version;
	uint16 length;
} TLSPlaintext;
   
typedef struct {
	uint8 type;
	ProtocolVersion version;
	uint16 length;
	Alert body;
} TLSPlaintextAL;
   
   
/* The Cipher Suite */

typedef struct {
	char name[100];
	CipherSuite id;
} CSuiteDesc;

typedef struct {
	CSuiteDesc* CSArray;
	int nol;
} CSuiteList;


/* Cipher Suite Evaluation */

typedef struct {
	CipherSuite *modern;
	CipherSuite *intermediate;
	CipherSuite *old;
	CipherSuite *all;
	int modern_size;
	int intermediate_size;
	int old_size;
	int all_size;
} CSuiteEvals;

   
   




