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
	uint8 length;
} SessionID;

typedef uint8 CipherSuite[2];
   
typedef struct {
	uint16 length;
	CipherSuite suite1;
} CipherSuitesList;
   

typedef struct {
	ProtocolVersion client_version;
	Random random;
	SessionID session_id;
	CipherSuitesList cipher_suites;
	uint16 compression_methods;
	//uint16 extensions_length; // not supported in TLS versions < 1.2
} ClientHello;
   
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
	ClientHello body;
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
	HandshakeClientHello body;
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
	int modern_size;
	int intermediate_size;
	int old_size;
} CSuiteEvals;

   
   




