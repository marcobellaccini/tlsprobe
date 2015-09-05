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
   
   
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <argp.h>
#include <config.h>

#include "arg.h"
#include "tls.h"

#define PING_ATT_MAX 4 // number of ping attempts when using ping to set timeout
#define TIMEOUT_DEFAULT 500 // default timeout [ms]


uint24 hton24(uint32); // convert uint24 to big endian

void fill_random (uint8*, size_t); // fills memory area with pseudo-random data

int searchCS(char*,CSuiteDesc*,int); // search for a cipher suite in the list, returning its position in the CSuitesL

int createConnection(struct sockaddr_in, struct timeval, struct timeval); // create tcp connection with send and receive timeouts, returns socket

int checkSuiteSupport(struct arguments, struct sockaddr_in, 	// check for support of a certain TLS Cipher Suite:
	struct timeval, struct timeval,						 	// last argument (selectedCS) is the position of the suite in CSuitesL array
	CSuiteDesc*, int);									 		// accepts send and receive timeouts as arguments
																// returns 0 if suite supported, 1 if unsupported (handshake failure received),
																// 2 if unsupported (timeout reached), 3 if unsupported (server sent FIN),
																// -2 if could not understand server reply,
																// -1 if other errors occurred
																
long int ping(struct sockaddr_in);	// launch ping command, parse output and return RTT in ms, return -1 if fails



int main(int argc, char * argv[]) {

struct arguments arguments; // argp options struct
struct hostent *hp;
struct sockaddr_in sin;
char *host;
int port;
int timeout_internal; // timeout
FILE *CS_file; // IANA Cipher Suites List

/* Default values for options */
arguments.truetime=0;
arguments.port=443;
arguments.printMessage=0;
arguments.CS_file="/usr/local/share/rockytlstester/tls-parameters-4.csv";
arguments.cipherSuite="TLS_RSA_WITH_AES_128_CBC_SHA";
arguments.fullScanMode=0;
arguments.cipherSuiteMode=0;
arguments.timeout=TIMEOUT_DEFAULT;
arguments.autotimeout=0;
arguments.tlsVer="1.2";

/* Parse our arguments; every option seen by parse_opt will be reflected in arguments. */
argp_parse (&argp, argc, argv, 0, 0, &arguments);

port=arguments.port;
host=arguments.args[0];

/* Set tls version */
if ( 0==strcmp(arguments.tlsVer, "1.0") ) {
	version=version10;
} else if ( 0==strcmp(arguments.tlsVer, "1.1") ) {
	version=version11;
} else if ( 0==strcmp(arguments.tlsVer, "1.2") ) {
	version=version12;
} else {
	printf("An unknown TLS version was specified, aborting...\n");
	exit(1);
}


/* Check for options compatibility */
if (arguments.fullScanMode && arguments.cipherSuiteMode) { // if user triggered both -F and -c options (something that doesn't make sense)
	printf("Sorry, -c option is incompatible with -F\n");
	printf("Try `rockyTlsTester --help' or `rockyTlsTester --usage' for more information.\n");
	exit(1);
}
if (!arguments.fullScanMode && !arguments.cipherSuiteMode) { // assure that one operation mode (-c or -F) was specified
	printf("No operation mode was selected, aborting...\n");
	printf("Please specify an operation mode (with -F or -c for example).\n");
	printf("Try `rockyTlsTester --help' or `rockyTlsTester --usage' for more information.\n");
	exit(1);
}



/* open IANA Cipher Suites List */
CS_file = fopen(arguments.CS_file,"r");

if (NULL == CS_file) {
	printf("Error while opening IANA Cipher Suites List file:\nput tls-parameters-4.csv is in this directory or specify its path through the -f option\n");
	printf("If you miss it, you can get an up-to-date CSV file from: http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml\n");
	exit(1);
}

/* parse IANA Cipher Suites List */

int nol=0; // number of valid lines in the file

int temp1,temp2; // temporary stuff..
char temp3[150]; // temporary stuff..

while(!feof(CS_file)) // count lines
{
	if (3==fscanf(CS_file,"\"0x%02x,0x%02x\",%[^,],%*s",&temp1,&temp2,&temp3)) // if a valid suite was parsed
		nol++;
	else {
		fgets(temp3, 150, CS_file); // skip line
	}
}


rewind(CS_file); // back to the beginning of the file

CSuiteDesc *CSuitesL=malloc(nol*sizeof(CSuiteDesc)); // allocate memory for cipher suites list


int idx_f=0;
while (!feof(CS_file)) {
	if (3==fscanf(CS_file,"\"0x%02x,0x%02x\",%[^,],%*s", (unsigned int *)&CSuitesL[idx_f].id[0], (unsigned int *)&CSuitesL[idx_f].id[1], &CSuitesL[idx_f].name)) // if a valid suite was parsed
		idx_f++;
	else
		fgets(temp3, 150, CS_file); // skip line
}

/* file parsed, close file */

fclose(CS_file);

/* search for the selected cipher suite */

int selectedCS = searchCS(arguments.cipherSuite,CSuitesL,nol);
if (-1==selectedCS) {
	printf("Cipher suite %s was not found in the IANA List.\n",arguments.cipherSuite);
	exit(1);
}


/* translate host name into peer’s IP address */

hp = gethostbyname(host);
if (!hp) {
    fprintf(stderr, "unknown host: %s\n", host);
    exit(1);
}

srand ((unsigned int) time (NULL)); // initialize random seed



/* build address data structure */

memset((char *)&sin, '\0', sizeof(sin));
sin.sin_family = AF_INET;
memcpy((char *)&sin.sin_addr, hp->h_addr, hp->h_length);
sin.sin_port = htons(port);

/* if user requested to set timeout via RTT estimation */
if (arguments.autotimeout) {
	long int myrtt=-1;
	unsigned int ping_att;
	printf("Estimating RTT in order to set timeout...\n");
	for (ping_att=1; ping_att<PING_ATT_MAX && myrtt<0; ping_att++){
		myrtt=ping(sin);
		if (myrtt<0){
			printf("Server did not reply to ping #%d (or some error occurred), trying again...\n", ping_att);
			usleep(200000); // sleep 0.2s and retry - seems like if retry immediately always fails...
		}
	}

	if (ping_att==PING_ATT_MAX) {
		printf("Server did not reply to any ping (or some error occurred), setting timeout to default value (%d ms).\n", TIMEOUT_DEFAULT);
		timeout_internal=TIMEOUT_DEFAULT;
	} else {
		timeout_internal=myrtt+200; // setting timeout to rtt + 200ms
		printf("Ping attempt #%d was successful, RTT was about %ld ms, setting timeout to %d ms.\n", ping_att-1, myrtt, timeout_internal);
	}
	
} else {
	timeout_internal=arguments.timeout;
}



/* socket timeouts */
struct timeval timeoutS, timeoutR;      
timeoutS.tv_sec = 2;
timeoutS.tv_usec = 0;

if (arguments.timeout<1000) {
	timeoutR.tv_sec = 0;
	timeoutR.tv_usec = timeout_internal*1000;
} else {
	timeoutR.tv_sec = timeout_internal/1000;
	timeoutR.tv_usec = (timeout_internal-(1000*timeoutR.tv_sec))*1000;
}


/* single cipher suite test mode */
if (!arguments.fullScanMode) {
	switch ( checkSuiteSupport(arguments, sin, timeoutS, timeoutR, CSuitesL, selectedCS) ) {
		case 0:
			printf("Cipher Suite SUPPORTED\n");
			break;
		case 1:
			printf("Cipher Suite NOT SUPPORTED (handshake failure received)\n");
			break;
		case 2:
			printf("Cipher Suite NOT SUPPORTED (timeout)\n");
			break;
		case 3:
			printf("Cipher Suite NOT SUPPORTED (server closed TCP connection)\n");
			break;
		case -2:
			printf("Could not understand server reply, aborting...\n");
		case -1:
		default:
			printf("An error occurred while checking for cipher suite support\n");
			exit(1);

	}

}

/* full scan mode (test for support of all known cipher suites) */

else {
	int noss=0; // number of supported cipher suites
	printf("Scanning the server for supported cipher suites...\nCipher suites SUPPORTED by the server are:\n");
	for (selectedCS=0; selectedCS < nol; selectedCS++) {
		switch ( checkSuiteSupport(arguments, sin, timeoutS, timeoutR, CSuitesL, selectedCS) ) {
			case 0:
				printf("\r");
				printf(CSuitesL[selectedCS].name);
				printf("\n");
				noss++;
				break;
			case 1:
			case 2:
			case 3:
				//printf("\r\t\t\t\t\t\t\t");
				printf("\rTesting suite %d/%d...",selectedCS+1,nol+1);
				break;
			case -2:
				printf("Could not understand server reply, aborting...\n");
			case -1:
			default:
				printf("An error occurred while checking for cipher suite support\n");
				exit(1);

		}
	}
	
	printf("\rFinished, %d supported cipher suites were found.\n", noss);
	if (0==noss) {
		printf("Maybe you have to set a bigger timeout?\n");
	}
	
}



free(CSuitesL); // free memory - SHOULD DO SOMETHING IN CASE PROGRAM DOES NOT REACH THIS POINT
return 0; // return if successful

}


uint24 hton24(uint32 in) {
	uint24 out;
	out.lsb=(in)&0xff;
	out.nsb=(in>>8)&0xff;
	out.msb=(in>>16)&0xff;
	return out;
}

void fill_random (uint8* ptr, size_t num_bytes) 
{
  size_t i;

  for (i = 0; i < num_bytes; i++)
  {
    *(ptr+i) = rand() % 255;
  }
}

int searchCS(char* name,CSuiteDesc* CSL, int CSL_size) {
	int i;
	for(i=0;i<CSL_size;i++) {
		if (0==strcmp(name,CSL[i].name)){
			return i; // Cipher Suite found at element i
		}
	}
	return -1; // return -1 if fails
}

int createConnection(struct sockaddr_in sin, struct timeval timeoutS, struct timeval timeoutR) {

	int s; // socket
	
	/* active open */

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("rockyTlsTester: socket");
		return -1;
	}

	if (setsockopt (s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeoutR, sizeof(timeoutR)) < 0) { // receive timeout
		perror("setsockopt failed\n");
		return -1;
	}

	if (setsockopt (s, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeoutS, sizeof(timeoutS)) < 0) { // send timeout
        perror("setsockopt failed\n");
		return -1;
	}

	/* connect */
	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		printf("Unable to connect to the server.\n");
		close(s);
		return -1;
	}
	
	return s;

}

int checkSuiteSupport(struct arguments arguments, struct sockaddr_in sin, struct timeval timeoutS, struct timeval timeoutR, CSuiteDesc *CSuitesL, int selectedCS) {
	
	/* pre-build TLS Alert message (used to tear down the connection after Server Hello(s) ) */

	Alert alertMsg;
	alertMsg.level=AL_FATAL;
	alertMsg.description=AD_INTERNAL_ERROR;
	// using an internal error message seems fine since is vague:
	/* From TLS 1.2 RFC:
	internal_error
	An internal error unrelated to the peer or the correctness of the
	protocol (such as a memory allocation failure) makes it impossible
	to continue.  This message is always fatal. */

	TLSPlaintextAL tlsPTAL;
	tlsPTAL.type=CT_ALERT; // handshake message
	tlsPTAL.version=version; // TLS 1.2
	tlsPTAL.length=htons(sizeof(alertMsg));
	tlsPTAL.body=alertMsg;
	
	
	/* build a ClientHello message */

	ClientHello myClientHello;
	myClientHello.client_version=version; //using TLS 1.2 by default

	time_t tv;
	tv=time(NULL);

	if (arguments.truetime) { // if user requested true timestamp to be used in TLS messages
		myClientHello.random.gmt_unix_time=htonl((uint32) tv); // timestamp converted to big endian
	} else {
		fill_random((uint8*)&(myClientHello.random.gmt_unix_time), 32); // else use random data (to avoid clock drift fingerprinting - https://bugzilla.mozilla.org/show_bug.cgi?id=967923 )
	}

	fill_random(myClientHello.random.random_bytes, 28); // fill the random nonce

	myClientHello.session_id.length=0x0; // no session id
	myClientHello.cipher_suites.length=0x0200; // 1 cipher suite (little endian)
	//myClientHello.cipher_suites.suite1[0]=TLS_DHE_RSA_WITH_AES_128_CBC_SHA[0];
	//myClientHello.cipher_suites.suite1[1]=TLS_DHE_RSA_WITH_AES_128_CBC_SHA[1];
	//myClientHello.cipher_suites.suite1[0]=0xc0;
	//myClientHello.cipher_suites.suite1[1]=0x2f;
	myClientHello.cipher_suites.suite1[0]=CSuitesL[selectedCS].id[0];
	myClientHello.cipher_suites.suite1[1]=CSuitesL[selectedCS].id[1];
	//printf("Trying with suite %s\n",CSuitesL[selectedCS].name);
	myClientHello.compression_methods=0x0001; // 1 compression method: no compression (little endian)
	//myClientHello.extensions_length=0x00; // not using TLS extensions

	HandshakeClientHello myHandShakeCH;
	myHandShakeCH.msg_type=HT_CLIENT_HELLO; //client_hello
	//printf("Size:%d\n",(int32_t)sizeof(myClientHello));
	myHandShakeCH.length=hton24((uint32)sizeof(myClientHello));
	myHandShakeCH.body=myClientHello;

	TLSPlaintext tlsPTCH;
	tlsPTCH.type=CT_HANDSHAKE; // handshake message
	tlsPTCH.version=version; // TLS 1.2
	tlsPTCH.length=htons(sizeof(myHandShakeCH));
	tlsPTCH.body=myHandShakeCH;
	
	if (arguments.printMessage) { // let's print ClientHello before sending it
		unsigned int indexi;
		for (indexi = 0; indexi < sizeof(tlsPTCH); indexi++)
			printf("%02x", *(((uint8*)&tlsPTCH)+indexi));
	
		printf("\n");
	}


	/* create tcp connection */
	int s; // socket
	if ((s=createConnection(sin, timeoutS, timeoutR)) < 0) {
		return -1;
	}
	
	uint8 rbuf[7]; // buffer for incoming data
	int timeOutReached=0; // timeout flag initialization

	send(s, &tlsPTCH, sizeof(tlsPTCH), 0); // send ClientHello



	// get the initial part of the reply
	ssize_t received=recv(s, rbuf, sizeof(rbuf), 0);
	if (received<0) {
		timeOutReached=1; // server did not reply: for IIS Servers this means that the selected cipher suite is not supported by the server
						  // i.e.: IIS does not send any Handshake Failure message
	}

	if(rbuf[0]==CT_HANDSHAKE && rbuf[5]==HT_SERVER_HELLO && !timeOutReached && received > 0) { // if server hello received

		//printf("Cipher Suite SUPPORTED\n");
	
		send(s, &tlsPTAL, sizeof(tlsPTAL), 0); // send TLS Alert to cancel the handshake
		shutdown(s,SHUT_WR); // shutdown connection
		
		
		return 0; // cipher suite supported
	
	} else if ((rbuf[0]==CT_ALERT && rbuf[6]==AD_HANDSHAKE_FAILURE && !timeOutReached && received > 0)) { // if handshake failure received (and so the selected cipher suite is not supported by the server)
	
		//printf("Cipher Suite NOT SUPPORTED: handshake failure received\n");
	
		shutdown(s,SHUT_WR); // shutdown connection
		
		return 1; // cipher suite not supported: handshake failure
	
	} else if (timeOutReached) { // if timeout was reached - for IIS Servers this means that the selected cipher suite is not supported by the server
	
		//printf("Cipher Suite NOT SUPPORTED: timeout\n");
	
		send(s, &tlsPTAL, sizeof(tlsPTAL), 0); // send TLS Alert to cancel the handshake
		shutdown(s,SHUT_WR); // shutdown connection
		
		
		return 2; // cipher suite not supported: timeout
	
	} else if ( 0 == received ) { // if connection was closed by the server (i.e. server sent FIN) - this happens with LDAP over TLS if cipher suite was not supported
		
		shutdown(s,SHUT_WR); // shutdown connection
		
		
		return 3; // cipher suite not supported: server sent FIN
		
	} else {
	
		//printf("Could not understand server reply\n");
	
		send(s, &tlsPTAL, sizeof(tlsPTAL), 0); // send TLS Alert to cancel the handshake
		shutdown(s,SHUT_WR); // shutdown connection
	
		//exit(1);
		return -2; // error: could not understand server reply
	
	}

}

long int ping(struct sockaddr_in sin) {
	
	FILE *fp;
	long int rtt;
	char *endptr=NULL; // first invalid char for strtol
	
	char command[200], hostip[50],pingres[100];
	
	
	
	if (NULL == inet_ntop(AF_INET, &(sin.sin_addr), hostip, sizeof(hostip)))
		return -1;
	
	strcpy(command,"/bin/ping -q -c 1 -W 1 "); // options: quiet, 1 packet, 1s timeout
	strcat(command, hostip);
	strcat(command," | tail -1 | awk '{print $4}' | cut -d '/' -f 3");
	
	
	
	fp=popen(command,"r");
	
	if ( NULL == fp ) {
		pclose(fp);
		return -1;
	}
	
		
	if ( NULL == fgets(pingres, sizeof(pingres)-1, fp) ) { // put command output in a string
		pclose(fp);
		return -1;
	}
	
	
	rtt=strtol(pingres, &endptr,10);
	
	if (*endptr=='.' || *endptr=='\0') { // if conversion was successful (and so fp was a number) - i,e. pointer points to decimal separator or end of string
		pclose(fp);
		return (long int)rtt;
	} else {
		pclose(fp);
		return -1;
	}
	
	
}
