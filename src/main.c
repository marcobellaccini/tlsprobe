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
#include <inttypes.h>
#include <errno.h>
#include <argp.h>
#include <config.h>

#include "arg.h"
#include "tls.h"

#define PING_ATT_MAX 4 // number of ping attempts when using ping to set timeout
#define TIMEOUT_DEFAULT 500 // default timeout [ms]
#define SERVER_BUFLEN 2048 // incoming data buffer length - used in server mode

/* color codes for Cipher Suite security Evaluation */
#define KGRN  "\x1B[32m"
#define KCYN  "\x1B[36m"
#define KYEL  "\x1B[33m"
#define KRED  "\x1B[31m"
#define KWHT  "\x1B[37m"
#define KRESET "\033[0m"


uint24 hton24(uint32); // convert uint24 to big endian

void fill_random (uint8*, size_t); // fills memory area with pseudo-random data

CSuiteList loadCSList(char*); // load Cipher Suite list from the file passed as argument, return a Cipher Suite list struct in case of success, else return a CSuiteList with a NULL pointer as CSArray 

int searchCSbyName(char*,CSuiteDesc*,int); // search for a cipher suite in the list by name, returning its position in the CSuitesL, return -1 if fails

int searchCSbyID(CipherSuite,CSuiteDesc*, int); // search for a cipher suite in the list by id, returning its position in the CSuitesL, return -1 if fails

int createConnection(struct sockaddr_in, struct timeval, struct timeval); // create active tcp connection with send and receive timeouts, return socket (or -1 if fails)

int passiveOpenConnection(int); // create passive tcp connection with listening port passed as argument, return socket (or -1 if fails)

int checkSuiteSupport(struct arguments, struct sockaddr_in, 	// check for support of a certain TLS Cipher Suite:
	struct timeval, struct timeval,						 	// last argument (selectedCS) is the position of the suite in CSuitesL array
	CSuiteDesc*, int);									 		// accepts send and receive timeouts as arguments
																// returns 0 if suite supported, 1 if unsupported (handshake failure received),
																// 2 if unsupported (timeout reached), 3 if unsupported (server sent FIN),
																// -2 if could not understand server reply,
																// -1 if other errors occurred
																
long int ping(struct sockaddr_in);	// launch ping command, parse output and return RTT in ms, return -1 if fails

struct sockaddr_in getSockAddr(char *,int); // get socket address struct from host and port

void printMem(void*, size_t); // print hex data passed as pointer for all the specified size

CSuiteEvals loadCSEvals(char*); // load Cipher Suite Evaluations from the file passed as argument, return a valid CSuiteEvals struct in case of success

int scanSuiteSecList (CipherSuite, CipherSuite *, int); // search for selected Cipher Suite in memory area pointed by the passed pointer, return 0 if found, else 1

int checkSuiteSecurity (CipherSuite, CSuiteEvals); // return security level of the suite (0=max, 3=min, 4=unknown) - from Mozilla definitions (see https://wiki.mozilla.org/Security/Server_Side_TLS )

void printSecColor (int); // print text in the right color associated with security level: green=high, cyan=good, yellow=poor, red=critical


int main(int argc, char * argv[]) {

struct arguments arguments; // argp options struct
struct sockaddr_in sin;
char *host;
int port;
int timeout_internal; // timeout
int selectedCS = -1; // initialize selected Cipher Suite with invalid value


/* Default values for options */
arguments.truetime=0;
arguments.port=443;
arguments.printMessage=0;
arguments.CS_file="/usr/local/share/tlsprobe/tls-parameters-4.csv";
arguments.CS_eval_file="/usr/local/share/tlsprobe/cs_eval.dat";
arguments.cipherSuite="TLS_RSA_WITH_AES_128_CBC_SHA";
arguments.fullScanMode=0;
arguments.cipherSuiteMode=0;
arguments.serverMode=0;
arguments.timeout=TIMEOUT_DEFAULT;
arguments.autotimeout=0;
arguments.tlsVer="1.2";

/* Parse our arguments; every option seen by parse_opt will be reflected in arguments. */
argp_parse (&argp, argc, argv, 0, 0, &arguments);

port=arguments.port;

if (arguments.fullScanMode || arguments.cipherSuiteMode) { // if either full scan mode or cipher suite probe mode was selected, target was passed as argument
	host=arguments.args[0];
}


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



/* load Cipher Suites List */

CSuiteList CSList=loadCSList(arguments.CS_file);

if (NULL==CSList.CSArray) {
	printf("Error loading Cipher Suites List, aborting...\n");
	exit(1);
}

/* load Cipher Suites Evaluations */

CSuiteEvals CSEvalSt = loadCSEvals(arguments.CS_eval_file);
//printf("%d %d %d\n", CSEvalSt.modern_size,CSEvalSt.intermediate_size,CSEvalSt.old_size);
//printMem(CSEvalSt.modern, 2*CSEvalSt.modern_size);
//exit(1);


struct timeval timeoutS, timeoutR; // socket timeouts

/* if either full scan mode or cipher suite probe mode was selected  */

if (arguments.fullScanMode || arguments.cipherSuiteMode) {
	
	
	/* initialize random seed - this is for random parts of TLS payload*/
	srand ((unsigned int) time (NULL)); // 

	/* get socket address struct */
	sin=getSockAddr(host, port);


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



	/* socket timeouts for client mode operation */
	     
	timeoutS.tv_sec = 2;
	timeoutS.tv_usec = 0;

	if (arguments.timeout<1000) {
		timeoutR.tv_sec = 0;
		timeoutR.tv_usec = timeout_internal*1000;
	} else {
		timeoutR.tv_sec = timeout_internal/1000;
		timeoutR.tv_usec = (timeout_internal-(1000*timeoutR.tv_sec))*1000;
	}

}



/* single cipher suite test mode */
if (arguments.cipherSuiteMode && !arguments.fullScanMode && !arguments.serverMode) {
	/* search for the selected cipher suite */

	selectedCS = searchCSbyName(arguments.cipherSuite,CSList.CSArray,CSList.nol);
	
	
	if (-1==selectedCS) {
		printf("Cipher suite %s was not found in the IANA List.\n",arguments.cipherSuite);
		exit(1);
	}
	
	switch ( checkSuiteSupport(arguments, sin, timeoutS, timeoutR, CSList.CSArray, selectedCS) ) {
		case 0:
			printSecColor(checkSuiteSecurity (CSList.CSArray[selectedCS].id, CSEvalSt));
			printf("Cipher Suite SUPPORTED\n");
			printf(KRESET);
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

	printf("Legend: " KGRN "SAFER " KCYN "SAFE " KYEL "WEAK " KRED "WEAKER " KWHT "UNKNOWN\n" KRESET);

}

/* full scan mode (test for support of all known cipher suites) */

else if (!arguments.cipherSuiteMode && arguments.fullScanMode && !arguments.serverMode) {
	int noss=0; // number of supported cipher suites
	printf("Scanning the server for supported cipher suites...\nCipher suites SUPPORTED by the server are:\n");
	for (selectedCS=0; selectedCS < CSList.nol; selectedCS++) {
		switch ( checkSuiteSupport(arguments, sin, timeoutS, timeoutR, CSList.CSArray, selectedCS) ) {
			case 0:
				printf("\r");
				printSecColor(checkSuiteSecurity (CSList.CSArray[selectedCS].id, CSEvalSt));
				printf(CSList.CSArray[selectedCS].name);
				printf(KRESET "\n");
				noss++;
				break;
			case 1:
			case 2:
			case 3:
				//printf("\r\t\t\t\t\t\t\t");
				printf("\rTesting suite %d/%d...",selectedCS+1,CSList.nol+1);
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
	} else {
		printf("Legend: " KGRN "SAFER " KCYN "SAFE " KYEL "WEAK " KRED "WEAKER " KWHT "UNKNOWN\n" KRESET);
	}
	
}

/* server mode */

else if (!arguments.cipherSuiteMode && !arguments.fullScanMode && arguments.serverMode) {
	
	int s = passiveOpenConnection(port); // setup passive open and get socket
	
	if (s < 0) {
		printf("Error while setting up passive open, aborting...\n");
		exit(1);
	}		

	
	int new_s; // new socket
	int len; // length of incoming data
	uint8 buf[SERVER_BUFLEN]; // buffer for incoming data
	
	printf("Listening for TLS connections on TCP port %d...\n", port);
	
	
	/* wait for incoming connection */
	//while (1) {
		if ((new_s = accept(s, (struct sockaddr *)&sin, &len)) < 0) {
			perror("tlsprobe: accept");
			printf("An error occurred while processing incoming connection, aborting...\n");
			exit(1);
		}
		
				
		len = recv(new_s, buf, sizeof(buf), 0);
		
		if (arguments.printMessage) { // print received data (i.e.: = received ClientHello if it's all right)
			printMem(buf,len);
		}
		
		/* parse received data */
		if (len>=46) { // if a minimum of 46 bytes (=minimum length of ClientHello from the start to Cipher Suites Length included) were received
			TLSPlaintext tlsPT;
			tlsPT.type=(uint8)(*(buf));
			tlsPT.version.major=(uint8)(*(buf+1));
			tlsPT.version.minor=(uint8)(*(buf+2));
			tlsPT.length=ntohs((uint16)(*(buf+3)));
			
			/* check if handshake message was received */
			if (CT_HANDSHAKE!=tlsPT.type)
				goto bad_creq;
			
			/* ...if so, continue parsing it... */
			
			tlsPT.body.msg_type=(uint8)(*(buf+5));
			
			// skip length -- tlsPT.body.length=(uint24)(*(buf+6));
			
			/* check if ClientHello message was received */
			if (HT_CLIENT_HELLO!=tlsPT.body.msg_type)
				goto bad_creq;
				
			/* ...if so, continue parsing it... */
			
			tlsPT.body.body.client_version.major=(uint8)(*(buf+9));
			tlsPT.body.body.client_version.minor=(uint8)(*(buf+10));
			
			tlsPT.body.body.random.gmt_unix_time=ntohl((uint32)(*(buf+11)));
			
			// skip random bytes (28 bytes) - 11+4+28=43
			
			tlsPT.body.body.session_id.length=(uint8)(*(buf+43));
			//printf("sid_len:%d\n",tlsPT.body.body.session_id.length);
			
			// skip session id itself 43+1+tlsPT.body.body.session_id.length
			
			tlsPT.body.body.cipher_suites.length=((uint16)(*(buf+43+2+tlsPT.body.body.session_id.length)));
			

			/* print offered cipher suite list */
			int ocs_idx;
			CipherSuite cs;
			int cs_pos;
			
			printf("ClientHello was received, Cipher Suites offered by the client are (in order of preference):\n");
			//printf("%d\n",tlsPT.body.body.cipher_suites.length);
			
			for (ocs_idx=0;ocs_idx<tlsPT.body.body.cipher_suites.length/2;ocs_idx++) { // 2 bytes per cipher suite
				cs[0] = (uint8)(*(buf+43+1+tlsPT.body.body.session_id.length+2+2*ocs_idx));
				cs[1] = (uint8)(*(buf+43+1+tlsPT.body.body.session_id.length+3+2*ocs_idx));
				
				//printf("%d %d\n",cs[0],cs[1]);
				cs_pos=searchCSbyID(cs,CSList.CSArray,CSList.nol); // search for the offered cipher suite in the IANA list
				
				if (cs_pos!=-1) { // if CS was found in the IANA list
					printSecColor(checkSuiteSecurity (CSList.CSArray[cs_pos].id, CSEvalSt));
					printf("%s\n",CSList.CSArray[cs_pos].name);
					printf(KRESET);
				}
			}
			
			printf("Finished, %d Cipher Suites were offered by the client.\n", tlsPT.body.body.cipher_suites.length/2);
			printf("Legend: " KGRN "SAFER " KCYN "SAFE " KYEL "WEAK " KRED "WEAKER " KWHT "UNKNOWN\n" KRESET);
			
			
		} 
		else {
		bad_creq:	printf("Could not understand client request, aborting...\n");
					exit(1);
		}
		
		
		close(new_s);
		close(s);
	//}
	
}

/* no operation mode or more than one operation mode were selected */
else {
	printf("Sorry, no operation MODE or more than one operation MODE were selected.\n");
	printf("You can specify an operation mode with -F, -c or -S options.\n");
	printf("Try with tlsprobe --help for more information.\n");
	exit(1);
}



free(CSList.CSArray); // free memory - SHOULD DO SOMETHING IN CASE PROGRAM DOES NOT REACH THIS POINT
free(CSEvalSt.modern);
free(CSEvalSt.intermediate);
free(CSEvalSt.old);

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

int searchCSbyName(char* name,CSuiteDesc* CSL, int CSL_size) {
	int i;
	for(i=0;i<CSL_size;i++) {
		if (0==strcmp(name,CSL[i].name)){
			return i; // Cipher Suite found at element i
		}
	}
	return -1; // return -1 if fails
}

int searchCSbyID(CipherSuite id,CSuiteDesc* CSL, int CSL_size) {
	int i;
	for(i=0;i<CSL_size;i++) {
		if (id[0]==CSL[i].id[0] && id[1]==CSL[i].id[1]){
			return i; // Cipher Suite found at element i
		}
	}
	return -1; // return -1 if fails
}

int createConnection(struct sockaddr_in sin, struct timeval timeoutS, struct timeval timeoutR) {

	int s; // socket
	
	/* active open */

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("tlsprobe: socket");
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

int passiveOpenConnection(int port) {
	
	int s; // socket
	struct sockaddr_in sin;
	
	memset((char *)&sin, '\0', sizeof(sin));
	
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);
	
	/* passive open */

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("tlsprobe: socket");
		return -1;
	}

	/* bind even if port is in TIME_WAIT state */
	int  optValS = 1;

	if ( setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optValS, sizeof(optValS)) < 0 ) {
		perror("setsockopt failed\n");
		exit(1);
	}

	/* bind */
	if ((bind(s, (struct sockaddr *)&sin,sizeof(sin))) < 0) {
		perror("tlsprobe: bind");
		if (EACCES==errno) {
			printf("Error trying to listen on privileged (<1024) port.\n"
			"Please either specify an unprivileged (>=1024) port with -p option, install tlprobe setuid root, or setcap-mode install.\n"
			"See tlsprobe INSTALL file for details.\n");
		}
		return -1;
	}
	
	listen(s, 1); // set max num of pending connections to 1 (i.e.: refuse the 2nd connection while serving the 1st)
	
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
		printMem(&tlsPTCH, sizeof(tlsPTCH));
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

CSuiteList loadCSList(char* filePath) {
	
	FILE *CS_file; // IANA Cipher Suites List
	CSuiteList CSList;
	CSList.CSArray=NULL;
	CSList.nol=0;
	
	/* open IANA Cipher Suites List */
	CS_file = fopen(filePath,"r");

	if (NULL == CS_file) {
		printf("Error while opening IANA Cipher Suites List file:\nmake sure tls-parameters-4.csv is in the default directory (/usr/local/share/tlsprobe/) or specify its path through the -f option\n");
		printf("If you miss it, you can get an up-to-date CSV file from: http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml\n");
		return CSList; // which was initialized as invalid
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
	
	/* success, return valid data */
	
	CSList.CSArray=CSuitesL;
	CSList.nol=nol;
	
	return CSList;
	
}

void printMem(void* mem, size_t size) {
	unsigned int indexi;
	for (indexi = 0; indexi < size; indexi++)
		printf("%02x", *(((uint8*)mem)+indexi));
	
	printf("\n");
}

struct sockaddr_in getSockAddr(char *host, int port) {

	struct sockaddr_in sin;
	struct hostent *hp;
	
	/* translate host name into peer’s IP address */
	
	hp = gethostbyname(host);
	if (!hp) {
		fprintf(stderr, "unknown host: %s\n", host);
		exit(1);
	}

	/* build address data structure */

	memset((char *)&sin, '\0', sizeof(sin));
	sin.sin_family = AF_INET;
	memcpy((char *)&sin.sin_addr, hp->h_addr, hp->h_length);
	sin.sin_port = htons(port);

	return sin;
	
}

CSuiteEvals loadCSEvals(char* filePath) {

	FILE *CSE_file; // Cipher Suites Evals file
	CSuiteEvals CSEList;

	// initialize
	CSEList.modern=NULL;
	CSEList.intermediate=NULL;
	CSEList.old=NULL;
	CSEList.all=NULL;
	CSEList.modern_size=0;
	CSEList.intermediate_size=0;
	CSEList.old_size=0;
	CSEList.all_size=0;
	
	/* open Cipher Suites Evaluation file */
	CSE_file = fopen(filePath,"r");

	if (NULL == CSE_file) {
		printf("Error while opening Cipher Suites Evaluation file:\nmake sure cs_eval.dat is in the default directory (/usr/local/share/tlsprobe/) or specify its path through the -e option\n");
		exit(1);
	}

	/* parse Cipher Suites Evaluation file */
	char line[300];
	uint8 a,b;

	/* search for <modern> tag */
	

	while(!feof(CSE_file))
	{
		
		fgets(line, sizeof(line), CSE_file);

		if (NULL != strstr(line,"<modern>")) {
			while (NULL == strstr(line,"</modern>") && !feof(CSE_file)) {

				if (2==sscanf(line,"0x%02x,0x%02x%*s", &a, &b)) {
					CSEList.modern_size++;
					CSEList.modern=realloc(CSEList.modern,CSEList.modern_size*sizeof(CipherSuite));
					(*(CSEList.modern+CSEList.modern_size-1))[0]=a;
					(*(CSEList.modern+CSEList.modern_size-1))[1]=b;
				}

				fgets(line, sizeof(line), CSE_file);
			}
			
		}
		else if (NULL != strstr(line,"<intermediate>")) {
			while (NULL == strstr(line,"</intermediate>") && !feof(CSE_file)) {

				if (2==sscanf(line,"0x%02x,0x%02x%*s", &a, &b)) {
					CSEList.intermediate_size++;
					CSEList.intermediate=realloc(CSEList.intermediate,CSEList.intermediate_size*sizeof(CipherSuite));
					(*(CSEList.intermediate+CSEList.intermediate_size-1))[0]=a;
					(*(CSEList.intermediate+CSEList.intermediate_size-1))[1]=b;
				}

				fgets(line, sizeof(line), CSE_file);
			}
			
		}
		else if (NULL != strstr(line,"<old>")) {
			while (NULL == strstr(line,"</old>") && !feof(CSE_file)) {

				if (2==sscanf(line,"0x%02x,0x%02x%*s", &a, &b)) {
					CSEList.old_size++;
					CSEList.old=realloc(CSEList.old,CSEList.old_size*sizeof(CipherSuite));
					(*(CSEList.old+CSEList.old_size-1))[0]=a;
					(*(CSEList.old+CSEList.old_size-1))[1]=b;
				}

				fgets(line, sizeof(line), CSE_file);
			}
			
		}
		else if (NULL != strstr(line,"<all>")) {
			while (NULL == strstr(line,"</all>") && !feof(CSE_file)) {

				if (2==sscanf(line,"0x%02x,0x%02x%*s", &a, &b)) {
					CSEList.all_size++;
					CSEList.all=realloc(CSEList.all,CSEList.all_size*sizeof(CipherSuite));
					(*(CSEList.all+CSEList.all_size-1))[0]=a;
					(*(CSEList.all+CSEList.all_size-1))[1]=b;
				}

				fgets(line, sizeof(line), CSE_file);
			}
			
		}

	}

	/* close file */

	fclose(CSE_file);

	/* if file was parsed correctly, returns struct */
	if ( CSEList.modern_size>0 && CSEList.intermediate_size>0 && CSEList.old_size>0 && CSEList.all_size>0 ) {

		return CSEList;
		
	} else {
		
		exit(1);
		
	}

}

int scanSuiteSecList (CipherSuite CS, CipherSuite *CSL, int size) {

	unsigned int i;

	for (i=0; i<size;i++) {
		//printf("%d %d, %d %d\n",CS[0],*(CSL+i)[0],CS[1],(*(CSL+i))[1]);
		if (CS[0]==*(CSL+i)[0] && CS[1]==(*(CSL+i))[1])
			return 0;
	}

	return 1;
}

int checkSuiteSecurity (CipherSuite CS,CSuiteEvals CSEList) {

	/* check whether suite is modern, intermediate or old */
	if (0==scanSuiteSecList(CS, CSEList.modern, CSEList.modern_size)) {
		return 0;
	}
	else if (0==scanSuiteSecList(CS, CSEList.intermediate, CSEList.intermediate_size)) {
		return 1;
	}
	else if (0==scanSuiteSecList(CS, CSEList.old, CSEList.old_size)) {
		return 2;
	}
	else if (0==scanSuiteSecList(CS, CSEList.all, CSEList.all_size)) {
		return 3; // weak suite
	}
	else {
		return 4; // unknown suite
	}

}

void printSecColor(int secLevel) {
	switch ( secLevel ) {
		case 0:
			printf(KGRN);
			break;
		case 1:
			printf(KCYN);
			break;
		case 2:
			printf(KYEL);
			break;
		case 3:
			printf(KRED);
			break;
		case 4:
			printf(KWHT);
			break;
		default:
			printf("Error: unknown security level.\n");
			exit(1);

	}
}
