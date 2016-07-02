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
#include <pthread.h>

#include "arg.h"
#include "tls.h"

#define PING_ATT_MAX 4 // number of ping attempts when using ping to set timeout
#define TIMEOUT_DEFAULT 500 // default timeout [ms]
#define SERVER_BUFLEN 2048 // incoming data buffer length - used in server mode
#define CLIENT_BUFLEN 7 // incoming data buffer length - used in client mode
#define CSF_LINE_MAX 500 // max line length for cipher suite list files

/* color codes for Cipher Suite security Evaluation */
#define KCYN  "\x1B[36m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KRED  "\x1B[31m"
#define KWHT  "\x1B[37m"
#define KGRY  "\x1B[38m"
#define KRESET "\033[0m"


/* structure passed to checkSuiteSupportThr */
typedef struct {
	struct arguments arguments;
	struct sockaddr_in sin;
	struct timeval timeoutS;
	struct timeval timeoutR;
	CSuiteDesc *CSuitesL;
	int selectedCS;
	int result;
} threadParam;

uint24 hton24(uint24); // convert uint24 to big endian

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
																// 2 if unsupported (server closed connection or timeout reached), 3 if unsupported (server sent decode error),
																// -2 if could not understand server reply,
																// -1 if other errors occurred
																
void * checkSuiteSupportThr(void*); // thread version of checkSuiteSupport
																
long int ping(struct sockaddr_in);	// launch ping command, parse output and return RTT in ms, return -1 if fails

struct sockaddr_in getSockAddr(char *,int); // get socket address struct from host and port

void printMem(void*, size_t); // print hex data passed as pointer for all the specified size

CSuiteEvals loadCSEvals(char*); // load Cipher Suite Evaluations from the file passed as argument, return a valid CSuiteEvals struct in case of success

int scanSuiteSecList (CipherSuite, CipherSuite *, int); // search for selected Cipher Suite in memory area pointed by the passed pointer, return 0 if found, else 1

int checkSuiteSecurity (CipherSuite, CSuiteEvals); // return security level of the suite (0=max, 3=min, 4=unknown) - from Mozilla definitions (see https://wiki.mozilla.org/Security/Server_Side_TLS )

void printSecColor (int); // print text in the right color associated with security level: green=high, cyan=good, yellow=poor, red=critical

int isIpAddr(char*); // return 1 if passed string is an ip (ipv4) address, else return 0



int hostIsIp; // flag is set to 1 if passed argument was an ip address

char *host; // host name



int main (int argc, char * argv[]) {

struct arguments arguments; // argp options struct
struct sockaddr_in sin;
int port;
int timeout_internal; // timeout
int selectedCS = -1; // initialize selected Cipher Suite with invalid value
hostIsIp=1; // default


/* Default values for options */
arguments.truetime=0;
arguments.port=443;
arguments.printMessage=0;
arguments.CS_file="/usr/local/share/tlsprobe/tls-parameters-4.csv";
arguments.CS_file_SSL="/usr/local/share/tlsprobe/ssl-parameters.csv";
arguments.CS_eval_file="/usr/local/share/tlsprobe/cs_eval.dat";
arguments.cipherSuite="TLS_RSA_WITH_AES_128_CBC_SHA";
arguments.fullScanMode=0;
arguments.cipherSuiteMode=0;
arguments.serverMode=0;
arguments.timeout=TIMEOUT_DEFAULT;
arguments.autotimeout=0;
arguments.tlsVer="1.2";
arguments.skipSSL=0;
arguments.quiet=0;
arguments.maxThreads=16;
arguments.TLSExtensions=1;
arguments.TLSSNExtension=1;
arguments.TLSECExtension=1;
arguments.TLSECPFExtension=1;

/* Parse our arguments; every option seen by parse_opt will be reflected in arguments. */
argp_parse (&argp, argc, argv, 0, 0, &arguments);

port=arguments.port;

if (arguments.fullScanMode || arguments.cipherSuiteMode) { // if either full scan mode or cipher suite probe mode was selected, target was passed as argument
	host=arguments.args[0];
	hostIsIp=isIpAddr(host);
}


/* Set tls version */
if ( 0==strcmp(arguments.tlsVer, "1.0") ) {
	version=version10;
} else if ( 0==strcmp(arguments.tlsVer, "1.1") ) {
	version=version11;
} else if ( 0==strcmp(arguments.tlsVer, "1.2") ) {
	version=version12;
} else if ( 0==strcmp(arguments.tlsVer, "1.3") ) {
	version=version13;
} else {
	printf("An unknown TLS version was specified, aborting...\nSupported TLS versions are \"1.0\", \"1.1\", \"1.2\" and \"1.3\" (draft)\n");
	exit(1);
}



/* load TLS Cipher Suites List */

CSuiteList CSList=loadCSList(arguments.CS_file);

if (NULL==CSList.CSArray) {
	printf("Error loading TLS Cipher Suites List, aborting...\n");
	exit(1);
}

/* load SSL Cipher Suites List */

CSuiteList CSListSSL=loadCSList(arguments.CS_file_SSL);

if (NULL==CSListSSL.CSArray) {
	printf("Error loading SSL Cipher Suites List, aborting...\n");
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
		if (!arguments.quiet)
			printf("Estimating RTT in order to set timeout...\n");
		for (ping_att=1; ping_att<PING_ATT_MAX && myrtt<0; ping_att++){
			myrtt=ping(sin);
			if (myrtt<0){
				if (!arguments.quiet)
					printf("Server did not reply to ping #%d (or some error occurred), trying again...\n", ping_att);
				usleep(200000); // sleep 0.2s and retry - seems like if retry immediately always fails...
			}
		}

		if (ping_att==PING_ATT_MAX) {
			if (!arguments.quiet)
				printf("Server did not reply to any ping (or some error occurred), setting timeout to default value (%d ms).\n", TIMEOUT_DEFAULT);
			timeout_internal=TIMEOUT_DEFAULT;
		} else {
			timeout_internal=myrtt+200; // setting timeout to rtt + 200ms
			if (!arguments.quiet)
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

	int isSSL=0; // SSL3 flag
	
	/* search for the selected cipher suite in the TLS list */

	selectedCS = searchCSbyName(arguments.cipherSuite,CSList.CSArray,CSList.nol);

	if (-1 != selectedCS) { // if found
		if (!arguments.quiet) {
			printf("Probing for support of TLS Cipher Suite %s\n", arguments.cipherSuite);
		}
	}
	
	else { // if not found in TLS list...

		/* search for the selected cipher suite in the SSL list */

		selectedCS = searchCSbyName(arguments.cipherSuite,CSListSSL.CSArray,CSListSSL.nol);

		if (-1 != selectedCS) { // if found

			isSSL=1;
			version=version30; // set SSL version 3 instead of default (TLS 1.2)
			
			if (!arguments.quiet) {
				printf("Probing for support of SSL Cipher Suite %s\n", arguments.cipherSuite);
			}
		}

		else { // if not found even in the SSL list
			printf("Unknown Cipher Suite %s.\n",arguments.cipherSuite);
			exit(1);
		}
		
		
	}

	if (!isSSL) { // if TLS
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
				printf("Cipher Suite NOT SUPPORTED (server closed TCP connection or timeout)\n");
				break;
			case 3:
				printf("Cipher Suite NOT SUPPORTED (server sent decode error)\n");
				break;
			case -2:
				printf("Could not understand server reply, aborting...\n");
			case -1:
			default:
				printf("An error occurred while checking for cipher suite support\n");
				exit(1);

		}
	}
	else { // if SSL
		switch ( checkSuiteSupport(arguments, sin, timeoutS, timeoutR, CSListSSL.CSArray, selectedCS) ) {
			case 0:
				//printSecColor(checkSuiteSecurity (CSList.CSArray[selectedCS].id, CSEvalSt));
				printf(KRED); // SSL 3 is unsafe
				printf("Cipher Suite SUPPORTED\n");
				printf(KRESET);
				break;
			case 1:
				printf("Cipher Suite NOT SUPPORTED (handshake failure received)\n");
				break;
			case 2:
				printf("Cipher Suite NOT SUPPORTED (server closed TCP connection or timeout)\n");
				break;
			case 3:
				printf("Cipher Suite NOT SUPPORTED (server sent decode error)\n");
				break;
			case -2:
				printf("Could not understand server reply, aborting...\n");
			case -1:
			default:
				printf("An error occurred while checking for cipher suite support\n");
				exit(1);

		}
	}
	
	

	if (!arguments.quiet)
		printf("Legend: " KCYN "MODERN " KGRN "INTERMEDIATE " KYEL "OLD " KRED "PROBLEMATIC " KWHT "UNKNOWN\n" KRESET);

}

/* full scan mode (test for support of all known cipher suites) */

else if (!arguments.cipherSuiteMode && arguments.fullScanMode && !arguments.serverMode) {
	
	int nossTLS=0; // number of supported cipher suites - TLS
	int nossSSL=0; // number of supported cipher suites - SSL
	
	/* check connectivity */
	int sTest; //socket
	if ((sTest=createConnection(sin, timeoutS, timeoutR)) < 0) {
		exit(1);
	} else {
		shutdown(sTest, SHUT_WR); // shutdown connection
	}
	
	if (!arguments.quiet)
		printf("Scanning server for supported cipher suites...\nCipher suites SUPPORTED by the server are:\n");
	
	/* set up pthread_t stuff */
	pthread_t *tlsThreads=malloc(arguments.maxThreads*sizeof(pthread_t));
	pthread_attr_t attr;
	
	/* array for values returned by threads */
	int *returnedValues=malloc(arguments.maxThreads*sizeof(int));
	
	/* set thread detach attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);	

	/* thread parameters (arguments) array */
	threadParam *threadParams=malloc(arguments.maxThreads*sizeof(threadParam));

	/* other thread-related stuff */
	int tId; // thread identifier (thread index in thread array)
	int tRet; // for storing pthread_create and pthread_join values
	int *returnedValue=NULL; // used to get the Cipher Suite check result from the thread 
	
	int startCS; // index of the starting Cipher Suite in current iteration


	/* scan for TLS */
	printf("\rTLS:\n");

	/* At every iteration, start from Cipher Suite number startCS.
	 Then create "arguments.maxThreads" different threads (if possible)
	 in order to check support for Suites with indices from startCS
	 up to startCS+arguments.maxThreads-1 */
	
	for (startCS=0; startCS < CSList.nol; startCS+=arguments.maxThreads) {
		
		/* start threads */
		
		for(tId=0, selectedCS=startCS; tId < arguments.maxThreads && selectedCS < CSList.nol; tId++, selectedCS++) {

			/* initialize thread parameters */
			//threadParams[tId]=malloc(sizeof(struct threadParam));
	
			threadParams[tId].arguments=arguments;
			threadParams[tId].sin=sin;
			threadParams[tId].timeoutS=timeoutS;
			threadParams[tId].timeoutR=timeoutR;
			threadParams[tId].CSuitesL=CSList.CSArray;
			threadParams[tId].selectedCS=selectedCS;
			
			
			tRet = pthread_create(&(tlsThreads[tId]), &attr, checkSuiteSupportThr, (void *)&(threadParams[tId]));
			if (tRet) {
				printf("Error while creating threads: return code from pthread_create() is %d\n", tRet);
				exit(1);
			}
		}

		/* join threads */
		
		for(tId=0, selectedCS=startCS; tId < arguments.maxThreads && selectedCS < CSList.nol; tId++, selectedCS++) {
			
			tRet = pthread_join(tlsThreads[tId], (void **)&returnedValue );
			returnedValues[tId]=*returnedValue;

			free(returnedValue); // clean mem allocated by thread returning value
		
			if (tRet) {
				printf("Error while joining threads: return code from pthread_join() is %d\n", tRet);
				exit(1);
			}
		}

		/* print results */
		
		for(tId=0, selectedCS=startCS; tId<arguments.maxThreads && selectedCS < CSList.nol; tId++, selectedCS++) {

			switch ( returnedValues[tId] ) {
				case 0:
					printf("\r");
					printSecColor(checkSuiteSecurity (CSList.CSArray[selectedCS].id, CSEvalSt));
					printf("%s", CSList.CSArray[selectedCS].name);
					printf(KRESET "\n");
					nossTLS++;
					break;
				case 1:
				case 2:
				case 3:
				case 4:
					if (!arguments.quiet)
						printf("\rTesting suite %d/%d...",selectedCS+1,CSList.nol);
					break;
				case -2:
					printf("Could not understand server reply, aborting...\n");
				case -1:
				default:
					printf("An error occurred while checking for cipher suite support\n");
					exit(1);

			}
			
		}
		
		
	}

	if (0 == nossTLS) {
		printf("\r                         ");
		printf("\rNONE\n");
	}

	/* clean some mem after TLS scan */
	//for(tId=0; tId < arguments.maxThreads; tId++)
	//		free(threadParams[tId]);

	if (!arguments.skipSSL) {
		
		/* scan for SSL */
		
		printf("\r                         ");
		printf("\n\rSSL3:\n");
		version=version30; // force SSL version 3 instead of the selected version

		/* At every iteration, start from Cipher Suite number startCS.
	 	Then create "arguments.maxThreads" different threads (if possible)
	 	in order to check support for Suites with indices from startCS
	 	up to startCS+arguments.maxThreads-1 */
		
		for (startCS=0; startCS < CSListSSL.nol; startCS+=arguments.maxThreads) {

			/* start threads */
		
			for(tId=0, selectedCS=startCS; tId < arguments.maxThreads && selectedCS < CSListSSL.nol; tId++, selectedCS++) {

				/* initialize thread parameters */
				//threadParams[tId]=malloc(sizeof(struct threadParam));
	
				threadParams[tId].arguments=arguments;
				threadParams[tId].sin=sin;
				threadParams[tId].timeoutS=timeoutS;
				threadParams[tId].timeoutR=timeoutR;
				threadParams[tId].CSuitesL=CSListSSL.CSArray;
				threadParams[tId].selectedCS=selectedCS;
				
				tRet = pthread_create(&(tlsThreads[tId]), &attr, checkSuiteSupportThr, (void *)&(threadParams[tId]));

				if (tRet) {
					printf("Error while creating threads: return code from pthread_create() is %d\n", tRet);
					exit(1);
				}
			}


			/* join threads */
		
			for(tId=0, selectedCS=startCS; tId < arguments.maxThreads && selectedCS < CSListSSL.nol; tId++, selectedCS++) {
				
				tRet = pthread_join(tlsThreads[tId], (void **)&returnedValue );
				
				returnedValues[tId]=*returnedValue;
				

				free(returnedValue); // clean mem allocated by thread returning value
		
				if (tRet) {
					printf("Error while joining threads: return code from pthread_join() is %d\n", tRet);
					exit(1);
				}
			}

			/* print results */
		
			for(tId=0, selectedCS=startCS; tId<arguments.maxThreads && selectedCS < CSListSSL.nol; tId++, selectedCS++) {

				switch ( returnedValues[tId] ) {
					
					case 0:
						printf("\r");
						//printSecColor(checkSuiteSecurity (CSListSSL.CSArray[selectedCS].id, CSEvalSt));
						printf(KRED); // SSL3 is assumed to be unsafe
						printf("%s", CSListSSL.CSArray[selectedCS].name);
						printf(KRESET "\n");
						nossSSL++;
						break;
					case 1:
					case 2:
					case 3:
					case 4:
						if (!arguments.quiet)
							printf("\rTesting suite %d/%d...",selectedCS+1,CSListSSL.nol);
						break;
					case -2:
						printf("Could not understand server reply, aborting...\n");
					case -1:
					default:
						printf("An error occurred while checking for cipher suite support\n");
						exit(1);

				}
			}
		}

		if (0 == nossSSL) {
			printf("\r                         ");
			printf("\rNONE\n");
		}		

		/* clean some mem after SSL scan */
		//for(tId=0; tId < arguments.maxThreads; tId++)
		//		free(threadParams[tId]);
		
	}


	/* common memory cleaning for threads-related stuff */
	
	free(tlsThreads);
	free(returnedValues);
	free(threadParams);
	
	
	
	if (!arguments.quiet)
		printf("\rFinished, found support for %d TLS Cipher Suites and %d SSL3 Cipher Suites.\n", nossTLS, nossSSL);
	if (0==nossTLS+nossSSL) {
		if (!arguments.quiet)
			printf("Maybe you have to set a bigger timeout?\n");
	} else {
		if (!arguments.quiet)
			printf("Legend: " KCYN "MODERN " KGRN "INTERMEDIATE " KYEL "OLD " KRED "PROBLEMATIC " KWHT "UNKNOWN\n" KRESET);
	}
	
}

/* server mode */

else if (!arguments.cipherSuiteMode && !arguments.fullScanMode && arguments.serverMode) {

	int isSSL=0; // SSL3 flag
	
	int s = passiveOpenConnection(port); // setup passive open and get socket
	
	if (s < 0) {
		printf("Error while setting up passive open, aborting...\n");
		exit(1);
	}		

	
	int new_s; // new socket
	int len; // length of incoming data
	uint8 buf[SERVER_BUFLEN]; // buffer for incoming data
	
	// initialize buf by filling it with zeros
	memset(buf,0,SERVER_BUFLEN);
	
	if (!arguments.quiet)
		printf("Listening for TLS connections on TCP port %d...\n", port);
	
	
	/* wait for incoming connection */
	//while (1) {
		if ((new_s = accept(s, NULL, NULL)) < 0) {
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
			HandshakeClientHello tlsHCH;
			tlsHCH.msg_type=(uint8)(*(buf+5));
			
			// skip length -- tlsPT.body.length=(uint24)(*(buf+6));
			
			/* check if ClientHello message was received */
			if (HT_CLIENT_HELLO!=tlsHCH.msg_type)
				goto bad_creq;
				
			/* ...if so, continue parsing it... */
			ClientHello tlsCH;
			tlsCH.client_version.major=(uint8)(*(buf+9));
			tlsCH.client_version.minor=(uint8)(*(buf+10));

			if (3==tlsCH.client_version.major && 0==tlsCH.client_version.minor) // if SSL3
				isSSL=1;
			
			tlsCH.random.gmt_unix_time=ntohl((uint32)(*(buf+11)));
			
			// skip random bytes (28 bytes) - 11+4+28=43
			
			tlsCH.session_id=(uint8)(*(buf+43));
			//printf("sid_len:%d\n",tlsCH.session_id.length);
			
			// skip session id itself 43+1+tlsCH.session_id.length
			
			tlsCH.cipher_suites_length=((uint16)(*(buf+43+2+tlsCH.session_id)));
			

			/* print offered cipher suite list */
			int ocs_idx;
			CipherSuite cs;
			int cs_pos;
			
			if (!arguments.quiet) {
				if (!isSSL) {
					printf("TLS ");
				} else {
					printf("SSL3 ");
				}
				printf("ClientHello was received, Cipher Suites offered by the client are (in order of preference):\n");
			}
			//printf("%d\n",tlsCH.cipher_suites.length);
			
			for (ocs_idx=0;ocs_idx<tlsCH.cipher_suites_length/2;ocs_idx++) { // 2 bytes per cipher suite
				cs.a = (uint8)(*(buf+43+1+tlsCH.session_id+2+2*ocs_idx));
				cs.b = (uint8)(*(buf+43+1+tlsCH.session_id+3+2*ocs_idx));
				
				//printf("%d %d\n",cs[0],cs[1]);
				if (!isSSL)
					cs_pos=searchCSbyID(cs,CSList.CSArray,CSList.nol); // search for the offered cipher suite in the IANA list
				else
					cs_pos=searchCSbyID(cs,CSListSSL.CSArray,CSListSSL.nol);
				
				if (cs_pos!=-1) { // if CS was found in the list
					if (!isSSL) {
						printSecColor(checkSuiteSecurity (CSList.CSArray[cs_pos].id, CSEvalSt));
						printf("%s\n",CSList.CSArray[cs_pos].name);
					}
					else {
						printf(KRED); // SSL3 is unsafe
						printf("%s\n",CSListSSL.CSArray[cs_pos].name);
					}
					
					printf(KRESET);
				}
				else if (0x00==cs.a && 0xff==cs.b) { // this handles TLS_EMPTY_RENEGOTIATION_INFO_SCSV

					printf(KWHT);
					
					if (!isSSL) {
						printf("TLS_EMPTY_RENEGOTIATION_INFO_SCSV\n");
					} else {
						printf("SSL_EMPTY_RENEGOTIATION_INFO_SCSV\n");
					}

					printf(KRESET);

				}
				else if (0x56==cs.a && 0x00==cs.b) { // this handles TLS_FALLBACK_SCSV
					printf(KWHT);
					
					if (!isSSL) {
						printf("TLS_FALLBACK_SCSV\n");
					} else {
						printf("SSL_FALLBACK_SCSV\n");
					}

					printf(KRESET);
				}
				else {
					printf("An unknown Cipher Suite was received:%02x %02x.\n", cs.a, cs.b);
				}
			}
			
			if (!arguments.quiet) {
				printf("Finished, %d Cipher Suites were offered by the client.\n", tlsCH.cipher_suites_length/2);
				printf("Legend: " KCYN "MODERN " KGRN "INTERMEDIATE " KYEL "OLD " KRED "PROBLEMATIC " KWHT "SIGNAL/UNKNOWN\n" KRESET);
			}
			
			
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
free(CSListSSL.CSArray);
free(CSEvalSt.modern);
free(CSEvalSt.intermediate);
free(CSEvalSt.old);
free(CSEvalSt.all);

return 0; // return if successful

}


uint24 hton24(uint24 in) {
	uint24 out;
	out.lsb=in.msb;
	out.nsb=in.nsb;
	out.msb=in.lsb;
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
		if (id.a==CSL[i].id.a && id.b==CSL[i].id.b){
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

void *checkSuiteSupportThr(void* params) {
	
	//struct threadParam *thrPar=params;
	
	int *retVal=malloc(sizeof(int));
	
	*retVal=checkSuiteSupport(((threadParam*)params)->arguments, ((threadParam*)params)->sin, ((threadParam*)params)->timeoutS, ((threadParam*)params)->timeoutR, ((threadParam*)params)->CSuitesL, ((threadParam*)params)->selectedCS);

	//printf("RetVAL:%d\n",*retVal);
	pthread_exit((void*)retVal);
	
}



int checkSuiteSupport(struct arguments arguments, struct sockaddr_in sin, struct timeval timeoutS, struct timeval timeoutR, CSuiteDesc *CSuitesL, int selectedCS) {
	
	/* pre-build TLS Alert message (used to tear down the connection after Server Hello(s) ) */
	
	Alert alertMsg;
	alertMsg.level=AL_FATAL;
	alertMsg.description=AD_HANDSHAKE_FAILURE;
	// HANDSHAKE_FAILURE was chosen because is compatible with all the TLS/SSL versions supported by the program:
	/* From TLS 1.2 RFC:
	handshake_failure
      Reception of a handshake_failure alert message indicates that the
      sender was unable to negotiate an acceptable set of security
      parameters given the options available.  This is a fatal error. */

	TLSPlaintextAL tlsPTAL;
	tlsPTAL.type=CT_ALERT; // handshake message
	tlsPTAL.version=version;
	tlsPTAL.length=htons(sizeof(alertMsg));
	tlsPTAL.body=alertMsg;
	
	
	/* TLS message set-up phase */

	ClientHello myCH;
	myCH.client_version=version;

	time_t tv;
	tv=time(NULL);

	if (arguments.truetime) { // if user requested true timestamp to be used in TLS messages
		myCH.random.gmt_unix_time=(uint32) tv; // timestamp converted to big endian
	} else {
		fill_random((uint8*)&(myCH.random.gmt_unix_time), 32); // else use random data (to avoid clock drift fingerprinting - https://bugzilla.mozilla.org/show_bug.cgi?id=967923 )
	}

	fill_random(myCH.random.random_bytes, 28); // fill the random nonce

	myCH.session_id=0x0; // no session id
	myCH.cipher_suites_length=1*sizeof(CipherSuite); // 1 cipher suite (little endian)
	myCH.cipher_suites=malloc(1*sizeof(CipherSuite));
	myCH.cipher_suites->a=CSuitesL[selectedCS].id.a;
	myCH.cipher_suites->b=CSuitesL[selectedCS].id.b;
	myCH.compression_methods_length=1*sizeof(CompressionMethod); // 1 compression method: no compression
	myCH.compression_methods=malloc(1*sizeof(CompressionMethod));
	myCH.compression_methods[0]=CM_NO_COMPRESSION;
	
	/* Determine the number of TLS Extensions to use and set-up Extensions*/
	int noTLSExt=0;
	int csIsECC=0;
	Extension snExt;
	ServerNameExData sNameData;
	Extension ecExt;
	Extension ecPFExt;
	ECExData ecData;
	ECPFExData ecPFData;
	
	myCH.extensions_length=0;
	
	if (arguments.TLSExtensions) {
		/* server_name extension */
		if (arguments.TLSSNExtension && !hostIsIp) {
			noTLSExt++;
			sNameData.name=host;
			sNameData.name_length=strlen(host);
			sNameData.name_type=TLS_EXT_SERVER_NAME_HOSTNAME;
			sNameData.list_length=sNameData.name_length+sizeof(sNameData.name_length)+sizeof(sNameData.name_type);
			
			snExt.length=sNameData.list_length+sizeof(sNameData.list_length);
			snExt.type=TLS_EXT_SERVER_NAME;
			
			myCH.extensions_length+=snExt.length+sizeof(snExt.length)+sizeof(snExt.type); // update ClientHello extensions length
		}
		/* if selectedCS is ECC-related... */
		csIsECC=(NULL!=strstr(CSuitesL[selectedCS].name,"ECDH") || NULL!=strstr(CSuitesL[selectedCS].name,"ECDSA"));
		if (csIsECC) {
			/* elliptic_curves extension */
			if (arguments.TLSECExtension) {
				noTLSExt++;
				
				ecData.curves=malloc(35*sizeof(uint16));
				
				// beware, you fixed 35 elements!!!
				// fill curve list with all the known curves (to be improved...)
				uint16 idx;
				for (idx=0;idx<28; idx++) {
					ecData.curves[idx]=idx+1;
				}
				ecData.curves[28]=256;
				ecData.curves[29]=257;
				ecData.curves[30]=258;
				ecData.curves[31]=259;
				ecData.curves[32]=260;
				ecData.curves[33]=65281;
				ecData.curves[34]=65282;
				
				 
				ecData.ECLength=35*sizeof(uint16);
				
				ecExt.type=TLS_EXT_EC;
				ecExt.length=ecData.ECLength+sizeof(ecData.ECLength);
				
				myCH.extensions_length+=ecExt.length+sizeof(ecExt.length)+sizeof(ecExt.type); // update ClientHello extensions length
				
			}
			
			/* elliptic_curves point formats extension */
			if (arguments.TLSECPFExtension) {
				noTLSExt++;
				
				ecPFData.formats=malloc(1*sizeof(uint8));
				
				//beware, you fixed 1 element!!!
				ecPFData.formats[0]=TLS_EXT_EC_PF_UN;
				 
				ecPFData.formats_length=1*sizeof(uint8);
				
				ecPFExt.type=TLS_EXT_EC_PF;
				ecPFExt.length=ecPFData.formats_length+sizeof(ecPFData.formats_length);
				
				myCH.extensions_length+=ecPFExt.length+sizeof(ecPFExt.length)+sizeof(ecPFExt.type); // update ClientHello extensions length
				
			}
			
			
		}
	}
	
	
	size_t actCHSize=sizeof(myCH.client_version)+sizeof(myCH.random)+sizeof(myCH.session_id)+sizeof(myCH.cipher_suites_length)+sizeof(*(myCH.cipher_suites))+sizeof(myCH.compression_methods_length)+sizeof(*(myCH.compression_methods)); // actual Client Hello size
	
	
	if (noTLSExt>0)
		actCHSize+=sizeof(myCH.extensions_length)+myCH.extensions_length;
	
	
	HandshakeClientHello myHandShakeCH;
	myHandShakeCH.msg_type=HT_CLIENT_HELLO; //client_hello
	myHandShakeCH.length.lsb=(actCHSize >> 16)&0xff;
	myHandShakeCH.length.nsb=(actCHSize >> 8)&0xff;
	myHandShakeCH.length.msb=(actCHSize)&0xff;

	TLSPlaintext tlsPTCH;
	tlsPTCH.type=CT_HANDSHAKE; // handshake message
	tlsPTCH.version=version;
	tlsPTCH.length=sizeof(myHandShakeCH)+actCHSize;
	
	
	/* endianess conversions */
	
	tlsPTCH.length=htons(tlsPTCH.length);
	myHandShakeCH.length=hton24(myHandShakeCH.length);
	myCH.random.gmt_unix_time=htonl(myCH.random.gmt_unix_time);
	myCH.cipher_suites_length=htons(myCH.cipher_suites_length);
	
	if (noTLSExt>0) {
		myCH.extensions_length=htons(myCH.extensions_length);
		
		if (arguments.TLSSNExtension && !hostIsIp) {
			snExt.type=htons(snExt.type);
			snExt.length=htons(snExt.length);
			sNameData.name_type=htons(sNameData.name_type);
			sNameData.list_length=htons(sNameData.list_length);
		}
		
		if (csIsECC) {
			if (arguments.TLSECExtension) {
				ecExt.type=htons(ecExt.type);
				ecExt.length=htons(ecExt.length);
				ecData.ECLength=htons(ecData.ECLength);
				int idx;
				for (idx=0; idx<ntohs(ecData.ECLength)/sizeof(uint16); idx++) {
					ecData.curves[idx]=htons(ecData.curves[idx]);
				}
				
			}
			if (arguments.TLSECPFExtension) {
				ecPFExt.type=htons(ecPFExt.type);
				ecPFExt.length=htons(ecPFExt.length);
			}
		}
		
		
	}
	
	
	/* TLS message build-up phase */
	
	size_t msg_size=sizeof(TLSPlaintext)+sizeof(HandshakeClientHello)+actCHSize;
	opaque* tlsMsg=malloc(msg_size);
	opaque* mloc=tlsMsg; // pointer to the mem area to fill
	
	memcpy(mloc,&(tlsPTCH.type),sizeof(tlsPTCH.type));
	mloc+=sizeof(tlsPTCH.type);
	memcpy(mloc,&(tlsPTCH.version),sizeof(tlsPTCH.version));
	mloc+=sizeof(tlsPTCH.version);
	memcpy(mloc,&(tlsPTCH.length),sizeof(tlsPTCH.length));
	mloc+=sizeof(tlsPTCH.length);
	
	memcpy(mloc,&(myHandShakeCH.msg_type),sizeof(myHandShakeCH.msg_type));
	mloc+=sizeof(myHandShakeCH.msg_type);
	memcpy(mloc,&(myHandShakeCH.length),sizeof(myHandShakeCH.length));
	mloc+=sizeof(myHandShakeCH.length);
	
	memcpy(mloc,&(myCH.client_version),sizeof(myCH.client_version));
	mloc+=sizeof(myCH.client_version);
	memcpy(mloc,&(myCH.random),sizeof(myCH.random));
	mloc+=sizeof(myCH.random);
	memcpy(mloc,&(myCH.session_id),sizeof(myCH.session_id));
	mloc+=sizeof(myCH.session_id);
	memcpy(mloc,&(myCH.cipher_suites_length),sizeof(myCH.cipher_suites_length));
	mloc+=sizeof(myCH.cipher_suites_length);
	memcpy(mloc,&(myCH.cipher_suites[0]),sizeof(myCH.cipher_suites[0]));
	mloc+=sizeof(myCH.cipher_suites[0]);
	memcpy(mloc,&(myCH.compression_methods_length),sizeof(myCH.compression_methods_length));
	mloc+=sizeof(myCH.compression_methods_length);
	memcpy(mloc,&(myCH.compression_methods[0]),sizeof(myCH.compression_methods[0]));
	mloc+=sizeof(myCH.compression_methods[0]);
	
	
	if (noTLSExt>0) {
		memcpy(mloc,&(myCH.extensions_length),sizeof(myCH.extensions_length));
		mloc+=sizeof(myCH.extensions_length);
		/* server_name extension */
		if (arguments.TLSSNExtension && !hostIsIp) {
			memcpy(mloc,&(snExt.type),sizeof(snExt.type));
			mloc+=sizeof(snExt.type);
			memcpy(mloc,&(snExt.length),sizeof(snExt.length));
			mloc+=sizeof(snExt.length);
			memcpy(mloc,&(sNameData.list_length),sizeof(sNameData.list_length));
			mloc+=sizeof(sNameData.list_length);
			memcpy(mloc,&(sNameData.name_type),sizeof(sNameData.name_type));
			mloc+=sizeof(sNameData.name_type);
			memcpy(mloc,&(sNameData.name_length),sizeof(sNameData.name_length));
			mloc+=sizeof(sNameData.name_length);
			memcpy(mloc,sNameData.name,sNameData.name_length); // can do this because sNameData.name_length is uint8 - no endianess problems
			mloc+=sNameData.name_length;
		}
		
		/* ecc extensions */
		if (csIsECC) {
			if (arguments.TLSECExtension) {
				memcpy(mloc,&(ecExt.type),sizeof(ecExt.type));
				mloc+=sizeof(ecExt.type);
				memcpy(mloc,&(ecExt.length),sizeof(ecExt.length));
				mloc+=sizeof(ecExt.length);
				memcpy(mloc,&(ecData.ECLength),sizeof(ecData.ECLength));
				mloc+=sizeof(ecData.ECLength);
				memcpy(mloc,ecData.curves,ntohs(ecData.ECLength));
				mloc+=ntohs(ecData.ECLength);
			}
			if (arguments.TLSECPFExtension) {
				memcpy(mloc,&(ecPFExt.type),sizeof(ecPFExt.type));
				mloc+=sizeof(ecPFExt.type);
				memcpy(mloc,&(ecPFExt.length),sizeof(ecPFExt.length));
				mloc+=sizeof(ecPFExt.length);
				memcpy(mloc,&(ecPFData.formats_length),sizeof(ecPFData.formats_length));
				mloc+=sizeof(ecPFData.formats_length);
				memcpy(mloc,ecPFData.formats,ecPFData.formats_length);
				mloc+=ecPFData.formats_length;
			}
			
		}
		
		
		
	}
	
	
	
	if (arguments.printMessage) { // let's print ClientHello before sending it
		printMem(tlsMsg, msg_size);
	}


	/* create tcp connection */
	int s; // socket
	if ((s=createConnection(sin, timeoutS, timeoutR)) < 0) {
		return -1;
	}
	
	uint8 rbuf[CLIENT_BUFLEN]; // buffer for incoming data
	int timeOutReached=0; // timeout flag initialization

	send(s, tlsMsg, msg_size, 0); // send ClientHello


	/* free memory from ClientHello-related elements */
	
	free(tlsMsg);
	free(myCH.cipher_suites);
	free(myCH.compression_methods);
	
	if (noTLSExt>0) {
		if (csIsECC) {
			if (arguments.TLSECExtension) {
				free(ecData.curves);
			}
			if (arguments.TLSECPFExtension) {
				free(ecPFData.formats);
			}
		}
	}

	// initialize rbuf by filling it with zeros
	memset(rbuf,0,CLIENT_BUFLEN);

	// get the initial part of the reply
	ssize_t received=recv(s, rbuf, sizeof(rbuf), 0);

	if(rbuf[0]==CT_HANDSHAKE && rbuf[5]==HT_SERVER_HELLO && !timeOutReached && received > 0) { // if server hello received
	
		send(s, &tlsPTAL, sizeof(tlsPTAL), 0); // send TLS Alert to cancel the handshake
		shutdown(s,SHUT_WR); // shutdown connection
		
		
		return 0; // cipher suite supported
	
	} else if ((rbuf[0]==CT_ALERT && rbuf[6]==AD_HANDSHAKE_FAILURE && !timeOutReached && received > 0)) { // if handshake failure received (and so the selected cipher suite is not supported by the server)
	
		shutdown(s,SHUT_WR); // shutdown connection
		
		return 1; // cipher suite not supported: handshake failure
	
	} else if ( received <= 0 ) { // if connection was closed by the server or timeout was reached
		
		shutdown(s,SHUT_WR); // shutdown connection
		
		return 2; // cipher suite not supported: connection was closed by the server or timeout was reached
		
	} else if ((rbuf[0]==CT_ALERT && rbuf[6]==AD_DECODE_ERROR && !timeOutReached && received > 0)) { // IIS return this sometimes...
	
		shutdown(s,SHUT_WR); // shutdown connection
		
		return 3; // cipher suite not supported: decode error
	
	} else {
	
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
	char line[CSF_LINE_MAX];
	CSuiteDesc actCS;
	int a32,b32; // these are to avoid overflows with sscanf
	
	/* open IANA Cipher Suites List */
	CS_file = fopen(filePath,"r");

	if (NULL == CS_file) {
		printf("Error while opening Cipher Suites List file:\nplease make sure tls-parameters-4.csv and ssl-parameters.csv are in the default directory (/usr/local/share/tlsprobe/) or specify their path through the -f and -g options\n");
		// this would result in ChaCha Suites not being discovered:
		// printf("For TLS, you can get an up-to-date CSV file from: http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml\n");
		return CSList; // which was initialized as invalid
	}

	/* parse IANA Cipher Suites List */

	while (!feof(CS_file)) {
		if (NULL != fgets(line, sizeof(line), CS_file) && 3==sscanf(line,"\"0x%02x,0x%02x\",%99[^,\n],%*s", &a32, &b32, (actCS.name))) { // if a valid suite was parsed
			actCS.id.a=(uint8)a32;
			actCS.id.b=(uint8)b32;
			CSList.nol++;
			CSList.CSArray=realloc(CSList.CSArray,CSList.nol*sizeof(CSuiteDesc));
			CSList.CSArray[CSList.nol-1]=actCS;
		}
	}

	/* file parsed, close file */

	fclose(CS_file);
	
	/* success, return valid data */
	
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
	char line[CSF_LINE_MAX];
	int a32,b32; // these are used to avoid overflow with sscanf and %02x
	uint8 a,b;

	/* search for <modern> tag */
	

	while(!feof(CSE_file))
	{
		
		if (NULL != fgets(line, sizeof(line), CSE_file)) {
			
			if (NULL != strstr(line,"<modern>")) {
				while ((NULL == strstr(line,"</modern>")) && !feof(CSE_file)) {

					if (2==sscanf(line,"0x%02x,0x%02x%*s", &a32, &b32)) {
						a=(uint8)a32; // this is to avoid overflow (see a32 and b32 declarations)
						b=(uint8)b32;
						CSEList.modern_size++;
						CSEList.modern=realloc(CSEList.modern,CSEList.modern_size*sizeof(CipherSuite));
						(*(CSEList.modern+CSEList.modern_size-1)).a=a;
						(*(CSEList.modern+CSEList.modern_size-1)).b=b;
					}

					if ( NULL == fgets(line, sizeof(line), CSE_file) )
						printf("Error while loading CS eval file.\n");
						
				}
			
			}
			else if (NULL != strstr(line,"<intermediate>")) {
				while (NULL == strstr(line,"</intermediate>") && !feof(CSE_file)) {

					if (2==sscanf(line,"0x%02x,0x%02x%*s", &a32, &b32)) {
						a=(uint8)a32; // this is to avoid overflow (see a32 and b32 declarations)
						b=(uint8)b32;
						CSEList.intermediate_size++;
						CSEList.intermediate=realloc(CSEList.intermediate,CSEList.intermediate_size*sizeof(CipherSuite));
						(*(CSEList.intermediate+CSEList.intermediate_size-1)).a=a;
						(*(CSEList.intermediate+CSEList.intermediate_size-1)).b=b;
					}

					if ( NULL == fgets(line, sizeof(line), CSE_file) )
						printf("Error while loading CS eval file.\n");
						
				}
			
			}
			else if (NULL != strstr(line,"<old>")) {
				while (NULL == strstr(line,"</old>") && !feof(CSE_file)) {

					if (2==sscanf(line,"0x%02x,0x%02x%*s", &a32, &b32)) {
						a=(uint8)a32; // this is to avoid overflow (see a32 and b32 declarations)
						b=(uint8)b32;
						CSEList.old_size++;
						CSEList.old=realloc(CSEList.old,CSEList.old_size*sizeof(CipherSuite));
						(*(CSEList.old+CSEList.old_size-1)).a=a;
						(*(CSEList.old+CSEList.old_size-1)).b=b;
					}

					if ( NULL == fgets(line, sizeof(line), CSE_file) )
						printf("Error while loading CS eval file.\n");
						
				}
			
			}
			else if (NULL != strstr(line,"<all>")) {
				while (NULL == strstr(line,"</all>") && !feof(CSE_file)) {

					if (2==sscanf(line,"0x%02x,0x%02x%*s", &a32, &b32)) {
						a=(uint8)a32; // this is to avoid overflow (see a32 and b32 declarations)
						b=(uint8)b32;
						CSEList.all_size++;
						CSEList.all=realloc(CSEList.all,CSEList.all_size*sizeof(CipherSuite));
						(*(CSEList.all+CSEList.all_size-1)).a=a;
						(*(CSEList.all+CSEList.all_size-1)).b=b;
					}

					if ( NULL == fgets(line, sizeof(line), CSE_file) )
						printf("Error while loading CS eval file.\n");
				}
			
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
	//printf("%d %d, %d %d\n",CS.a,(*(CSL+i)).a,CS.b,(*(CSL+i)).b);
		if (CS.a==(*(CSL+i)).a && CS.b==(*(CSL+i)).b)
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
			printf(KCYN);
			break;
		case 1:
			printf(KGRN);
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

int isIpAddr(char* str) {
	int a,b,c,d;
	int ngot=0;
	
	ngot=sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
	
	if (4==ngot && a<256 && b<256 && c<256 && d<256)
		return 1;
	else
		return 0;
		
}
