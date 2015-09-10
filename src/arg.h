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

#define ARGNUM 1


const char *argp_program_version =
  "tlsprobe 0.1";
const char *argp_program_bug_address =
  "<marco.bellaccini[at!]gmail.com>";

/* Program documentation. */
static char doc[] =
  "tlsprobe -- a TLS tester utility";

/* A description of the arguments we accept. */
static char args_doc[] = "host";

/* The options we understand. */
static struct argp_option options[] = {
  {"true-time",    'T', 0,      0,  "Insert real Unix timestamp in TLS messages instead of random data (see https://bugzilla.mozilla.org/show_bug.cgi?id=967923 for details)" },
  {"print-messages",    'm', 0,      0,  "Print sent/received ClientHello message" },
  {"port",   'p', "PORT", 0, "Set port to TCP port PORT (default is tcp/443 - HTTPS)" },
  {"cs-file",   'f', "FILE", 0, "Use IANA Cipher Suites List file FILE (default is tls-parameters-4.csv located in /usr/local/share/tlsprobe)" },
  {"cipher-suite",   'c', "CIPHER_SUITE_ID", 0, "Cipher Suite probe MODE: test if server supports cipher suite CIPHER_SUITE_ID (e.g. TLS_RSA_WITH_AES_128_CBC_SHA)" },
  {"full-scan",   'F', 0, 0, "Full-scan MODE: test the server for support of all the cipher suites listed in the IANA Cipher Suites List file" },
  {"timeout",   't', "TIMEOUT", 0, "Set the timeout at TIMEOUT [ms] for server reply (useful with IIS servers - which don't send handshake failure messages).\n\
  Note: smaller timeouts mean faster scan, but may lead to unreliable results (i.e.: underestimation of the number of supported ciphers).\nDefault timeout is 500ms." },
  {"auto-timeout",   'a', 0, 0, "Autoset timeout by estimating RTT with ping (needs a shell with ping, tail, awk and cut utilities)." },
  {"tls-version",   'R', "VERSION", 0, "Use TLS version VERSION (default is VERSION=1.2)" },
  {"server-mode",   'S', 0, 0, "Server MODE: listen for incoming connections and list offered Cipher Suites when a ClientHello message is received" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *args[ARGNUM];                // host and port
  int truetime, port, printMessage, fullScanMode, timeout, autotimeout, cipherSuiteMode, serverMode;
  char *CS_file;
  char *cipherSuite;
  char *tlsVer;
};



/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'T':
      arguments->truetime = 1;
      break;
	case 'm':
      arguments->printMessage = 1;
	  break;
	case 'p':
      arguments->port = atoi(arg);
	break;
	case 'f':
      arguments->CS_file = arg;
	break;
	case 'c':
      arguments->cipherSuite = arg;
	  arguments->cipherSuiteMode = 1;
	break;
	case 'F':
      arguments->fullScanMode = 1;
	break;
	case 't':
      arguments->timeout = atoi(arg);
	break;
	case 'a':
      arguments->autotimeout = 1;
	break;
	case 'R':
      arguments->tlsVer = arg;
	break;
	case 'S':
      arguments->serverMode = 1;
	break;

    case ARGP_KEY_ARG:
      if (state->arg_num >= ARGNUM)
        /* Too many arguments. */
        argp_usage (state);

      arguments->args[state->arg_num] = arg;

      break;

    case ARGP_KEY_END:
      if (state->arg_num < ARGNUM )
        /* Not enough arguments. */
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };