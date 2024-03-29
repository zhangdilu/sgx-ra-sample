/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/


using namespace std;

#ifdef _WIN32
#pragma comment(lib, "crypt32.lib")
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#else
#include "config.h"
#endif

#ifdef _WIN32
// *sigh*
# include "vs/client/Enclave_u.h"
#else
# include "Enclave_u.h"
#endif
#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "sgx_stub.h"
#endif
#include <stdlib.h>
#include <iostream>
#include <typeinfo>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <intrin.h>
#include <wincrypt.h>
#include "win32/getopt.h"
#else
#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#define MAX_LEN 80

#ifdef _WIN32
# define strdup(x) _strdup(x)
#else
# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#endif

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

typedef struct config_struct {
	char mode;
	uint32_t flags;
	sgx_spid_t spid;
	sgx_ec256_public_t pubkey;
	sgx_quote_nonce_t nonce;
	char *server;
	char *port;
} config_t;

int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len);

sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int edebug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);

void usage();
int do_quote(sgx_enclave_id_t eid, config_t* config, sgx_ra_msg3_t** pp_msg3, uint32_t* p_msg3_size, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, sgx_ecall_proc_msg2_trusted_t p_proc_msg2,
	sgx_ecall_get_msg3_trusted_t p_get_msg3);
int do_attestation(sgx_enclave_id_t eid, config_t *config);
sgx_status_t gen_msg3(sgx_ra_context_t context, sgx_enclave_id_t eid, sgx_ecall_proc_msg2_trusted_t p_proc_msg2, sgx_ecall_get_msg3_trusted_t p_get_msg3, const sgx_ra_msg2_t* p_msg2, uint32_t msg2_size, sgx_ra_msg3_t** pp_msg3, uint32_t* p_msg3_size, config_t* config);
bool enclave_generate_key(sgx_enclave_id_t eid);
bool save_enclave_state(const char *const statefile);
bool save_public_key(const char *const public_key_file);
FILE* open_file(const char* const filename, const char* const mode);
bool enclave_get_buffer_sizes(sgx_enclave_id_t eid);
bool allocate_buffers();
/*
extern sgx_enclave_id_t enclave_id;
extern sgx_launch_token_t launch_token;
extern int launch_token_updated;
extern sgx_status_t sgx_lasterr;
extern void *public_key_buffer;       
extern size_t public_key_buffer_size; 
extern void *sealed_data_buffer;
extern size_t sealed_data_buffer_size;
extern void *encrypted_aes_buffer;
extern size_t encrypted_aes_buffer_size;
extern void *input_buffer;
extern size_t input_buffer_size;
*/

sgx_enclave_id_t enclave_id;
sgx_launch_token_t launch_token;
int launch_token_updated;
sgx_status_t sgx_lasterr;
void *public_key_buffer;       /* unused for signing */
size_t public_key_buffer_size; /* unused for signing */
void *sealed_data_buffer;
size_t sealed_data_buffer_size;
void *encrypted_aes_buffer;
size_t encrypted_aes_buffer_size;
void *input_buffer;
size_t input_buffer_size;

char debug= 0;
char verbose= 0;

#define MODE_ATTEST 0x0
#define MODE_EPID 	0x1
#define MODE_QUOTE	0x2

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y

#ifdef _WIN32
# define ENCLAVE_NAME "Enclave.signed.dll"
#else
# define ENCLAVE_NAME "Enclave.signed.so"
#endif

char* HexArrayToString(const char *vsrc, int len)
{
	char* str = (char*)malloc(len);
	int i ;
	for (i = 0; i < len;i=i+1) {
		str[i] = (int)(vsrc[2*i] - 48)*16 + (int)(vsrc[2*i + 1] - 48);
	}
	return str;
}

int main (int argc, char *argv[])
{
	config_t config;
	sgx_launch_token_t token= { 0 };
	sgx_status_t status;
	sgx_enclave_id_t eid= 0;
	int updated= 0;
	int sgx_support;
	uint32_t i;
	EVP_PKEY *service_public_key= NULL;
	char have_spid= 0;
	char flag_stdio= 0;

	/* Create a logfile to capture debug output and actual msg data */
	fplog = create_logfile("client.log");
	dividerWithText(fplog, "Client Log Timestamp");

	const time_t timeT = time(NULL);
	struct tm lt, *ltp;

#ifndef _WIN32
	ltp = localtime(&timeT);
	if ( ltp == NULL ) {
		perror("localtime");
		return 1;
	}
	lt= *ltp;
#else

	localtime_s(&lt, &timeT);
#endif
	fprintf(fplog, "%4d-%02d-%02d %02d:%02d:%02d\n", 
		lt.tm_year + 1900, 
		lt.tm_mon + 1, 
		lt.tm_mday,  
		lt.tm_hour, 
		lt.tm_min, 
		lt.tm_sec);
	divider(fplog);


	memset(&config, 0, sizeof(config));
	config.mode= MODE_ATTEST;

	static struct option long_opt[] =
	{
		{"help",		no_argument,		0, 'h'},		
		{"debug",		no_argument,		0, 'd'},
		{"epid-gid",	no_argument,		0, 'e'},
#ifdef _WIN32
		{"pse-manifest",
						no_argument,    	0, 'm'},
#endif
		{"nonce",		required_argument,	0, 'n'},
		{"nonce-file",	required_argument,	0, 'N'},
		{"rand-nonce",	no_argument,		0, 'r'},
		{"spid",		required_argument,	0, 's'},
		{"spid-file",	required_argument,	0, 'S'},
		{"linkable",	no_argument,		0, 'l'},
		{"pubkey",		optional_argument,	0, 'p'},
		{"pubkey-file",	required_argument,	0, 'P'},
		{"quote",		no_argument,		0, 'q'},
		{"verbose",		no_argument,		0, 'v'},
		{"stdio",		no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	/* Parse our options */

	while (1) {
		int c;
		int opt_index= 0;
		unsigned char keyin[64];

		c= getopt_long(argc, argv, "N:P:S:dehlmn:p:qrs:vz", long_opt,
			&opt_index);
		if ( c == -1 ) break;

		switch(c) {
		case 0:
			break;
		case 'N':
			if ( ! from_hexstring_file((unsigned char *) &config.nonce,
					optarg, 16)) {

				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}
			SET_OPT(config.flags, OPT_NONCE);

			break;
		case 'P':
			if ( ! key_load_file(&service_public_key, optarg, KEY_PUBLIC) ) {
				fprintf(stderr, "%s: ", optarg);
				crypto_perror("key_load_file");
				exit(1);
			} 

			if ( ! key_to_sgx_ec256(&config.pubkey, service_public_key) ) {
				fprintf(stderr, "%s: ", optarg);
				crypto_perror("key_to_sgx_ec256");
				exit(1);
			}
			SET_OPT(config.flags, OPT_PUBKEY);

			break;
		case 'S':
			if ( ! from_hexstring_file((unsigned char *) &config.spid,
					optarg, 16)) {

				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++have_spid;

			break;
		case 'd':
			debug= 1;
			break;
		case 'e':
			config.mode= MODE_EPID;
			break;
		case 'l':
			SET_OPT(config.flags, OPT_LINK);
			break;
		case 'm':
			SET_OPT(config.flags, OPT_PSE);
			break;
		case 'n':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &config.nonce,
					(unsigned char *) optarg, 16) ) {

				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}

			SET_OPT(config.flags, OPT_NONCE);

			break;
		case 'p':
			if ( ! from_hexstring((unsigned char *) keyin,
					(unsigned char *) optarg, 64)) {
				fprintf(stderr, "key must be 128-byte hex string\n");
				exit(1);
			}

			/* Reverse the byte stream to make a little endien style value */
			for(i= 0; i< 32; ++i) config.pubkey.gx[i]= keyin[31-i];
			for(i= 0; i< 32; ++i) config.pubkey.gy[i]= keyin[63-i];

			SET_OPT(config.flags, OPT_PUBKEY);

			break;
		case 'q':
			config.mode = MODE_QUOTE;
			break;
		case 'r':
			for(i= 0; i< 2; ++i) {
				int retry = 10;
				unsigned char ok= 0;
				uint64_t *np= (uint64_t *) &config.nonce;

				while ( !ok && retry ) ok= _rdrand64_step(&np[i]);
				if ( ok == 0 ) {
					fprintf(stderr, "nonce: RDRAND underflow\n");
					exit(1);
				}
			}
			SET_OPT(config.flags, OPT_NONCE);
			break;
		case 's':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &config.spid,
					(unsigned char *) optarg, 16) ) {

				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++have_spid;
			break;
		case 'v':
			verbose= 1;
			break;
		case 'z':
			flag_stdio= 1;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc-= optind;
	if ( argc > 1 ) usage();

	/* Remaining argument is host[:port] */

	if ( flag_stdio && argc ) usage();
	else if ( !flag_stdio && ! argc ) {
		// Default to localhost
		config.server= strdup("localhost");
		if ( config.server == NULL ) {
			perror("malloc");
			return 1;
		}
	} else if ( argc ) {
		char *cp;

		config.server= strdup(argv[optind]);
		if ( config.server == NULL ) {
			perror("malloc");
			return 1;
		}
		
		/* If there's a : then we have a port, too */
		cp= strchr(config.server, ':');
		if ( cp != NULL ) {
			*cp++= '\0';
			config.port= cp;
		}
	}

	if ( ! have_spid && config.mode != MODE_EPID ) {
		fprintf(stderr, "SPID required. Use one of --spid or --spid-file \n");
		return 1;
	}

	/* Can we run SGX? */

#ifndef SGX_HW_SIM
	sgx_support = get_sgx_support();
	if (sgx_support & SGX_SUPPORT_NO) {
		fprintf(stderr, "This system does not support Intel SGX.\n");
		return 1;
	} else {
		if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
			fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
			return 1;
		}
		else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
			fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
			return 1;
		}
		else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
			fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
			fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
			return 1;
		}
	} 
#endif

	/* Launch the enclave */

#ifdef _WIN32
	status = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG,
		&token, &updated, &eid, 0);
	if (status != SGX_SUCCESS) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		return 1;
	}
#else
	status = sgx_create_enclave_search(ENCLAVE_NAME,
		SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) 
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	}
#endif

	/* Are we attesting, or just spitting out a quote? */

	if ( config.mode == MODE_ATTEST ) {
		do_attestation(eid, &config);
	} else if ( config.mode == MODE_EPID || config.mode == MODE_QUOTE ) {
		//do_quote(eid, &config);
		printf("hello");
	} else {
		fprintf(stderr, "Unknown operation mode.\n");
		return 1;
	}

     
	close_logfile(fplog);

	return 0;
}

int do_attestation (sgx_enclave_id_t eid, config_t *config)
{

	sgx_status_t status, sgxrv, pse_status;
	sgx_ra_msg1_t msg1;
	sgx_ra_msg2_t *msg2 = NULL;
	sgx_ra_msg3_t *msg3 = NULL;
	ra_msg4_t *msg4 = NULL;
	uint32_t msg0_extended_epid_group_id = 0;
	uint32_t msg3_sz;
	uint32_t flags= config->flags;
	sgx_ra_context_t ra_ctx= 0xdeadbeef;
	int rv;
	MsgIO *msgio;
	size_t msg4sz = 0;
	int enclaveTrusted = NotTrusted; // Not Trusted
	int b_pse= OPT_ISSET(flags, OPT_PSE);


	if ( config->server == NULL ) {
		msgio = new MsgIO();
	} else {
		try {
			msgio = new MsgIO(config->server, (config->port == NULL) ?
				DEFAULT_PORT : config->port);
		}
		catch(...) {
			exit(1);
		}
	}

	/*
	 * WARNING! Normally, the public key would be hardcoded into the
	 * enclave, not passed in as a parameter. Hardcoding prevents
	 * the enclave using an unauthorized key.
	 *
	 * This is diagnostic/test application, however, so we have
	 * the flexibility of a dynamically assigned key.
	 */

	/* Executes an ECALL that runs sgx_ra_init() */

	if ( OPT_ISSET(flags, OPT_PUBKEY) ) {
		if ( debug ) fprintf(stderr, "+++ using supplied public key\n");
		status= enclave_ra_init(eid, &sgxrv, config->pubkey, b_pse,
			&ra_ctx, &pse_status);
	} else {
		if ( debug ) fprintf(stderr, "+++ using default public key\n");
		status= enclave_ra_init_def(eid, &sgxrv, b_pse, &ra_ctx,
			&pse_status);
	}

	/* Did the ECALL succeed? */
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "enclave_ra_init: %08x\n", status);
		delete msgio;
		return 1;
	}

#ifdef _WIN32
	/* If we asked for a PSE session, did that succeed? */
	if (b_pse) {
		if ( pse_status != SGX_SUCCESS ) {
			fprintf(stderr, "pse_session: %08x\n", pse_status);
			delete msgio;
			return 1;
		}
	}
#endif

	/* Did sgx_ra_init() succeed? */
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_ra_init: %08x\n", sgxrv);
		delete msgio;
		return 1;
	}

	/* Generate msg0 */

	status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx); 
		fprintf(stderr, "sgx_get_extended_epid_group_id: %08x\n", status);
		delete msgio;
		return 1;
	}
	if ( verbose ) {
		dividerWithText(stderr, "Msg0 Details");
		dividerWithText(fplog, "Msg0 Details");
		fprintf(stderr,   "Extended Epid Group ID: ");
		fprintf(fplog,   "Extended Epid Group ID: ");
		print_hexstring(stderr, &msg0_extended_epid_group_id,
			 sizeof(uint32_t));
		print_hexstring(fplog, &msg0_extended_epid_group_id,
			 sizeof(uint32_t));
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}
 
	/* Generate msg1 */

	status= sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
		fprintf(fplog, "sgx_ra_get_msg1: %08x\n", status);
		delete msgio;
		return 1;
	}

	if ( verbose ) {
		dividerWithText(stderr,"Msg1 Details");
		dividerWithText(fplog,"Msg1 Details");
		fprintf(stderr,   "msg1.g_a.gx = ");
		fprintf(fplog,   "msg1.g_a.gx = ");
		print_hexstring(stderr, msg1.g_a.gx, 32);
		print_hexstring(fplog, msg1.g_a.gx, 32);
		fprintf(stderr, "\nmsg1.g_a.gy = ");
		fprintf(fplog, "\nmsg1.g_a.gy = ");
		print_hexstring(stderr, msg1.g_a.gy, 32);
		print_hexstring(fplog, msg1.g_a.gy, 32);
		fprintf(stderr, "\nmsg1.gid    = ");
		fprintf(fplog, "\nmsg1.gid    = ");
		print_hexstring(stderr, msg1.gid, 4);
		print_hexstring(fplog, msg1.gid, 4);
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	/*
	 * Send msg0 and msg1 concatenated together (msg0||msg1). We do
	 * this for efficiency, to eliminate an additional round-trip
	 * between client and server. The assumption here is that most
	 * clients have the correct extended_epid_group_id so it's
	 * a waste to send msg0 separately when the probability of a
	 * rejection is astronomically small.
	 *
	 * If it /is/ rejected, then the client has only wasted a tiny
	 * amount of time generating keys that won't be used.
	 */

	dividerWithText(fplog, "Msg0||Msg1 ==> SP");
	fsend_msg_partial(fplog, &msg0_extended_epid_group_id,
		sizeof(msg0_extended_epid_group_id));
	fsend_msg(fplog, &msg1, sizeof(msg1));
	divider(fplog);

	dividerWithText(stderr, "Copy/Paste Msg0||Msg1 Below to SP");
	msgio->send_partial(&msg0_extended_epid_group_id,
		sizeof(msg0_extended_epid_group_id));
	msgio->send(&msg1, sizeof(msg1));
	divider(stderr);

	fprintf(stderr, "Waiting for msg2\n");

	/*
	generate publickey and seal private key
	*/

	const char *opt_enclave_path = NULL;
    const char *opt_statefile = NULL;
    const char *opt_public_key_file = NULL;
	opt_enclave_path = "./Enclave/Enclave.signed.so";
    opt_statefile = "./demo_sgx/sealeddata.bin";
    opt_public_key_file = "./demo_sgx/pub.pem";
	enclave_get_buffer_sizes(eid);
	allocate_buffers();
	enclave_generate_key(eid);
	save_enclave_state(opt_statefile);
	save_public_key(opt_public_key_file);

	/* Read msg2 
	 *
	 * msg2 is variable length b/c it includes the revocation list at
	 * the end. msg2 is malloc'd in readZ_msg do free it when done.
	 */

	rv= msgio->read((void **) &msg2, NULL);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg2\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg2\n");
		delete msgio;
		exit(1);
	}
	

	if ( verbose ) {
		dividerWithText(stderr, "Msg2 Details");
		dividerWithText(fplog, "Msg2 Details (Received from SP)");
		fprintf(stderr,   "msg2.g_b.gx      = ");
		fprintf(fplog,   "msg2.g_b.gx      = ");
		print_hexstring(stderr, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		print_hexstring(fplog, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		fprintf(stderr, "\nmsg2.g_b.gy      = ");
		fprintf(fplog, "\nmsg2.g_b.gy      = ");
		print_hexstring(stderr, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		print_hexstring(fplog, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		fprintf(stderr, "\nmsg2.spid        = ");
		fprintf(fplog, "\nmsg2.spid        = ");
		print_hexstring(stderr, &msg2->spid, sizeof(msg2->spid));
		print_hexstring(fplog, &msg2->spid, sizeof(msg2->spid));
		fprintf(stderr, "\nmsg2.quote_type  = ");
		fprintf(fplog, "\nmsg2.quote_type  = ");
		print_hexstring(stderr, &msg2->quote_type, sizeof(msg2->quote_type));
		print_hexstring(fplog, &msg2->quote_type, sizeof(msg2->quote_type));
		fprintf(stderr, "\nmsg2.kdf_id      = ");
		fprintf(fplog, "\nmsg2.kdf_id      = ");
		print_hexstring(stderr, &msg2->kdf_id, sizeof(msg2->kdf_id));
		print_hexstring(fplog, &msg2->kdf_id, sizeof(msg2->kdf_id));
		fprintf(stderr, "\nmsg2.sign_ga_gb  = ");
		fprintf(fplog, "\nmsg2.sign_ga_gb  = ");
		print_hexstring(stderr, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		print_hexstring(fplog, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		fprintf(stderr, "\nmsg2.mac         = ");
		fprintf(fplog, "\nmsg2.mac         = ");
		print_hexstring(stderr, &msg2->mac, sizeof(msg2->mac));
		print_hexstring(fplog, &msg2->mac, sizeof(msg2->mac));
		fprintf(stderr, "\nmsg2.sig_rl_size = ");
		fprintf(fplog, "\nmsg2.sig_rl_size = ");
		print_hexstring(stderr, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		print_hexstring(fplog, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		fprintf(stderr, "\nmsg2.sig_rl      = ");
		fprintf(fplog, "\nmsg2.sig_rl      = ");
		print_hexstring(stderr, &msg2->sig_rl, msg2->sig_rl_size);
		print_hexstring(fplog, &msg2->sig_rl, msg2->sig_rl_size);
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	if ( debug ) {
		fprintf(stderr, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
		fprintf(fplog, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
	}

	/* Process Msg2, Get Msg3  */
	/* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

	msg3 = NULL;

	//status = sgx_ra_proc_msg2(ra_ctx, eid,
	//	sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, 
	//	sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
	//    &msg3, &msg3_sz);
	status = SGX_SUCCESS;

	int msg3_status;
	//msg3_status = do_quote(eid, config, &msg3, &msg3_sz, ra_ctx, msg2,sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted);
	status = gen_msg3(ra_ctx, eid,sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,&msg3, &msg3_sz,config);
	free(msg2);
	

	//*msg3->quote = &newquote;

	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);
		fprintf(fplog, "sgx_ra_proc_msg2: %08x\n", status);

		delete msgio;
		return 1;
	} 

	if ( debug ) {
		fprintf(stderr, "+++ msg3_size = %u\n", msg3_sz);
		fprintf(fplog, "+++ msg3_size = %u\n", msg3_sz);
	}
	                          
	if ( verbose ) {
		dividerWithText(stderr, "Msg3 Details");
		dividerWithText(fplog, "Msg3 Details");
		fprintf(stderr,   "msg3.mac         = ");
		fprintf(fplog,   "msg3.mac         = ");
		print_hexstring(stderr, msg3->mac, sizeof(msg3->mac));
		print_hexstring(fplog, msg3->mac, sizeof(msg3->mac));
		fprintf(stderr, "\nmsg3.g_a.gx      = ");
		fprintf(fplog, "\nmsg3.g_a.gx      = ");
		print_hexstring(stderr, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		print_hexstring(fplog, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		fprintf(stderr, "\nmsg3.g_a.gy      = ");
		fprintf(fplog, "\nmsg3.g_a.gy      = ");
		print_hexstring(stderr, msg3->g_a.gy, sizeof(msg3->g_a.gy));
		print_hexstring(fplog, msg3->g_a.gy, sizeof(msg3->g_a.gy));
#ifdef _WIN32
		fprintf(stderr, "\nmsg3.ps_sec_prop.sgx_ps_sec_prop_desc = ");
		fprintf(fplog, "\nmsg3.ps_sec_prop.sgx_ps_sec_prop_desc = ");
		print_hexstring(stderr, msg3->ps_sec_prop.sgx_ps_sec_prop_desc,
			sizeof(msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
		print_hexstring(fplog, msg3->ps_sec_prop.sgx_ps_sec_prop_desc,
			sizeof(msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
		fprintf(fplog, "\n");
#endif
		fprintf(stderr, "\nmsg3.quote       = ");
		fprintf(fplog, "\nmsg3.quote       = ");
		print_hexstring(stderr, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		print_hexstring(fplog, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		fprintf(fplog, "\n");
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	dividerWithText(stderr, "Copy/Paste Msg3 Below to SP");
	msgio->send(msg3, msg3_sz);
	divider(stderr);

	dividerWithText(fplog, "Msg3 ==> SP");
	fsend_msg(fplog, msg3, msg3_sz);
	divider(fplog);

	if ( msg3 ) {
		free(msg3);
		msg3 = NULL;
	}
 
	/* Read Msg4 provided by Service Provider, then process */
        
	rv= msgio->read((void **)&msg4, &msg4sz);
	/*printf("%s\n", msg4->info);
	 secret_info_t tmp = msg4->secret;
	 //eprintf("secret    = %s\n",
	//	 hexstring(&msg4->secret, sizeof(tmp)));
	// const char* a = hexstring(&msg4->secret, sizeof(msg4->secret));

	 char* str = HexArrayToString(hexstring(&msg4->secret, sizeof(msg4->secret)), 100);
	 int i = 0;
	 while (str[i] != '\0') {
		 printf("%c", str[i]);
		 i = i + 1;
	 }
	 printf("%c", str[0]);
	
	*/
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg4\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg4\n");
		delete msgio;
		exit(1);
	}

	//edividerWithText("Enclave Trust Status from Service Provider");
	//printf("%s",msg4->secret);
	//enclaveTrusted= msg4->status;

	enclaveTrusted = Trusted;
	if ( enclaveTrusted == Trusted ) {
		eprintf("Enclave TRUSTED\n");
	}
	else if ( enclaveTrusted == NotTrusted ) {
		eprintf("Enclave NOT TRUSTED\n");
	}
	else if ( enclaveTrusted == Trusted_ItsComplicated ) {
		// Trusted, but client may be untrusted in the future unless it
		// takes action.

		eprintf("Enclave Trust is TRUSTED and COMPLICATED. The client is out of date and\nmay not be trusted in the future depending on the service provider's  policy.\n");
	} else {
		// Not Trusted, but client may be able to take action to become
		// trusted.

		eprintf("Enclave Trust is NOT TRUSTED and COMPLICATED. The client is out of date.\n");
	}

	/* check to see if we have a PIB by comparing to empty PIB */
	sgx_platform_info_t emptyPIB;
	memset(&emptyPIB, 0, sizeof (sgx_platform_info_t));

	int retPibCmp = memcmp(&emptyPIB, (void *)(&msg4->platformInfoBlob), sizeof (sgx_platform_info_t));

	if (retPibCmp == 0 ) {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
	} else {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

		if ( debug )  {
			eprintf("+++ PIB: " );
			print_hexstring(stderr, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
			print_hexstring(fplog, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
			eprintf("\n");
		}

		/* We have a PIB, so check to see if there are actions to take */
		sgx_update_info_bit_t update_info;
		sgx_status_t ret = sgx_report_attestation_status(&msg4->platformInfoBlob, 
			enclaveTrusted, &update_info);

		if ( debug )  eprintf("+++ sgx_report_attestation_status ret = 0x%04x\n", ret);

		edivider();

		/* Check to see if there is an update needed */
		if ( ret == SGX_ERROR_UPDATE_NEEDED ) {

			edividerWithText("Platform Update Required");
			eprintf("The following Platform Update(s) are required to bring this\n");
			eprintf("platform's Trusted Computing Base (TCB) back into compliance:\n\n");
			if( update_info.pswUpdate ) {
				eprintf("  * Intel SGX Platform Software needs to be updated to the latest version.\n");
			}

			if( update_info.csmeFwUpdate ) {
				eprintf("  * The Intel Management Engine Firmware Needs to be Updated.  Contact your\n");
				eprintf("    OEM for a BIOS Update.\n");
			}

			if( update_info.ucodeUpdate )  {
				eprintf("  * The CPU Microcode needs to be updated.  Contact your OEM for a platform\n");
				eprintf("    BIOS Update.\n");
			}                                           
			eprintf("\n");
			edivider();      
		}
	}

	/*
	 * If the enclave is trusted, fetch a hash of the the MK and SK from
	 * the enclave to show proof of a shared secret with the service 
	 * provider.
	 */

	if ( enclaveTrusted == Trusted ) {
		sgx_status_t key_status, sha_status;
		sgx_sha256_hash_t mkhash, skhash;

		// First the MK

		if ( debug ) eprintf("+++ fetching SHA256(MK)\n");
		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_MK, &mkhash);
		if ( debug ) eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
			status);

		if ( debug ) eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
		// Then the SK

		if ( debug ) eprintf("+++ fetching SHA256(SK)\n");
		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_SK, &skhash);
		if ( debug ) eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
			status);

		if ( debug ) eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
		if ( verbose ) {
			eprintf("SHA256(MK) = ");
			print_hexstring(stderr, mkhash, sizeof(mkhash));
			print_hexstring(fplog, mkhash, sizeof(mkhash));
			eprintf("\n");
			eprintf("SHA256(SK) = ");
			print_hexstring(stderr, skhash, sizeof(skhash));
			print_hexstring(fplog, skhash, sizeof(skhash));
			eprintf("\n");
		}
	}


	free (msg4);

	enclave_ra_close(eid, &sgxrv, ra_ctx);
	delete msgio;

	return 0;
}




/*----------------------------------------------------------------------
 * do_quote()
 *
 * Generate a quote from the enclave.
 *----------------------------------------------------------------------
 * WARNING!
 *
 * DO NOT USE THIS SUBROUTINE AS A TEMPLATE FOR IMPLEMENTING REMOTE
 * ATTESTATION. do_quote() short-circuits the RA process in order 
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation: 
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_calc_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 *----------------------------------------------------------------------
 */


int do_quote(sgx_enclave_id_t eid, config_t *config, sgx_ra_msg3_t **pp_msg3, uint32_t *p_msg3_size, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, sgx_ecall_proc_msg2_trusted_t p_proc_msg2,
	sgx_ecall_get_msg3_trusted_t p_get_msg3)
{
	sgx_status_t status, sgxrv;
	sgx_quote_t *quote;
	sgx_report_t report;
	sgx_report_t qe_report;
	sgx_target_info_t target_info;
	sgx_epid_group_id_t epid_gid;
	uint32_t sz= 0;
	uint32_t flags= config->flags;
	sgx_quote_sign_type_t linkable= SGX_UNLINKABLE_SIGNATURE;
#ifdef _WIN32
	sgx_ps_cap_t ps_cap;
	char *pse_manifest = NULL;
	size_t pse_manifest_sz;
	LPTSTR b64quote = NULL;
	DWORD sz_b64quote = 0;
	LPTSTR b64manifest = NULL;
	DWORD sz_b64manifest = 0;
#else
	char  *b64quote= NULL;
	char *b64manifest = NULL;
#endif

 	if (OPT_ISSET(flags, OPT_LINK)) linkable= SGX_LINKABLE_SIGNATURE;

	/* Platform services info. Win32 only. */
#ifdef _WIN32
	if (OPT_ISSET(flags, OPT_PSE)) {
		status = get_pse_manifest_size(eid, &pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest_size: %08x\n",
				status);
			return 1;
		}

		pse_manifest = (char *) malloc(pse_manifest_sz);

		status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest: %08x\n",
				status);
			return 1;
		}
		if (sgxrv != SGX_SUCCESS) {
			fprintf(stderr, "get_sec_prop_desc_ex: %08x\n",
				sgxrv);
			return 1;
		}
	}
#endif

	/* Get our quote */

	memset(&report, 0, sizeof(report));

	status= sgx_init_quote(&target_info, &epid_gid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_init_quote: %08x\n", status);
		return 1;
	}

	/* Did they ask for just the EPID? */
	if ( config->mode == MODE_EPID ) {
		printf("%08x\n", *(uint32_t *)epid_gid);
		exit(0);
	}
	sgx_report_data_t rdata;
	status= get_report(eid, &sgxrv, &report, &target_info,&rdata);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "get_report: %08x\n", status);
		return 1;
	}
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_report: %08x\n", sgxrv);
		return 1;
	}

	// sgx_get_quote_size() has been deprecated, but our PSW may be too old
	// so use a wrapper function.

	if (! get_quote_size(&status, &sz)) {
		fprintf(stderr, "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
		return 1;
	}
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "SGX error while getting quote size: %08x\n", status);
		return 1;
	}

	quote= (sgx_quote_t *) malloc(sz);
	if ( quote == NULL ) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}
	sgx_status_t st;
	//sgx_target_info_t qe_target_info;
	//p_proc_msg2(eid, &st, context, p_msg2, &target_info,
	//	&report, &config->nonce);

	memset(quote, 0, sz);
	status= sgx_get_quote(&report, linkable, &config->spid,
		(OPT_ISSET(flags, OPT_NONCE)) ? &config->nonce : NULL,
		NULL, 0,
		(OPT_ISSET(flags, OPT_NONCE)) ? &qe_report : NULL, 
		quote, sz);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_get_quote: %08x\n", status);
		return 0;
	}
	uint32_t msg3_size = static_cast<uint32_t>(sizeof(sgx_ra_msg3_t)) + sz;
	sgx_ra_msg3_t* p_msg3 = NULL;
	p_msg3 = (sgx_ra_msg3_t*)malloc(msg3_size);
	
	//sgx_quote_nonce_t nonce;
	//sgx_report_t qe_report;
	

	//memset(&nonce, 0, sizeof(nonce));
	//memset(&qe_report, 0, sizeof(qe_report));
	
	
	p_get_msg3(eid, &st, context, sz, &qe_report, p_msg3, msg3_size);
	*pp_msg3 = p_msg3;
	*p_msg3_size = msg3_size;
	/* Print our quote */

#ifdef _WIN32
	// We could also just do ((4 * sz / 3) + 3) & ~3
	// but it's cleaner to use the API.

	if (CryptBinaryToString((BYTE *) quote, sz, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, NULL, &sz_b64quote) == FALSE) {
		fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		return 0;
	}

	b64quote = (LPTSTR)(malloc(sz_b64quote));
	if (b64quote == NULL) {
		perror("malloc");
		return 0;
	}
	if (CryptBinaryToString((BYTE *) quote, sz, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, b64quote, &sz_b64quote) == FALSE) {
		fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		return 0;
	}

	if (OPT_ISSET(flags, OPT_PSE)) {
		if (CryptBinaryToString((BYTE *)pse_manifest, (uint32_t)(pse_manifest_sz), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &sz_b64manifest) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
			return 0;
		}

		b64manifest = (LPTSTR)(malloc(sz_b64manifest));
		if (b64manifest == NULL) {
			free(b64quote);
			perror("malloc");
			return 0;
		}

		if (CryptBinaryToString((BYTE *)pse_manifest, (uint32_t)(pse_manifest_sz), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64manifest, &sz_b64manifest) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
			return 0;#include <sgx_tcrypto.h>
#include <sgx_utils.h>
#include <sgx_tseal.h>
	}

#else
	b64quote= base64_encode((char *) quote, sz);
	if ( b64quote == NULL ) {
		eprintf("Could not base64 encode quote\n");
		return 1;
	}
#endif

	printf("{\n");
	printf("\"isvEnclaveQuotehahahhahhhahah\":\"%s\"", b64quote);
	if ( OPT_ISSET(flags, OPT_NONCE) ) {
		printf(",\n\"nonce\":\"");
		print_hexstring(stdout, &config->nonce, 16);
		printf("\"");
	}



#ifdef _WIN32
	if (OPT_ISSET(flags, OPT_PSE)) {
		printf(",\n\"pseManifest\":\"%s\"", b64manifest);	
	}
#endif
	printf("\n}\n");

#ifdef SGX_HW_SIM
	fprintf(stderr, "WARNING! Built in h/w simulation mode. This quote will not be verifiable.\n");
#endif

	free(b64quote);
#ifdef _WIN32
	if ( b64manifest != NULL ) free(b64manifest);
#endif

	return 1;

}

bool enclave_get_buffer_sizes(sgx_enclave_id_t eid)
{
    sgx_status_t ecall_retval = SGX_SUCCESS;

    printf("[GatewayApp]: Querying enclave for buffer sizes\n");

    /*
    * Invoke ECALL, 'ecall_calc_buffer_sizes()', to calculate the sizes of buffers needed for the untrusted app to store
    * data (public key, sealed private key and signature) from the enclave.
    */
    sgx_lasterr = ecall_calc_buffer_sizes(eid,
                                          &ecall_retval,
                                          &public_key_buffer_size,
                                          &sealed_data_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS &&
        (ecall_retval != 0))
    {
        fprintf(stderr, "[GatewayApp]: ERROR: ecall_calc_buffer_sizes returned %d\n", ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}

bool allocate_buffers()
{
    printf("[GatewayApp]: Allocating buffers\n");
    sealed_data_buffer = calloc(sealed_data_buffer_size, 1);
    public_key_buffer = calloc(public_key_buffer_size, 1);
    encrypted_aes_buffer_size = 256;
    encrypted_aes_buffer = calloc(encrypted_aes_buffer_size, 1);
    if (sealed_data_buffer == NULL || public_key_buffer == NULL || encrypted_aes_buffer == NULL)
    {
        fprintf(stderr, "[GatewayApp]: allocate_buffers() memory allocation failure\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}



bool enclave_generate_key(sgx_enclave_id_t eid)
{
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

    printf("[GatewayApp]: Calling enclave to generate key material\n");

    /*
    * Invoke ECALL, 'ecall_key_gen_and_seal()', to generate a keypair and seal it to the enclave.
    */
    sgx_lasterr = ecall_key_gen_and_seal(eid,
                                         &ecall_retval,
                                         (char *)public_key_buffer,
                                         public_key_buffer_size,
                                         (char *)sealed_data_buffer,
                                         sealed_data_buffer_size);

	printf("[GatewayApp]: generate rsa key success\n");
    if (sgx_lasterr == SGX_SUCCESS &&
        (ecall_retval != SGX_SUCCESS))
    {
        fprintf(stderr, "[GatewayApp]: ERROR: ecall_key_gen_and_seal returned %d\n", ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}

bool save_enclave_state(const char *const statefile)
{
    bool ret_status = true;

    printf("[GatewayApp]: Saving enclave state\n");

    FILE *file = open_file(statefile, "wb");

    if (file == NULL)
    {
        fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

	//printf("%d",sealed_data_buffer_size);
    if (fwrite(sealed_data_buffer, sealed_data_buffer_size, 1, file) != 1)
    {
        fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }

    fclose(file);

    return ret_status;
}

FILE* open_file(const char* const filename, const char* const mode)
{
    return fopen(filename, mode);
}

bool save_public_key(const char *const public_key_file)
{
    bool ret_status = true;
    uint8_t le_e[4]={0x01,0x00,0x01,0x00};
    EVP_PKEY *rsa_key = NULL;
    RSA *rsa_ctx = NULL;
    BIGNUM* n = NULL;
    BIGNUM* e = NULL;
    //BIO *bp = NULL;

    e = BN_lebin2bn(le_e, 4, e);

    uint8_t copied_bytes[public_key_buffer_size];
    for (size_t i = 0 ; i < public_key_buffer_size ; ++i)
    {
	copied_bytes[i] = ((uint8_t *)public_key_buffer)[i];
    }
	/*
	printf("this is copied bytes\n");
	for (int j = 0; j < public_key_buffer_size; ++j)
	{
		printf("%c",copied_bytes[j]);
	}
	*/
	//printf(copied_bytes);

    n= BN_lebin2bn(copied_bytes, public_key_buffer_size, n);
    rsa_ctx = RSA_new();
    rsa_key = EVP_PKEY_new();

    if (rsa_ctx == NULL || rsa_key == NULL || !EVP_PKEY_assign_RSA(rsa_key, rsa_ctx))
    {
        RSA_free(rsa_ctx);
        rsa_ctx = NULL;
        ret_status=false;
		printf("error");
        //goto cleanup;
    }
	/*
	printf("[GatewayApp]: this is n\n");
	char* hexn = BN_bn2hex(n);
	int t = 0;
	while (hexn[t] != '\0') {
		printf("%c", hexn[t]);
		t = t + 1;
	}
	printf("\n");
	printf("[GatewayApp]: this is e\n");
	t = 0;
	char* hexe = BN_bn2hex(e);
	while (hexe[t] != '\0') {
		printf("%c", hexe[t]);
		t = t + 1;
	}
	*/

    if (!RSA_set0_key(rsa_ctx, n, e, NULL))
    {
        ret_status=false;
		printf("error");
        //goto cleanup;
    }

    printf("[GatewayApp]: Saving public key\n");

	

	BIO *out;
	out = BIO_new_file(public_key_file,"wb");
    int ret = PEM_write_bio_RSAPublicKey(out, rsa_ctx);
    //printf("writepub:%d\n",ret);
    BIO_flush(out);
    BIO_free(out);
	return ret_status;
	//printf(n);

	/*
	if((bp = BIO_new(BIO_s_file())) == NULL)
	{
		printf("[GatewayApp]: generate_key bio file new error!\n");
        ret_status = false;
        goto cleanup;
	}
	/*
	if(BIO_write_filename(bp, public_key_file) <= 0)
	{
		printf("[GatewayApp]: BIO_write_filename error!\n");
        ret_status = false;
        goto cleanup;
	}
	
	if(PEM_write_bio_RSAPublicKey(bp, rsa_ctx) != 1)
	{
		printf("[GatewayApp]: PEM_write_bio_RSAPublicKey error!\n");
        ret_status = false;
        goto cleanup;
	}
	
	

	cleanup:
    if(!ret_status)sgx_lasterr = SGX_ERROR_UNEXPECTED;
    if(bp)BIO_free_all(bp);
    if(rsa_key)EVP_PKEY_free(rsa_key);
    if(n)BN_clear_free(n);
    if(e)BN_clear_free(e);

    return ret_status;
	*/
}


















#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

sgx_status_t gen_msg3(
	sgx_ra_context_t context,
	sgx_enclave_id_t eid,
	sgx_ecall_proc_msg2_trusted_t p_proc_msg2,
	sgx_ecall_get_msg3_trusted_t p_get_msg3,
	const sgx_ra_msg2_t* p_msg2,
	uint32_t msg2_size,
	sgx_ra_msg3_t** pp_msg3,
	uint32_t* p_msg3_size, config_t* config)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	sgx_report_t report;
	sgx_ra_msg3_t* p_msg3 = NULL;
	sgx_att_key_id_t empty_att_key_id;
	sgx_epid_group_id_t epid_gid;

	memset(&report, 0, sizeof(report));
	memset(&empty_att_key_id, 0, sizeof(empty_att_key_id));
	
	{
		sgx_quote_nonce_t nonce;
		sgx_report_t qe_report;
		sgx_target_info_t qe_target_info;

		memset(&nonce, 0, sizeof(nonce));
		memset(&qe_report, 0, sizeof(qe_report));

		sgx_status_t status;
		sgx_init_quote(&qe_target_info, &epid_gid);
		
		ret = p_proc_msg2(eid, &status, context, p_msg2, &qe_target_info,
			&report, &nonce);
	
		sgx_report_t newreport;
		sgx_report_data_t rdata;
		memset(&rdata, 0, sizeof(sgx_report_data_t));
		string s = "sjtu public key: abcdefgh";
		int i;
		for (i = 0; i < s.length(); i++) {
			rdata.d[i] = s[i];
		}
		status = get_report(eid, &ret, &newreport, &qe_target_info,&rdata);
		/*
		sgx_report_body_t* r = (sgx_report_body_t*)&newreport.body;
		sgx_report_data_t rdata;
		rdata.d[0] = 'a' ;
		r->report_data = rdata;
		printf("add report data");
		eprintf("report_data = %s\n",
			hexstring(&r->report_data, sizeof(sgx_report_data_t)));
		*/
		
		
		//here
		
		if (SGX_SUCCESS != ret)
		{
			goto CLEANUP;
		}
		if (SGX_SUCCESS != status)
		{
			ret = status;
			goto CLEANUP;
		}

		uint32_t quote_size = 0;
		ret = sgx_calc_quote_size(p_msg2->sig_rl_size ?
			const_cast<uint8_t*>(p_msg2->sig_rl) : NULL,
			p_msg2->sig_rl_size,
			&quote_size);
		if (SGX_SUCCESS != ret)
		{
			goto CLEANUP;
		}

		//check integer overflow of quote_size
		if (UINT32_MAX - quote_size < sizeof(sgx_ra_msg3_t))
		{
			ret = SGX_ERROR_UNEXPECTED;
			goto CLEANUP;
		}
		uint32_t msg3_size = static_cast<uint32_t>(sizeof(sgx_ra_msg3_t)) + quote_size;
		p_msg3 = (sgx_ra_msg3_t*)malloc(msg3_size);
		if (!p_msg3)
		{
			ret = SGX_ERROR_OUT_OF_MEMORY;
			goto CLEANUP;
		}
		memset(p_msg3, 0, msg3_size);
		/*
		ret = sgx_get_quote(&report,
			p_msg2->quote_type == SGX_UNLINKABLE_SIGNATURE ?
			SGX_UNLINKABLE_SIGNATURE : SGX_LINKABLE_SIGNATURE,
			const_cast<sgx_spid_t*>(&p_msg2->spid),
			&nonce,
			p_msg2->sig_rl_size ?
			const_cast<uint8_t*>(p_msg2->sig_rl) : NULL,
			p_msg2->sig_rl_size,
			&qe_report,
			(sgx_quote_t*)p_msg3->quote,
			quote_size);
		*/	
		ret = sgx_get_quote(&newreport, p_msg2->quote_type == SGX_UNLINKABLE_SIGNATURE ?
			SGX_UNLINKABLE_SIGNATURE : SGX_LINKABLE_SIGNATURE, &config->spid,&nonce, 
			 NULL,0, &qe_report,
			(sgx_quote_t*)p_msg3->quote,
			quote_size); 
		//printf("get quote%d", ret);
		if (SGX_SUCCESS != ret)
		{
			goto CLEANUP;
		}
#ifdef _WIN32
		sgx_ps_cap_t ps_cap;
		char* pse_manifest = NULL;
		size_t pse_manifest_sz;
		LPTSTR b64quote = NULL;
		DWORD sz_b64quote = 0;
		LPTSTR b64manifest = NULL;
		DWORD sz_b64manifest = 0;
		uint32_t flags = config->flags;
		sgx_status_t  sgxrv;

		if (OPT_ISSET(flags, OPT_PSE)) {
			status = get_pse_manifest_size(eid, &pse_manifest_sz);
			if (status != SGX_SUCCESS) {
				fprintf(stderr, "get_pse_manifest_size: %08x\n",
					status);
			}

			pse_manifest = (char*)malloc(pse_manifest_sz);

			status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
			if (status != SGX_SUCCESS) {
				fprintf(stderr, "get_pse_manifest: %08x\n",
					status);
			}
			if (sgxrv != SGX_SUCCESS) {
				fprintf(stderr, "get_sec_prop_desc_ex: %08x\n",
					sgxrv);
			}
		}

		if (CryptBinaryToString((BYTE*)(sgx_quote_t*)p_msg3->quote, quote_size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &sz_b64quote) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		}

		b64quote = (LPTSTR)(malloc(sz_b64quote));
		if (b64quote == NULL) {
			perror("malloc");
		}
		if (CryptBinaryToString((BYTE*)(sgx_quote_t*)p_msg3->quote, quote_size, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64quote, &sz_b64quote) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		}

		if (OPT_ISSET(flags, OPT_PSE)) {
			if (CryptBinaryToString((BYTE*)pse_manifest, (uint32_t)(pse_manifest_sz), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &sz_b64manifest) == FALSE) {
				fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
			}

			b64manifest = (LPTSTR)(malloc(sz_b64manifest));
			if (b64manifest == NULL) {
				free(b64quote);
				perror("malloc");
				
			}

			if (CryptBinaryToString((BYTE*)pse_manifest, (uint32_t)(pse_manifest_sz), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64manifest, &sz_b64manifest) == FALSE) {
				fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
				
			}
		}
		printf("{\n");
		printf("\"isvEnclaveQuote\":\"%s\"", b64quote);


#else
		char* b64quote = NULL;
		char* b64manifest = NULL;
		b64quote = base64_encode((char*)(sgx_quote_t*)p_msg3->quote, quote_size);
		if (b64quote == NULL) {
			eprintf("Could not base64 encode quote\n");
		}
		printf("\"isvEnclaveQuote\":\"%s\"", b64quote);
#endif		
		ret = p_get_msg3(eid, &status, context, quote_size, &qe_report,
			p_msg3, msg3_size);
		
		*pp_msg3 = p_msg3;
		*p_msg3_size = msg3_size;
		
	}

CLEANUP:
	if (ret)
		SAFE_FREE(p_msg3);
	return ret;
}



/*
 * Search for the enclave file and then try and load it.
 */

#ifndef _WIN32
sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' ) 
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 )
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
		
	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, const char *search, char *fullpath, 
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len-1);
			rem= (len-1)-lp-1;
			fullpath[len-1]= 0;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}

#endif


void usage () 
{
	fprintf(stderr, "usage: client [ options ] [ host[:port] ]\n\n");
	fprintf(stderr, "Required:\n");
	fprintf(stderr, "  -N, --nonce-file=FILE    Set a nonce from a file containing a 32-byte\n");
	fprintf(stderr, "                             ASCII hex string\n");
	fprintf(stderr, "  -P, --pubkey-file=FILE   File containing the public key of the service\n");
	fprintf(stderr, "                             provider.\n");
	fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containing a 32-byte\n");
	fprintf(stderr, "                             ASCII hex string\n");
	fprintf(stderr, "  -d, --debug              Show debugging information\n");
	fprintf(stderr, "  -e, --epid-gid           Get the EPID Group ID instead of performing\n");
	fprintf(stderr, "                             an attestation.\n");
	fprintf(stderr, "  -l, --linkable           Specify a linkable quote (default: unlinkable)\n");
#ifdef _WIN32
	fprintf(stderr, "  -m, --pse-manifest       Include the PSE manifest in the quote\n");
#endif
	fprintf(stderr, "  -n, --nonce=HEXSTRING    Set a nonce from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -p, --pubkey=HEXSTRING   Specify the public key of the service provider\n");
	fprintf(stderr, "                             as an ASCII hex string instead of using the\n");
	fprintf(stderr, "                             default.\n");
	fprintf(stderr, "  -q                       Generate a quote instead of performing an\n");
	fprintf(stderr, "                             attestation.\n");
	fprintf(stderr, "  -r                       Generate a nonce using RDRAND\n");
	fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -v, --verbose            Print decoded RA messages to stderr\n");
	fprintf(stderr, "  -z                       Read from stdin and write to stdout instead\n");
	fprintf(stderr, "                             connecting to a server.\n");
	fprintf(stderr, "\nOne of --spid OR --spid-file is required for generating a quote or doing\nremote attestation.\n");
	exit(1);
}

