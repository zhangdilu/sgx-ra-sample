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

#ifndef _WIN32
#include "../config.h"
#endif
#include "Enclave_t.h"
#include <string.h>
#include <sgx_utils.h>
#ifdef _WIN32
#include <sgx_tae_service.h>
#endif
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>

#include <stdarg.h>
#include <stdio.h>

#include <sgx_tcrypto.h>
#include <sgx_tseal.h>


static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

sgx_status_t ecall_key_gen_and_seal(char *pubkey, size_t pubkey_size, char *sealedprivkey, size_t sealedprivkey_size)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  size_t byte_size = 256;
  size_t p_byte_size = byte_size/2;
  size_t e_byte_size = 4;
  unsigned char e[4] = {1, 0, 1};
  unsigned char *n =(unsigned char *)malloc(byte_size);
  unsigned char *d = (unsigned char *)malloc(byte_size);
  unsigned char *p = (unsigned char *)malloc(p_byte_size);
  unsigned char *q = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_dmp1 = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_dmq1 = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_iqmp = (unsigned char *)malloc(p_byte_size);
  uint8_t *p_private = (uint8_t *)malloc(5*p_byte_size);
  
  if ((ret = sgx_create_rsa_key_pair(byte_size, e_byte_size, n, d, e, p, q, p_dmp1, p_dmq1, p_iqmp)) != SGX_SUCCESS)
  {
    //print("\nTrustedApp: sgx_create_rsa_key_pair() failed !\n");
    goto cleanup;
  }
  memcpy(p_private,p,p_byte_size);
  memcpy(p_private+p_byte_size,q,p_byte_size);
  memcpy(p_private+p_byte_size*2,p_dmp1,p_byte_size);
  memcpy(p_private+p_byte_size*3,p_dmq1,p_byte_size);
  memcpy(p_private+p_byte_size*4,p_iqmp,p_byte_size);
  memcpy(pubkey,n,byte_size);
  
  //print("n:");printh(n,byte_size);
  //print("\nseal:");printh(p_private,p_byte_size*5);
  if (sealedprivkey_size >= sgx_calc_sealed_data_size(0U, p_byte_size*5))
  {
    if ((ret = sgx_seal_data(0U, NULL, p_byte_size*5, (uint8_t *)p_private, (uint32_t)sealedprivkey_size, (sgx_sealed_data_t *)sealedprivkey)) != SGX_SUCCESS)
    {

      //print("\nTrustedApp: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  }
  else
  {
    //print("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
	      
  //print("\nTrustedApp: Key pair generated and private key was sealed. Sent the public key and sealed private key back.\n");
  ret = SGX_SUCCESS;

cleanup:
free(n);free(d); free(p); free(q); free(p_dmp1); free(p_dmq1); free(p_iqmp);free(p_private);
return ret;
}

sgx_status_t ecall_calc_buffer_sizes(size_t* epubkey_size, size_t* esealedprivkey_size)
{
  size_t size=256;
  *epubkey_size = size;
  *esealedprivkey_size = sgx_calc_sealed_data_size(0U, 5*size/2);
  //print("\nTrustedApp: Sizes for public key, sealed private key successfully.\n");
  return SGX_SUCCESS;
}



sgx_status_t ecall_unseal_and_decrypt(uint8_t *msg, uint32_t msg_size, uint8_t *encrypted_key, uint32_t encrypted_key_size, char *sealed, size_t sealed_size)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  void *new_pri_key2=NULL;
  int byte_size = 256;
  size_t p_byte_size = byte_size/2;
  int e_byte_size = 4;
  unsigned char e[4] = {1, 0, 1};
  unsigned char *p = (unsigned char *)malloc(p_byte_size);
  unsigned char *q = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_dmp1 = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_dmq1 = (unsigned char *)malloc(p_byte_size);
  unsigned char *p_iqmp = (unsigned char *)malloc(p_byte_size);
  size_t aeskey_size=0;
  unsigned char *aeskey=NULL;
  size_t ctr_size=16;
  uint8_t *p_ctr=(uint8_t *)malloc(ctr_size);
  uint32_t text_size=msg_size-ctr_size;
  uint8_t *p_src=(uint8_t *)malloc(text_size);
  uint8_t *p_dst=(uint8_t *)malloc(text_size);


  //print("\nTrustedApp: Received sensor data and the sealed private key.\n");
  uint32_t unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);

  uint8_t *unsealed_data = (uint8_t *)malloc(unsealed_data_size);
  if (unsealed_data == NULL)
  {
    //printf("\nTrustedApp: malloc(unsealed_data_size) failed !\n");
    goto cleanup;
  }

  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL, unsealed_data, &unsealed_data_size)) != SGX_SUCCESS)
  {
    //printf("\nTrustedApp: sgx_unseal_data() failed !\n");
    goto cleanup;
  }

  memcpy(p,unsealed_data,p_byte_size);
  memcpy(q,unsealed_data+p_byte_size,p_byte_size);
  memcpy(p_dmp1,unsealed_data+p_byte_size*2,p_byte_size);
  memcpy(p_dmq1,unsealed_data+p_byte_size*3,p_byte_size);
  memcpy(p_iqmp,unsealed_data+p_byte_size*4,p_byte_size);
  if ((ret = sgx_create_rsa_priv2_key(byte_size, e_byte_size, e, p, q, p_dmp1, p_dmq1, p_iqmp, &new_pri_key2)) != SGX_SUCCESS)
  {
    //printf("\nTrustedApp: sgx_create_rsa_priv2_key() failed !\n");
    goto cleanup;
  }

  if ((ret = sgx_rsa_priv_decrypt_sha256(new_pri_key2, NULL, &aeskey_size,encrypted_key,encrypted_key_size)) != SGX_SUCCESS)
  {
    //printf("\nTrustedApp: sgx_rsa_priv_decrypt_sha256() failed !\n");
    goto cleanup;
  }
  aeskey=(unsigned char *)malloc(aeskey_size);
  if ((ret = sgx_rsa_priv_decrypt_sha256(new_pri_key2, aeskey, &aeskey_size,encrypted_key,encrypted_key_size)) != SGX_SUCCESS)
  {
    //printf("\nTrustedApp: sgx_rsa_priv_decrypt_sha256() failed !\n");
    goto cleanup;
  }

  /*print("p:");printh(p,p_byte_size);print("\n");
  print("p:");printh(p,p_byte_size);print("\n");
  print("q:");printh(q,p_byte_size);print("\n");
  print("e:");printh(e,4);print("\n");
  print("p_dmp1:");printh(p_dmp1,p_byte_size);print("\n");
  print("p_dmq1:");printh(p_dmq1,p_byte_size);print("\n");
  print("p_iqmp:");printh(p_iqmp,p_byte_size);print("\n");
  print("aeskey:");printh(aeskey,aeskey_size);print("\n");*/
  //print("aes_key:");print(aeskey);
  memcpy(p_ctr,msg,ctr_size);
  memcpy(p_src,msg+ctr_size,text_size);

  sgx_aes_ctr_decrypt((sgx_aes_gcm_128bit_key_t *)aeskey,p_src,text_size,p_ctr,128,p_dst);
  //print(p_dst);
  //printf("\nTrustedApp: Unsealed the sealed private key, decrypted sensor data with this private key.\n");
  ret = SGX_SUCCESS;

cleanup:
  if (unsealed_data != NULL)
  {
    memset_s(unsealed_data, unsealed_data_size, 0, unsealed_data_size);
    free(unsealed_data);
  }
  if (aeskey != NULL)
  {
    memset_s(aeskey, aeskey_size, 0, aeskey_size);
    free(aeskey);
  }
  memset_s(p_src, text_size, 0, text_size);free(p_src);
  memset_s(p_ctr, ctr_size, 0, ctr_size);free(p_ctr);
  memset_s(p_dst, text_size, 0, text_size);free(p_dst);
  memset_s(p, p_byte_size, 0, p_byte_size);free(p);
  memset_s(q, p_byte_size, 0, p_byte_size);free(q);
  memset_s(p_dmp1, p_byte_size, 0, p_byte_size);free(p_dmp1);
  memset_s(p_dmq1, p_byte_size, 0, p_byte_size);free(p_dmq1);
  memset_s(p_iqmp, p_byte_size, 0, p_byte_size);free(p_iqmp);
  if(new_pri_key2)sgx_free_rsa_key(new_pri_key2,SGX_RSA_PRIVATE_KEY,byte_size,e_byte_size);

return ret;
}


sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info, sgx_report_data_t *report_data)
{
#ifdef SGX_HW_SIM
	return sgx_create_report(NULL, NULL, report);
#else
	return sgx_create_report(target_info, report_data, report);
#endif
}

#ifdef _WIN32
size_t get_pse_manifest_size ()
{
	return sizeof(sgx_ps_sec_prop_desc_t);
}

sgx_status_t get_pse_manifest(char *buf, size_t sz)
{
	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
	int retries= PSE_RETRIES;

	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	if ( status != SGX_SUCCESS ) return status;

	memcpy(buf, &ps_sec_prop_desc, sizeof(ps_sec_prop_desc));

	sgx_close_pse_session();

	return status;
}
#endif

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

#ifdef _WIN32
	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	ra_status= sgx_ra_init(&key, b_pse, ctx);

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_close_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}
#else
	ra_status= sgx_ra_init(&key, 0, ctx);
#endif

	return ra_status;
}

sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t *ctx,
	sgx_status_t *pse_status)
{
	return enclave_ra_init(def_service_public_key, b_pse, ctx, pse_status);
}

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	/* Now generate a SHA hash */

	sha_ret= sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); // Sigh.

	/* Let's be thorough */

	memset(k, 0, sizeof(k));

	return sha_ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}

