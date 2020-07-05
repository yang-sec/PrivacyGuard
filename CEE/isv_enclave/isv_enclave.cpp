/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <assert.h>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "string.h"
#include "isv_enclave_t.h"  /* print_string */

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <cstring>
#include <string>
#include <cmath>

#include "ipp/ippcpdefs.h"
#include "ipp/ippcp.h"
// #include "libcxx/cstdlib"

#include <stdint.h>
#include "ethers.h"
#include "types.h"
#include "uECC.h"
#include "mbusafecrt.h"

#include "enclave_utilities.h"
#include "secp256k1.h"
#include "svm.h"
#include "fann.h"
#include "keccak.h"

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
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

// To store the sk_keys for DC and iDA/DB
sgx_ec_key_128bit_t sk_key_DC;
sgx_ec_key_128bit_t sk_key_DO;

// To store the secrets provisioned by DC and iDA
uint8_t g_secret_DC[32];
// uint8_t g_secret_DO[16];

// To store the data encryption key for every DO
int num_DOs_here;
sgx_aes_gcm_128bit_key_t *DO_data_key;

// To store result hash
uint8_t K_result[16];
std::string K_result_hash;
std::string C_result_hash;


// For test data enc/dec
// uint8_t data_key[16] = {0x87, 0xA6, 0x0B, 0x39, 0xD5, 0x26, 0xAB, 0x1C, 0x30, 0x9E, 0xEC, 0x60, 0x6C, 0x72, 0xBA, 0x36};


// For signing transactions in Enclave
typedef struct {
    secp256k1_context* ctx;
    unsigned char msg[32];
    unsigned char key[32];
} bench_sign;


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////  SVM Globals  ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#define Malloc(type,n) (type *)malloc((n)*sizeof(type))
struct svm_parameter param;
struct svm_problem prob;
struct svm_model *model;
struct svm_node *x_space;
int cross_validation;

void read_svm_problem_from_plaintext(uint8_t *p_data, uint32_t data_size, int N_sum, int K, int C);
////////////////////////////////////////////////////////////////////////////////
//////////////////////////////  SVM Globals End  ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void read_fann_problem_from_plaintext(uint8_t *p_data, uint32_t data_size, struct fann_train_data *data, int N_sum, int K, int C);








#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t
{
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";



// Derive two keys from shared key and key id.
bool derive_key(
    const sgx_ec256_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sgx_ec_key_128bit_t *first_derived_key,
    sgx_ec_key_128bit_t *second_derived_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++)
    {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s)-1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    assert(sizeof(sgx_ec_key_128bit_t)* 2 == sizeof(sgx_sha256_hash_t));
    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

    return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t
{
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
    uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    bool derive_ret = false;

    if (NULL == shared_key)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ISV_KDF_ID != kdf_id)
    {
        printf("ENCLAVE: Error, key derivation id mismatch. \n");
        return SGX_ERROR_KDF_MISMATCH;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK, smk_key, sk_key);
    if (derive_ret != true)
    {
        printf("ENCLAVE: Error, key derivation failed for SMK key. \n");
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK, mk_key, vk_key);
    if (derive_ret != true)
    {
        printf("ENCLAVE: Error, key derivation failed for MK key. \n");
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t ECALL_enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse)
    {
        int busy_retry_times = 2;
        do{
            ret = sgx_create_pse_session();
        }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS) return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(&g_sp_pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(&g_sp_pub_key, b_pse, p_context);
#endif
    if(b_pse)
    {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI ECALL_enclave_ra_close(
    sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t ECALL_verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    }
    while(0);

    return ret;
}





/* Assign space for sk_key_DO, DO_data_key */
sgx_status_t ECALL_enclave_DO_config(int num_DOs)
{
    int i;
    sgx_status_t ret = SGX_SUCCESS;
    num_DOs_here = num_DOs;
    DO_data_key = (sgx_aes_gcm_128bit_key_t *) malloc(num_DOs * sizeof(sgx_aes_gcm_128bit_key_t));
    return ret;
}




// Generate a secret information for the SP encrypted with SK.
// Input pointers aren't checked since the trusted stubs copy
// them into EPC memory.
//
// @param context The trusted KE library key context.
// @param p_secret Message containing the secret.
// @param secret_size Size in bytes of the secret message.
// @param p_gcm_mac The pointer the the AESGCM MAC for the message.
// @param provisioner_type 1: DataConsumer, 2: iDataAgent
//
// @return SGX_ERROR_INVALID_PARAMETER - secret size if incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESGCM function.
// @return SGX_ERROR_UNEXPECTED - the secret doesn't match the expected value.

sgx_status_t ECALL_put_secret_data(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac,
    uint32_t provisioner_type)
{
    sgx_status_t ret = SGX_SUCCESS;
    int i, j;
    
    uint8_t aes_gcm_iv[12] = {0};

    do {

        if(provisioner_type == 1) // DataConsumer
        {
            ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key_DC);
            if(SGX_SUCCESS != ret)
            {
                printf("[ENCLAVE] Get keys failed.\n");
                break;
            }

            ret = sgx_rijndael128GCM_decrypt(&sk_key_DC,
                                         p_secret,
                                         secret_size,
                                         &g_secret_DC[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *)(p_gcm_mac));
            if (ret != SGX_SUCCESS)
            {
                printf("[ENCLAVE] 128GCM decrypt failed\n");
            }

            printf("\n[ENCLAVE] DataConsumer's secret is:\n");
            for(i=0;i<secret_size;i++)
            {
                printf("0x%02X ", g_secret_DC[i]);
            }
            printf("\n");
        }
        else // iDataAgent
        {
            ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key_DO);
            if(SGX_SUCCESS != ret)
            {
                printf("[ENCLAVE] Get keys failed.\n");
                break;
            }

            ret = sgx_rijndael128GCM_decrypt(&sk_key_DO,
                                         p_secret,
                                         secret_size,
                                         &DO_data_key[0][0], //&g_secret_DO[0],
                                         &aes_gcm_iv[0],
                                         12,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *)(p_gcm_mac));


            printf("\n[ENCLAVE] Data decryption keys\n");

            // for(i = 0; i < num_DOs_here; i++)
            // {
            //     printf("Key %d: ", i+1);
            //     for(j = 0; j < sizeof(sgx_aes_gcm_128bit_key_t); j++)
            //     {
            //         printf("%02x", DO_data_key[i][j]);
            //     }
            //     printf("\n");
            // }
            // printf("\n");
        }

        // Once the server has the shared secret, it should be sealed to
        // persistent storage for future use. This will prevents having to
        // perform remote attestation until the secret goes stale. Once the
        // enclave is created again, the secret can be unsealed.
    } while(0);
    return ret;
}




// This ECALL function computes the sum of data items
sgx_status_t ECALL_compute_task1(
    sgx_ra_context_t context,
    uint32_t data_num,
    uint32_t *dataSizes,
    uint32_t *macSizes,
    uint8_t *p_data_encrypted,
    uint32_t data_size,
    uint8_t *p_data_gcm_mac,
    uint32_t mac_size,
    uint8_t *p_result_encrypted,
    uint32_t result_size,
    uint8_t *p_result_gcm_mac)
{
    sgx_status_t ret = SGX_SUCCESS;
    uint8_t aes_gcm_iv[12] = {0};
    uint8_t g_data[data_size];
    uint8_t result[result_size];
    int i, j, len, N, K, C, N_sum = 0;
    int cryptoCount = 0;
    uint32_t data_loc = 0, mac_loc = 0; 

    /* Decrypt all data files */
    for(j = 0; j < data_num; j++)
    {
        do{
            ret = sgx_rijndael128GCM_decrypt( 
                                        &DO_data_key[j], //(const sgx_ec_key_128bit_t*) g_secret_DO,
                                        &p_data_encrypted[data_loc],
                                        dataSizes[j],
                                        &g_data[data_loc],
                                        aes_gcm_iv,
                                        12,
                                        NULL,
                                        0,
                                        (const sgx_aes_gcm_128bit_tag_t*) &p_data_gcm_mac[mac_loc]);
            
            if(cryptoCount >= 5)
            {
                return ret;
            }
            cryptoCount ++;

        }while(ret != SGX_SUCCESS);

        // printf("\n[ENCLAVE] Data %d:\n", j+1);
        // for(i = 0; i < dataSizes[j]; i++)
        // {
        //     printf("%c", g_data[data_loc + i]);
        // }

        /* Read meta data */
        i = data_loc;

        for(len = 0; g_data[i + len] != ' '; len++);
        N = (int)s2dou(&g_data[i], len);
        i += len + 1;

        for(len = 0; g_data[i + len] != ' '; len++);
        K = (int)s2dou(&g_data[i], len);
        i += len + 1;

        for(len = 0; g_data[i + len] != ' '; len++);
        C = (int)s2dou(&g_data[i], len);

        printf("\n[ENCLAVE] Datafile %d's dimension: N = %d, K = %d, C = %d\n", j, N, K, C);

        N_sum += N;
        data_loc += dataSizes[j];
        mac_loc  += macSizes[j];
    }

    printf("\n[ENCLAVE] Merged Data's dimension: N = %d, K = %d, C = %d\n\n", N_sum, K, C);
    


    // The result
    int sum = 0;
    for(i = 0;i < data_size;i++)
    {
        sum += g_data[i] - 48;
    }
    printf("\n[ENCLAVE] The result is: %d.\n", sum);

    *result = sum;

    /* Generate a 16-Byte random key to encrypt the result */
    sgx_read_rand(K_result, sizeof(K_result));

    /* Encrypt the result with K_result */
    ret = sgx_rijndael128GCM_encrypt((const sgx_ec_key_128bit_t*) K_result,
                                    result,
                                    result_size,
                                    p_result_encrypted,
                                    aes_gcm_iv,
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*) p_result_gcm_mac);


    /* Compute K_result_hash and C_result_hash */
    char K_result_string[32], C_result_string[result_size*2];
    u_array2c_array(K_result_string, K_result, sizeof(K_result));
    u_array2c_array(C_result_string, p_result_encrypted, sizeof(p_result_encrypted));
    Keccak keccak1, keccak2;
    K_result_hash = keccak1(K_result_string);
    C_result_hash = keccak2(C_result_string);

    return ret;
}


/*
This ECALL function trains an SVM classifier
*/
sgx_status_t ECALL_compute_task2(
    sgx_ra_context_t context,
    uint32_t data_num,
    uint32_t *dataSizes,
    uint32_t *macSizes,
    uint8_t *p_data_encrypted,
    uint32_t data_size,
    uint8_t *p_data_gcm_mac,
    uint32_t mac_size,
    uint8_t *p_result_encrypted,
    uint32_t result_size,
    uint8_t *p_result_gcm_mac)
{
    sgx_status_t ret = SGX_SUCCESS;
    uint8_t aes_gcm_iv[12] = {0};
    uint8_t g_data[data_size];
    uint8_t* result;

    int i, j, len, N, K, C, N_sum = 0;
    int cryptoCount = 0;
    uint32_t data_loc = 0, mac_loc = 0; 

    /* Decrypt all data files */
    for(j = 0; j < data_num; j++)
    {
        do{
            ret = sgx_rijndael128GCM_decrypt(
                                        &DO_data_key[j], //(const sgx_ec_key_128bit_t*) g_secret_DO,
                                        &p_data_encrypted[data_loc],
                                        dataSizes[j],
                                        &g_data[data_loc],
                                        aes_gcm_iv,
                                        12,
                                        NULL,
                                        0,
                                        (const sgx_aes_gcm_128bit_tag_t*) &p_data_gcm_mac[mac_loc]);
            
            if(cryptoCount >= 5)
            {
                return ret;
            }
            cryptoCount ++;

        }while(ret != SGX_SUCCESS);

        // printf("\n[ENCLAVE] Data %d:\n", j+1);
        // for(i = 0; i < dataSizes[j]; i++)
        // {
        //     printf("%c", g_data[data_loc + i]);
        // }

        /* Read meta data */
        i = data_loc;

        for(len = 0; g_data[i + len] != ' '; len++);
        N = (int)s2dou(&g_data[i], len);
        i += len + 1;

        for(len = 0; g_data[i + len] != ' '; len++);
        K = (int)s2dou(&g_data[i], len);
        i += len + 1;

        for(len = 0; g_data[i + len] != ' '; len++);
        C = (int)s2dou(&g_data[i], len);

        printf("\n[ENCLAVE] Datafile %d's dimension: N = %d, K = %d, C = %d\n", j, N, K, C);

        N_sum += N;
        data_loc += dataSizes[j];
        mac_loc  += macSizes[j];
    }

    printf("\n[ENCLAVE] Merged Data's dimension: N = %d, K = %d, C = %d\n\n", N_sum, K, C);

    /* Get the problem */
    read_svm_problem_from_plaintext(g_data, data_size, N_sum, K, C);

    /* Model training parameters */
    param.svm_type = C_SVC;
    param.kernel_type = RBF;
    param.degree = 3;
    param.gamma = 0.5;  // default: 1/num_features
    param.coef0 = 0;
    param.nu = 0.5;
    param.cache_size = 100;
    param.C = 5;   // default: 1
    param.eps = 0.1; // default: 1e-3
    param.p = 0.1;
    param.shrinking = 1;
    param.probability = 0;
    param.nr_weight = 0;
    param.weight_label = NULL;
    param.weight = NULL;
    cross_validation = 0;
    
    /* Check parameters */
    const char *error_msg;
    error_msg = svm_check_parameter(&prob, &param);
    if(error_msg)
    {
        printf("[ENCLAVE] ERROR: %s\n",error_msg);
        return SGX_ERROR_UNEXPECTED;
    }

    /* Train and save model */
    model = svm_train(&prob, &param);

    /* Generate a 16-Byte random key to encrypt the result */
    sgx_read_rand(K_result, sizeof(K_result));

    /* Encrypt the result with K_result */
    ret = sgx_rijndael128GCM_encrypt((const sgx_ec_key_128bit_t*) K_result,
                                    (uint8_t*) model,
                                    sizeof(model),
                                    p_result_encrypted,
                                    aes_gcm_iv,
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*) p_result_gcm_mac);

    /* Clean */
    svm_free_and_destroy_model(&model);
    svm_destroy_param(&param);
    free(prob.y);
    free(prob.x);
    free(x_space);

    /* Compute K_result_hash and C_result_hash */
    char K_result_string[32], C_result_string[result_size*2];
    u_array2c_array(K_result_string, K_result, sizeof(K_result));
    u_array2c_array(C_result_string, p_result_encrypted, sizeof(p_result_encrypted));
    Keccak keccak1, keccak2;
    K_result_hash = keccak1(K_result_string);
    C_result_hash = keccak2(C_result_string);

    return ret;
}




/*
This ECALL function trains an ANN classifier
*/
sgx_status_t ECALL_compute_task3(
    sgx_ra_context_t context,
    uint32_t data_num,
    uint32_t *dataSizes,
    uint32_t *macSizes,
    uint8_t *p_data_encrypted,
    uint32_t data_size,
    uint8_t *p_data_gcm_mac,
    uint32_t mac_size,
    uint8_t *p_result_encrypted,
    uint32_t result_size,
    uint8_t *p_result_gcm_mac)
{
    sgx_status_t ret = SGX_SUCCESS;
    uint8_t aes_gcm_iv[12] = {0};
    uint8_t g_data[data_size];

    int i, j, len, N, K, C, N_sum = 0;
    int cryptoCount = 0;
    struct fann_train_data *data;

    uint32_t data_loc = 0, mac_loc = 0; 

    // printf("asdasd\n");

    /* Decrypt all data files */
    for(j = 0; j < data_num; j++)
    {
        do{
            ret = sgx_rijndael128GCM_decrypt(
                                        &DO_data_key[j], //(const sgx_ec_key_128bit_t*) g_secret_DO,
                                        &p_data_encrypted[data_loc],
                                        dataSizes[j],
                                        &g_data[data_loc],
                                        aes_gcm_iv,
                                        12,
                                        NULL,
                                        0,
                                        (const sgx_aes_gcm_128bit_tag_t*) &p_data_gcm_mac[mac_loc]);
            
            if(cryptoCount >= 20)
            {
                printf("\n[ENCLAVE] Decryption failed.\n");
                return ret;
            }
            cryptoCount ++;

        }while(ret != SGX_SUCCESS);

        printf("\n[ENCLAVE] Data %d:\n", j+1);
        for(i = 0; i < dataSizes[j]; i++)
        {
            printf("%c", g_data[data_loc + i]);
        }

        /* Read meta data */
        i = data_loc;

        for(len = 0; g_data[i + len] != ' '; len++);
        N = (int)s2dou(&g_data[i], len);
        i += len + 1;

        for(len = 0; g_data[i + len] != ' '; len++);
        K = (int)s2dou(&g_data[i], len);
        i += len + 1;

        for(len = 0; g_data[i + len] != ' '; len++);
        C = (int)s2dou(&g_data[i], len);

        printf("\n[ENCLAVE] Data file %d's dimension: N = %d, K = %d, C = %d", j+1, N, K, C);

        N_sum += N;
        data_loc += dataSizes[j];
        mac_loc  += macSizes[j];
    }

    printf("\n[ENCLAVE] Merged Data's dimension: N = %d, K = %d, C = %d\n\n", N_sum, K, C);

    // printf("\n[ENCLAVE] DataOwner's data are:\n");
    // for(i = 0;i < data_size;i++)
    // {
    //     printf("%c", g_data[i]);
    // }

    /* Assign space for data points */
    data = fann_create_train(N_sum, K, C);

    /* Read training data */
    read_fann_problem_from_plaintext(g_data, data_size, data, N_sum, K, C);

    // for(i = 0; i < N_sum; i++)
    // {
    //     printf("%d: [%f %f] ", i+1, data->output[i][0], data->output[i][1]);
    //     for(j = 0; j < 14; j++)
    //     {
    //         printf("%f ", data->input[i][j]);
    //     }
    //     printf("\n");
    // }

    /* Model training parameters */
    const unsigned int num_input = 14;
    const unsigned int num_output = 2;
    const unsigned int num_layers = 4;
    const float desired_error = (const float) 0.001;
    const unsigned int max_epochs = 10000;
    const unsigned int epochs_between_reports = 1000;

    /* Train and save model */
    struct fann *ann = fann_create_standard(num_layers, num_input, 8, 8, num_output);
    fann_set_activation_function_hidden(ann, FANN_SIGMOID_SYMMETRIC);
    fann_set_activation_function_output(ann, FANN_SIGMOID_SYMMETRIC);
    fann_train_on_data(ann, data, max_epochs, epochs_between_reports, desired_error);
    
    /* Generate a 16-Byte random key to encrypt the result */
    sgx_read_rand(K_result, sizeof(K_result));

    /* Encrypt the result with K_result */
    ret = sgx_rijndael128GCM_encrypt((const sgx_ec_key_128bit_t*) K_result,
                                    (uint8_t*) ann,
                                    sizeof(ann),
                                    p_result_encrypted,
                                    aes_gcm_iv,
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*) p_result_gcm_mac);

    /* Clean */
    fann_destroy(ann);
    fann_destroy_train(data);

    /* Compute K_result_hash and C_result_hash */
    char K_result_string[32], C_result_string[result_size*2];
    u_array2c_array(K_result_string, K_result, sizeof(K_result));
    u_array2c_array(C_result_string, p_result_encrypted, result_size);
    Keccak keccak1, keccak2;
    K_result_hash = keccak1(K_result_string);
    C_result_hash = keccak2(C_result_string);

    return ret;
}



/*
This ECALL function perform an SVM training process
*/
sgx_status_t ECALL_get_K_result_hashes(
    sgx_ra_context_t context,
    uint8_t *p_K_result_en,
    uint8_t *p_K_result_gcm_mac,
    uint8_t *p_K_result_hash_en_DC,
    uint8_t *p_K_result_hash_DC_gcm_mac,
    uint8_t *p_C_result_hash_en_DC,
    uint8_t *p_C_result_hash_DC_gcm_mac)
{
    int i;
    sgx_status_t ret = SGX_SUCCESS;
    uint8_t aes_gcm_iv[12] = {0};

    printf("\n[ENCLAVE] K_result:\n");
    for(i = 0; i < 16; i++)
    {
        printf("%02x", K_result[i]);
    }

    printf("\n[ENCLAVE] K_result_hash:\n");
    for(i = 0; i < 64; i++)
    {
        printf("%c", K_result_hash[i]);
    }

    printf("\n[ENCLAVE] C_result_hash:\n");
    for(i = 0; i < 64; i++)
    {
        printf("%c", C_result_hash[i]);
    }

    printf("\n\n");

    /* Convert string typed hashes to uint8_t* */
    uint8_t K_result_hash_uint8[32], C_result_hash_uint8[32];
    string2u_array(K_result_hash_uint8, K_result_hash, 32);
    string2u_array(C_result_hash_uint8, C_result_hash, 32);

    /* Encrypt K_result with sk_key_DO */
    ret = sgx_rijndael128GCM_encrypt((const sgx_ec_key_128bit_t*) sk_key_DO,
                                    K_result,
                                    16,
                                    p_K_result_en,
                                    aes_gcm_iv,
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*) p_K_result_gcm_mac);

    /* Encrypt K_result_hash with sk_key_DC */
    ret = sgx_rijndael128GCM_encrypt((const sgx_ec_key_128bit_t*) sk_key_DC,
                                    K_result_hash_uint8,
                                    32,
                                    p_K_result_hash_en_DC,
                                    aes_gcm_iv,
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*) p_K_result_hash_DC_gcm_mac);

    /* Encrypt C_result_hash with sk_key_DC */
    ret = sgx_rijndael128GCM_encrypt((const sgx_ec_key_128bit_t*) sk_key_DC,
                                    C_result_hash_uint8,
                                    32,
                                    p_C_result_hash_en_DC,
                                    aes_gcm_iv,
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*) p_C_result_hash_DC_gcm_mac);
}






/* Read the svm data and write them into prob*/
// The format of the plaintext needs to be strictly conformed:
// 1. The 1st line spedifies the metadata: 'n_datapoints n_features '
// 2. Every data value ends and is followed with ' '
// 3. Format for every data value: i:0.123 while i=1,2,...,n_features
// 4. No blank line is allowed
void read_svm_problem_from_plaintext(uint8_t *p_data, uint32_t data_size, int N, int K, int C)
{
    int i = 0, j = 0, k, idx, element = 0, n_features, n_classes;
    int len;

    // /* Read meta data */
    // for(len = 0; p_data[i + len] != ' '; len++);
    // prob.l = (int)s2dou(&p_data[i], len);
    // i += len + 1;

    // for(len = 0; p_data[i + len] != ' '; len++);
    // n_features = (int)s2dou(&p_data[i], len);
    // i += len + 1;

    // for(len = 0; p_data[i + len] != ' '; len++);
    // n_classes = (int)s2dou(&p_data[i], len);
    // i += len + 2;

    prob.l = N;


    // printf("\n[ENCLAVE] Training data dimension: N = %d, K = %d, C = %d\n", prob.l, K, C);

    /* Assign space for data points */
    prob.y = Malloc(double, prob.l);
    prob.x = Malloc(struct svm_node *, prob.l);
    x_space = Malloc(struct svm_node, (K + 1) * prob.l); // contains all data points' vectors

    /* Read data points */
    for (j = 0; j < prob.l; j++)
    {
        /* Skip meta data lines */
        if(p_data[i] != '+' && p_data[i] != '-')
        {
            for(len = 0; p_data[i + len] != '\n'; len++);
            i += len + 1;
            j --;
            continue;
        }

        /* Read label */
        for(len = 0; p_data[i + len] != ' '; len++);
        prob.y[j] = s2dou(&p_data[i], len);
        i += len + 1;

        prob.x[j] = &x_space[element];

        /* Read the values of the particular data point led by the previous label */
        for(k = 0; k < K; k++)
        {
            for(len = 0; p_data[i + len] != ':'; len++);
            idx = (int)s2dou(&p_data[i], len);
            i += len + 1;

            // If the (k+1)th element missing -- assign 0 to it 
            if(idx > k+1){ 
                k = idx - 1;
            }

            x_space[element].index = idx;
            
            for(len = 0; p_data[i + len] != ' '; len++);
            x_space[element].value = s2dou(&p_data[i], len);
            i += len + 1;
            element ++;
        }
        x_space[element++].index = -1;

        i++; // skip the '\n' 
    }
}



/* Read the data from plaintext */
// The format of the plaintext needs to be strictly conformed:
// 1. The 1st line spedifies the metadata: 'n_datapoints n_features '
// 2. Every data value ends and is followed with ' '
// 3. Format for every data value: i:0.123 while i=1,2,...,n_features
// 4. No blank line is allowed
void read_fann_problem_from_plaintext(uint8_t *p_data, uint32_t data_size, struct fann_train_data *data, int N, int K, int C)
{
    int i = 0, j, k;
    int len;
    int tmpLabel;

    // /* Read meta data */
    // for(len = 0; p_data[i + len] != ' '; len++);
    // N = (int)s2dou(&p_data[i], len);
    // i += len + 1;

    // for(len = 0; p_data[i + len] != ' '; len++);
    // K = (int)s2dou(&p_data[i], len);
    // i += len + 1;

    // for(len = 0; p_data[i + len] != ' '; len++);
    // C = (int)s2dou(&p_data[i], len);
    // i += len + 2;

    /* Read data points */
    for (j = 0; j < N; j++)
    {   
        /* Skip meta data lines */
        if(p_data[i] != '+' && p_data[i] != '-')
        {
            for(len = 0; p_data[i + len] != '\n'; len++);
            i += len + 1;
            j --;
            continue;
        }

        /* Read label */
        for(len = 0; p_data[i + len] != ' '; len++);
        tmpLabel = (int) s2dou(&p_data[i], len);
        // printf("tmpLabel = %d", tmpLabel);
        data->output[j][0] = 0;
        data->output[j][1] = 0;
        data->output[j][(tmpLabel+1)/2] = 1; // Assign 1 to the labeled class
        // data->output[j][0] = 1; // Assign 1 to the labeled class
        i += len + 1;

        // printf("\n[%f %f] ", data->output[j][0], data->output[j][1]);


        /* Read the values of the particular data point led by the previous label */
        for(k = 0; k < K; k++)
        {
            for(len = 0; p_data[i + len] != ':'; len++);
            i += len + 1;
            
            for(len = 0; p_data[i + len] != ' '; len++);
            data->input[j][k] = s2dou(&p_data[i], len);
            i += len + 1;
        }

        i++; // skip the '\n' 
    }
}