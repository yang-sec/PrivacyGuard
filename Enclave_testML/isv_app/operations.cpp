/* 
* Contract Execution Environment (CEE): enclave_operation.cpp
* 
* 
* PrivacyGuard Project (2018), Virginia Tech CNSR Lab
*/

#include "operations.h"

#include <stdio.h>
#include <cstdio>
#include <cwchar>
#include <string.h>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <limits.h>
#include <unistd.h>
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"
#include "isv_enclave_u.h"
// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"
#include "network_ra.h"
// Needed to create enclave and do ecall.
#include "sgx_urts.h"
// Needed to query extended epid group id.
#include "sgx_uae_service.h"
#include "service_provider.h"
#include "sample_messages.h"
#include "sample_libcrypto.h"

// #include "enclave_utilities.h"
// #include "svm.h"
#include "fann.h"
#include "keccak.h"

// #include "svm.h"


#define ENCLAVE_PATH "isv_enclave.signed.so"
#define _T(x) x

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif


uint8_t rand_key_DC_encrypted[AESGCM_KEY_SIZE];
uint8_t rand_key_DC_mac[AESGCM_MAC_SIZE];


// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}


void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0], response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga), sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl), p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result = (sample_ra_att_result_msg_t *)(response->body);
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob), sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n", p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload, p_att_result->secret.payload_size);
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. Response of type not supported %d\n", response->type);
    }
}



bool enclave_init(enclave_info_t* enclave_info)
{
	FILE* OUTPUT = stdout;
	int ret = 0;
	int launch_token_update = 0;
	sgx_launch_token_t launch_token = {0};
	sgx_status_t status = SGX_SUCCESS;

	// Enclave config
	enclave_info->enclave_id = 0;
	enclave_info->context = INT_MAX;
	enclave_info->extended_epid_group_id = 0;

	/*--------------------------
		Create an ISV enclave.
	----------------------------*/
	{
	    memset(&launch_token, 0, sizeof(sgx_launch_token_t));
        ret = sgx_create_enclave(_T(ENCLAVE_PATH), SGX_DEBUG_FLAG, &launch_token, &launch_token_update, &enclave_info->enclave_id, NULL);
        if(SGX_SUCCESS != ret)
        {
            fprintf(OUTPUT, "\nError, call sgx_create_enclave() fail. [%s]", __FUNCTION__);
            printf("\nError code: 0x%X\n", ret);
            return false;
        }
        // fprintf(OUTPUT, "\nCall sgx_create_enclave() success. [%s]", __FUNCTION__);	        
	}

	/*-----------------------------
		Config the epid group id.
	-------------------------------*/
	{
	    ret = sgx_get_extended_epid_group_id(&enclave_info->extended_epid_group_id);
	    if (SGX_SUCCESS != ret)
	    {
	        fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id() fail [%s].", __FUNCTION__);
	        return false;
	    }
	    // fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success() [%s].\n", __FUNCTION__);
	}

	printf("Enclave initialized.\n");
	return true;
}


/* Encrypt a given file */
const uint8_t data_key[16] = {0x87, 0xA6, 0x0B, 0x39, 0xD5, 0x26, 0xAB, 0x1C, 0x30, 0x9E, 0xEC, 0x60, 0x6C, 0x72, 0xBA, 0x36};
uint8_t aes_gcm_iv[12] = {0};

int encrypt_file(int DO_ID, int file_num)
{
	int ret;
	uint8_t en_mac[16];

	char buf1[100], buf2[100], buf3[100];
	sprintf(buf1, "../CloudStorage/Reserved_ML_Data/DO%d_%d.txt", DO_ID, file_num);
	sprintf(buf2, "data/DO%d_%d_en.txt", DO_ID, file_num);
	sprintf(buf3, "data/DO%d_%d_en_mac.txt", DO_ID, file_num);
	FILE *ifp = fopen(buf1, "rb");
	FILE *ofp_ctext = fopen(buf2, "wb");
	FILE *ofp_mac = fopen(buf3, "wb");
	int lSize;

	// Obtain file size
  	fseek(ifp, 0, SEEK_END);
  	lSize = ftell(ifp);
  	rewind(ifp);

	// Use AES-GCM provided in sample_crypto.h
	uint8_t* indata;
	uint8_t* outdata;
	indata =  (uint8_t*) malloc (sizeof(uint8_t)*lSize);
	outdata = (uint8_t*) malloc (sizeof(uint8_t)*lSize);

	fread(indata, 1, lSize, ifp);

    ret = sample_rijndael128GCM_encrypt(
						            &data_key,
						            indata,
						            lSize,
						            outdata, // Output
						            &aes_gcm_iv[0],
						            12,
						            NULL,
						            0,
						            &en_mac); // Output

	fwrite(outdata, 1, lSize, ofp_ctext);
	fwrite(en_mac, 1, SAMPLE_AESGCM_MAC_SIZE, ofp_mac);

	fclose(ifp);
	fclose(ofp_ctext);
	fclose(ofp_mac);
    printf("encrypt_file Completed\n");
}



/* The computing task */
// Input DO's encrypted data into the enclave, in which the data shall be decrypted and of which the result shall be computed;
// The result is re-encrypted with DC's sk_key stored in a 4-byte char array, which is then provisioned to DC.
int enclave_compute_task1(enclave_info_t* enclave_info, int DO_ID, int file_num)
{
	FILE* OUTPUT = stdout;
	sgx_status_t status = SGX_SUCCESS;
	int ret = 0;
	int result_size = TASK1_RESULT_SIZE; // task1 result format: int32 (4 bytes char array)
	uint32_t ctext_size, mac_size;

	/* File in/out */
	char buf1[100], buf2[100], buf3[100], buf4[100], buf5[100];
	sprintf(buf1, "../CloudStorage/DO%d/%d.txt", DO_ID, file_num);
	sprintf(buf2, "../CloudStorage/DO%d/%d_mac.txt", DO_ID, file_num);
	sprintf(buf3, "../CloudStorage/DO%d/%d_result.txt", DO_ID, file_num);
	sprintf(buf4, "../CloudStorage/DO%d/%d_result_mac.txt", DO_ID, file_num);
	sprintf(buf5, "../CloudStorage/DO%d/%d_result_rand_key_mac.txt", DO_ID, file_num);
	FILE *ifp_data = fopen(buf1, "rb");
	FILE *ifp_mac = fopen(buf2, "rb");
	FILE *ofp_result = fopen(buf3, "wb");
	FILE *ofp_result_mac = fopen(buf4, "wb");
	FILE *ofp_result_rand_key_mac = fopen(buf5, "wb");
	

	/* Computation result init */
	uint8_t* result = (uint8_t*) malloc(result_size);
	uint8_t result_mac[AESGCM_MAC_SIZE];

	/* Obtain file size */
  	fseek(ifp_data, 0, SEEK_END);
  	ctext_size = ftell(ifp_data);
  	rewind(ifp_data);
  	fseek(ifp_mac, 0, SEEK_END);
  	mac_size = ftell(ifp_mac);
  	rewind(ifp_mac); 	

	uint8_t* data;
	uint8_t* data_mac;
	data =  (uint8_t*) malloc (sizeof(uint8_t) * ctext_size);
	data_mac = (uint8_t*) malloc (sizeof(uint8_t) * mac_size);

	fread(data, 1, ctext_size, ifp_data);
	fread(data_mac, 1, mac_size, ifp_mac);
	fclose(ifp_data);
	fclose(ifp_mac);

	/* Put the encrypted data into enclave, begin computing */
	ret = ECALL_compute_task1(
							enclave_info->enclave_id,
							&status,
							enclave_info->context,
							data,
							ctext_size,
							data_mac,
							result,
							result_size,
							result_mac,
							rand_key_DC_encrypted,
							rand_key_DC_mac);

    if(SGX_SUCCESS != ret || status)
    {
        fprintf(OUTPUT, "\nError, call ECALL_computate_task1 fail [%s]. Session closed.\n", __FUNCTION__);
        return 1;
    }

    /* Store the encrypted result in cloud, in the same directory of the data */
    fwrite(result, 1, ctext_size, ofp_result);
    fwrite(result_mac, 1, AESGCM_MAC_SIZE, ofp_result_mac);
    fwrite(rand_key_DC_mac, 1, AESGCM_MAC_SIZE, ofp_result_rand_key_mac);
    fclose(ofp_result);
	fclose(ofp_result_mac);
	fclose(ofp_result_rand_key_mac);

    printf("\nComputation Completed. Result encrypted and stored.\n"); 
    SAFE_FREE(data);
    SAFE_FREE(data_mac);
    SAFE_FREE(result);

    return 0;
}


int enclave_compute_task(enclave_info_t* enclave_info, int Request_DC, int Request_type, int Request_start, int Request_end, int Request_operation)
{
    FILE* OUTPUT = stdout;
    sgx_status_t status = SGX_SUCCESS;
    int ret = 0;
    uint32_t result_size;
    int i, j;
    int num_data = Request_end - Request_start + 1;
    uint32_t ctextSizes[num_data]; // each represents the size of a data file
    uint32_t macSizes[num_data]; // each represents the size of a gcm mac file
    uint32_t ctextSizes_sum = 0;
    uint32_t macSizes_sum = 0;

    /* File IO init */
    char buf3[100], buf4[100];
    sprintf(buf3, "data/DC%d_Task%d_result_en.txt", Request_DC, Request_operation);
    sprintf(buf4, "data/DC%d_Task%d_result_en_mac.txt", Request_DC, Request_operation);  
    FILE *ofp_result = fopen(buf3, "wb");
    FILE *ofp_result_mac = fopen(buf4, "wb");

    /* Get total file size */
    j = 0;
    for(i = Request_start; i <= Request_end; i++)
    {
        char buf1[100], buf2[100];

        switch(Request_type)
        {
            case 0:
            {
                sprintf(buf1, "../CloudStorage/Reserved_ML_Data/DO1_%d.txt", i);
                // sprintf(buf1, "data/DO1_%d_en.txt", i);
                sprintf(buf2, "data/DO1_%d_en_mac.txt", i); 
                // printf("Type 0. DO1_%d\n", i);
                break;
            }

            case 1:
            {
                sprintf(buf1, "data/DO%d_1_en.txt", i);
                sprintf(buf2, "data/DO%d_1_en_mac.txt", i);
                // printf("Type 1. DO%d_1\n", i);
                break;
            }
        }

        FILE *ifp_data = fopen(buf1, "rb");
        FILE *ifp_mac = fopen(buf2, "rb");
        
        /* Obtain file size */
        fseek(ifp_data, 0, SEEK_END);
        ctextSizes[j] = ftell(ifp_data);
        rewind(ifp_data);

        fseek(ifp_mac, 0, SEEK_END);
        macSizes[j] = ftell(ifp_mac);
        rewind(ifp_mac);    

        
        ctextSizes_sum += ctextSizes[j];
        macSizes_sum += macSizes[j];

        fclose(ifp_data);
        fclose(ifp_mac);
        j ++;
    }

    /* Allocate space for data */
    uint8_t *data;
    uint8_t *data_mac;
    data =  (uint8_t*) malloc (sizeof(uint8_t) * ctextSizes_sum);
    data_mac = (uint8_t*) malloc (sizeof(uint8_t) * macSizes_sum);

    // printf("asd\n");

    /* Read file*/
    j = 0;
    int loc_data = 0, loc_mac = 0;
    for(i = Request_start; i <= Request_end; i++)
    {
        char buf1[100], buf2[100];

        switch(Request_type)
        {
            case 0:
            {
                sprintf(buf1, "../CloudStorage/Reserved_ML_Data/DO1_%d.txt", i);
                // sprintf(buf1, "data/DO1_%d_en.txt", i);
                sprintf(buf2, "data/DO1_%d_en_mac.txt", i); 
                break;
            }

            case 1:
            {
                sprintf(buf1, "data/DO%d_1_en.txt", i);
                sprintf(buf2, "data/DO%d_1_en_mac.txt", i);
                break;
            }
        }

        FILE *ifp_data = fopen(buf1, "rb");
        FILE *ifp_mac = fopen(buf2, "rb");

        fread(&data[loc_data],     sizeof(uint8_t), ctextSizes[j], ifp_data);
        fread(&data_mac[loc_mac], sizeof(uint8_t), macSizes[j],   ifp_mac);

        fclose(ifp_data);
        fclose(ifp_mac);

        loc_data += ctextSizes[j];
        loc_mac  += macSizes[j];
        j ++; 
    }


    

    /* Computation result and message init */
    uint8_t *result_encrypted;
    uint8_t result_gcm_mac[AESGCM_MAC_SIZE];

    // K_result_msg->DO_ID = DO_ID;
    // K_result_msg->file_num = file_num;
    // K_result_hash_msg->DO_ID = DO_ID;
    // K_result_hash_msg->file_num = file_num;
    
    
    /* Computation task */
    switch(Request_operation)
    {
        case 1: result_size = TASK1_RESULT_SIZE; break;
        case 2: result_size = TASK2_RESULT_SIZE; break;
        case 3: result_size = TASK3_RESULT_SIZE; break;
    }
    result_encrypted = (uint8_t *) malloc(result_size);

    switch(Request_operation)
    {
        case 1:
            printf("\nBegin task 1 [summation].\n");
            // ret = ECALL_compute_task1(
            //                 enclave_info->enclave_id,
            //                 &status,
            //                 enclave_info->context,
            //                 num_data,
            //                 ctextSizes,
            //                 macSizes,
            //                 data,
            //                 ctextSizes_sum,
            //                 data_mac,
            //                 macSizes_sum,
            //                 result_encrypted,
            //                 result_size,
            //                 result_gcm_mac);
            break;

        case 2:
            printf("\nBegin task 2 [training SVM classifier].\n");
            // ret = ECALL_compute_task2(
            //                 enclave_info->enclave_id,
            //                 &status,
            //                 enclave_info->context,
            //                 num_data,
            //                 ctextSizes,
            //                 macSizes,
            //                 data,
            //                 ctextSizes_sum,
            //                 data_mac,
            //                 macSizes_sum,
            //                 result_encrypted,
            //                 result_size,
            //                 result_gcm_mac);
            break;

        case 3:
            printf("\nBegin task 3 [training ANN classifier].\n");
            ret = ECALL_compute_task3(
                            enclave_info->enclave_id,
                            &status,
                            enclave_info->context,
                            num_data,
                            ctextSizes,
                            macSizes,
                            data,
                            ctextSizes_sum,
                            data_mac,
                            macSizes_sum,
                            result_encrypted,
                            result_size,
                            result_gcm_mac);
            break;
    }

    if(SGX_SUCCESS != ret || status)
    {
        fprintf(OUTPUT, "\nError, call ECALL_computate_task%d fail [%s]. Session closed.\n", Request_operation, __FUNCTION__);
        // return 1;
    }

    /* Store the encrypted svm_model result in the cloud */
    fwrite(result_encrypted, 1, result_size, ofp_result);
    fwrite(result_gcm_mac, 1, AESGCM_MAC_SIZE, ofp_result_mac);
    fclose(ofp_result);
    fclose(ofp_result_mac);

    free(result_encrypted);

    return 0;
}


// int enclave_compute_task(enclave_info_t* enclave_info, int task_num, int DO_ID, int file_num)
// {
// 	FILE* OUTPUT = stdout;
// 	sgx_status_t status = SGX_SUCCESS;
// 	int ret = 0;

// 	char buf1[100], buf2[100], buf3[100], buf4[100];
// 	sprintf(buf1, "data/%d_en.txt", file_num);  // change to DO's folder later!
// 	sprintf(buf2, "data/%d_en_mac.txt", file_num);
// 	sprintf(buf3, "data/Task%d_result_en.txt", task_num);
// 	sprintf(buf4, "data/Task%d_result_en_mac.txt", task_num);
// 	FILE *ifp_data = fopen(buf1, "rb");
// 	FILE *ifp_mac = fopen(buf2, "rb");
// 	FILE *ofp_result = fopen(buf3, "wb");
// 	FILE *ofp_result_mac = fopen(buf4, "wb");
// 	uint32_t ctext_size, mac_size;

// 	// Computation result message init
// 	uint32_t result_size = 10000;
// 	computation_result_msg_t* p_comp_result_msg = (computation_result_msg_t*) malloc(sizeof(computation_result_msg_t));
// 	p_comp_result_msg->result_encrypted = (uint8_t*) malloc(result_size);
// 	p_comp_result_msg->DO_ID = DO_ID;
// 	p_comp_result_msg->file_num = file_num;

// 	// Obtain file size
//   	fseek(ifp_data, 0, SEEK_END);
//   	ctext_size = ftell(ifp_data);
//   	rewind(ifp_data);

//   	fseek(ifp_mac, 0, SEEK_END);
//   	mac_size = ftell(ifp_mac);
//   	rewind(ifp_mac); 	

// 	uint8_t* data;
// 	uint8_t* data_mac;
// 	// uint8_t* result;
// 	data =  (uint8_t*) malloc (sizeof(uint8_t) * ctext_size);
// 	data_mac = (uint8_t*) malloc (sizeof(uint8_t) * mac_size);
// 	// result = (uint8_t*) malloc (sizeof(uint8_t) * 4); // The result is stored in a 4-byte char array

// 	fread(data, 1, ctext_size, ifp_data);
// 	fread(data_mac, 1, mac_size, ifp_mac);
// 	fclose(ifp_data);
// 	fclose(ifp_mac);
	
	
//     switch(task_num)
//     {
//         case 2:
//             ret = ECALL_compute_task2(
//                             enclave_info->enclave_id,
//                             &status,
//                             enclave_info->context,
//                             data,
//                             ctext_size,
//                             data_mac,
//                             p_comp_result_msg->result_encrypted,
//                             result_size,
//                             p_comp_result_msg->result_gcm_mac);
//             break;

//         case 3:
//             ret = ECALL_compute_task3(
//                             enclave_info->enclave_id,
//                             &status,
//                             enclave_info->context,
//                             data,
//                             ctext_size,
//                             data_mac,
//                             p_comp_result_msg->result_encrypted,
//                             result_size,
//                             p_comp_result_msg->result_gcm_mac);
//             break;
//     }

//     if(SGX_SUCCESS != ret || status)
//     {
//         fprintf(OUTPUT, "\nError, call ECALL_computate_task fail [%s]. Session closed.\n", __FUNCTION__);
//         return 1;
//     }

//     /* Store the encrypted svm_model result in the cloud */
//     fwrite(p_comp_result_msg->result_encrypted, 1, 1000, ofp_result);
// 	fwrite(p_comp_result_msg->result_gcm_mac, 1, SAMPLE_AESGCM_MAC_SIZE, ofp_result_mac);
// 	fclose(ofp_result);
// 	fclose(ofp_result_mac);

//     return 0;
// }




/* string to double converter */
// string has to begin with either '+', '-' or '0' ~ '9'
// the number has to be <= 11 decimal digits, not including '+' or '-'
double s2dou(uint8_t* str, int len)
{
    int i, pow = 1, point = 1, sign = 1, has_sign = 0;
    double res = 0;

    for(i = len-1;i >= 0;i--){
        if(str[i]=='.'){
            point = pow;
            continue;
        }
        if(str[i]=='-'){
            has_sign = 1;
            sign = -1;
            break;
        }
        if(str[i]=='+'){
            has_sign = 1;
            break;
        }
        res += ((int)str[i]-48)*pow;
        pow *= 10;
    }

    if(len - has_sign > 11){
        printf("String too long: %s\n", str);
        return 0;
    }

    return sign*res/point;
}


void u_array2c_array(char *c_arr, uint8_t *u_arr, int len)
{
    int i;
    for(i = 0; i < len; i++)
    {
        sprintf(&c_arr[2*i], "%02x", u_arr[i]);
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


uint8_t K_result[16] = {0x87, 0xA6, 0x0B, 0x39, 0xD5, 0x26, 0xAB, 0x1C, 0x30, 0x9E, 0xEC, 0x60, 0x6C, 0x72, 0xBA, 0x36};
std::string K_result_hash;
std::string C_result_hash;

int enclave_compute_task_normal(int Request_type, int Request_start, int Request_end, int Request_operation)
{
    FILE* OUTPUT = stdout;
    sgx_status_t status = SGX_SUCCESS;
    int ret = 0;
    uint32_t result_size;
    int data_num = Request_end - Request_start + 1;
    uint32_t ctextSizes[data_num]; // each represents the size of a data file
    uint32_t macSizes[data_num]; // each represents the size of a gcm mac file
    uint32_t ctextSizes_sum = 0;
    uint32_t macSizes_sum = 0;

    int i, j, len, N, K, C, N_sum = 0;
    struct fann_train_data *data;
    uint32_t data_loc = 0, mac_loc = 0;

    /* File IO init */
    char buf3[10000], buf4[10000];
    sprintf(buf3, "data/Task_%d_result_en.txt", Request_operation);
    sprintf(buf4, "data/Task_%d_result_en_mac.txt", Request_operation);  
    FILE *ofp_result = fopen(buf3, "wb");
    FILE *ofp_result_mac = fopen(buf4, "wb");

    /* Get total file size */
    j = 0;
    for(i = Request_start; i <= Request_end; i++)
    {
        char buf1[100];
 
        sprintf(buf1, "../CloudStorage/Reserved_ML_Data/DO1_%d.txt", i);

        FILE *ifp_data = fopen(buf1, "rb");
        
        /* Obtain file size */
        fseek(ifp_data, 0, SEEK_END);
        ctextSizes[j] = ftell(ifp_data);
        rewind(ifp_data);
        ctextSizes_sum += ctextSizes[j];
        fclose(ifp_data);

        j ++;
    }

    /* Allocate space for data */
    uint8_t *g_data;
    g_data =  (uint8_t*) malloc (sizeof(uint8_t) * ctextSizes_sum);

    j = 0;
    for(i = Request_start; i <= Request_end; i++)
    {
        char buf1[100];

        sprintf(buf1, "../CloudStorage/Reserved_ML_Data/DO1_%d.txt", i);
        FILE *ifp_data = fopen(buf1, "rb");
        fread(&g_data[data_loc], sizeof(uint8_t), ctextSizes[j], ifp_data);
        fclose(ifp_data);
        data_loc += ctextSizes[j];


        printf("Data %d size: %u\n", j+1, ctextSizes[j]);

        j ++; 

        // for(i = 0; i < ctextSizes[j]; i++)
        // {
        //     printf("%c", g_data[data_loc + i]);
        // }
    } 

        


    /* Read data*/
    data_loc = 0;
    for(j = 0; j < data_num; j++)
    {
        i = data_loc;

        for(len = 0; g_data[i + len] != ' '; len++);
        N = (int)s2dou(&g_data[i], len);
        i += len + 1;

        for(len = 0; g_data[i + len] != ' '; len++);
        K = (int)s2dou(&g_data[i], len);
        i += len + 1;

        for(len = 0; g_data[i + len] != ' '; len++);
        C = (int)s2dou(&g_data[i], len);

        printf("\nData file %d's dimension: N = %d, K = %d, C = %d", j+1, N, K, C);

        N_sum += N;
        data_loc += ctextSizes[j];

        
    }

    printf("\nMerged Data's dimension: N = %d, K = %d, C = %d\n\n", N_sum, K, C);

  

    
    
    /* Computation task */
    switch(Request_operation)
    {
        case 1: result_size = TASK1_RESULT_SIZE; break;
        case 2: result_size = TASK2_RESULT_SIZE; break;
        case 3: result_size = TASK3_RESULT_SIZE; break;
    }

    /* Computation result and message init */
    uint8_t *result_encrypted = (uint8_t *) malloc(result_size);;
    uint8_t result_gcm_mac[AESGCM_MAC_SIZE];
    uint8_t *p_result_encrypted = (uint8_t *) malloc(result_size);

    switch(Request_operation)
    {
        case 3:
        {
            printf("\nBegin task 3 [training ANN classifier].\n");

            /* Assign space for data points */
            data = fann_create_train(N_sum, K, C);

            /* Read training data */
            read_fann_problem_from_plaintext(g_data, ctextSizes_sum, data, N_sum, K, C);

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

            /* Encrypt result */
            // uint8_t result_gcm_mac[16];

            sample_rijndael128GCM_encrypt(
                                            &K_result,
                                            (uint8_t*) ann,
                                            sizeof(ann),
                                            p_result_encrypted, // Output
                                            &aes_gcm_iv[0],
                                            12,
                                            NULL,
                                            0,
                                            &result_gcm_mac); // Output



            /* Compute K_result_hash and C_result_hash */
            char K_result_string[32], C_result_string[result_size*2];
            u_array2c_array(K_result_string, K_result, sizeof(K_result));
            u_array2c_array(C_result_string, p_result_encrypted, sizeof(p_result_encrypted));
            Keccak keccak1, keccak2;
            K_result_hash = keccak1(K_result_string);
            C_result_hash = keccak2(C_result_string);

            /* Clean */
            fann_destroy(ann);
            fann_destroy_train(data);

            break;
        }
    }

    // printf("\nX1\n");

    /* Store the encrypted svm_model result in the cloud */
    fwrite(p_result_encrypted, 1, result_size, ofp_result);
    fwrite(result_gcm_mac, 1, AESGCM_MAC_SIZE, ofp_result_mac);
    // printf("\nX2\n");
    fclose(ofp_result);
    fclose(ofp_result_mac);




    return 0;
}



/* Close the enclave */
int enclave_close(enclave_info_t* enclave_info)
{
	FILE* OUTPUT = stdout;
	sgx_status_t status = SGX_SUCCESS;
	int ret = 0;
    // Need to close the RA key state.
    if(INT_MAX != enclave_info->context)
    {  
        ret = ECALL_enclave_ra_close(enclave_info->enclave_id, &status, enclave_info->context);
        if(SGX_SUCCESS != ret || status)
        {
            fprintf(OUTPUT, "\nError, call ECALL_enclave_ra_close fail [%s]. Session closed.\n", __FUNCTION__);
            return 1;
        }
        // fprintf(OUTPUT, "\nCall ECALL_enclave_ra_close success.\n\n");
        fprintf(OUTPUT, "\nEnclave closed.\n\n");
    }
    sgx_destroy_enclave(enclave_info->enclave_id);
    return 0;
}


/* OCall functions */
void OCALL_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate the input string to prevent buffer overflow. */
    printf("%s", str);
}


