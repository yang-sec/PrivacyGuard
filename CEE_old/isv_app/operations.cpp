/* 
* Contract Execution Environment (CEE): enclave_operation.cpp
* 
* 
* PrivacyGuard Project (2018), Virginia Tech CNSR Lab
*/

#include "operations.h"

#include <stdio.h>
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

#include "svm.h"
// #include "svm-train.c"
// #include "opencv2/core.hpp"
// #include "opencv2/opencv_modules.hpp"
// #include "opencv2/opencv.hpp"
// using namespace cv;

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


int remote_attest_enclave(int socket_num, int* p_challenger_type, enclave_info_t* enclave_info)
{
    FILE* OUTPUT = stdout;
    sgx_status_t status = SGX_SUCCESS;
    enclave_info->context = INT_MAX;
    int busy_retry_time = 4;
    int enclave_lost_retry_time = 1;

	// Remote attestation config
	int ret = 0;
	bool attestation_passed = true;
	char msg_recv[2048] = {0};
	ra_samp_request_header_t *p_msg0_full = NULL;
	ra_samp_response_header_t *p_msg0_resp_full = NULL;
	ra_samp_request_header_t *p_msg1_full = NULL;
	ra_samp_response_header_t *p_msg2_full = NULL;
	sgx_ra_msg3_t *p_msg3 = NULL;
	ra_samp_request_header_t* p_msg3_full = NULL;
	ra_samp_response_header_t* p_att_result_msg_full = NULL;


    // Authentication message from challenger
    int auth_msg_size = sizeof(auth_msg_header_t);
    auth_msg_header_t* auth_msg = (auth_msg_header_t*)malloc(auth_msg_size);

	if( read(socket_num, msg_recv, auth_msg_size) < 0)
	{
		printf("recv failed.\n");
		return -1;
	}
    auth_msg = (auth_msg_header_t*) msg_recv;
	printf("\n-------------------- New attestation --------------------\nChallenger Type = %u (1: DataConsumer, 2: iDataAgent)\n", auth_msg->challenger_type);
	*p_challenger_type = auth_msg->challenger_type;


	/*-------------------------------------
		Call ECALL_enclave_init_ra()
	---------------------------------------*/
	{
		do
	    {
	        ret = ECALL_enclave_init_ra(enclave_info->enclave_id, &status, false, &enclave_info->context);
	    } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

	    if(SGX_SUCCESS != ret || status)
	    {
	        fprintf(OUTPUT, "\nError, call ECALL_enclave_init_ra fail. [%s]", __FUNCTION__);
	        return 1;;
	    }
	    printf("Enclave is ready for attestation.\n");
	    // fprintf(OUTPUT, "\nCall ECALL_enclave_init_ra success. [%s]\n", __FUNCTION__);
	}


    /*------------------------------------
 		Generate msg0 and send it to SP
 	--------------------------------------*/
 	{
	    p_msg0_full = (ra_samp_request_header_t*) malloc(sizeof(ra_samp_request_header_t) +sizeof(uint32_t));
	    if (NULL == p_msg0_full)
	    {
	        ret = -1;
	        goto CLEANUP;
	    }
	    p_msg0_full->type = TYPE_RA_MSG0;
	    p_msg0_full->size = sizeof(uint32_t);

	    *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t)) = enclave_info->extended_epid_group_id;
	    // {
	    //     fprintf(OUTPUT, "\nMSG0 body generated -\n");
	    //     PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);
	    // }

	    ret = ra_network_send_receive_real(socket_num, p_msg0_full, &p_msg0_resp_full);

	    if (ret != 0)
	    {
	        fprintf(OUTPUT, "Error, ra_network_send_receive for MSG0 failed [%s].\n", __FUNCTION__);
	        goto CLEANUP;
	    }
	    fprintf(OUTPUT, "Sent MSG0 to the challenger.\n");
	}


    /*---------------------------------------
		Continue the attestation process.
 	-----------------------------------------*/
 	{
	    // isv application call uke sgx_ra_get_msg1
	    p_msg1_full = (ra_samp_request_header_t*) malloc(sizeof(ra_samp_request_header_t) + sizeof(sgx_ra_msg1_t));
	    if(NULL == p_msg1_full)
	    {
	        ret = -1;
	        goto CLEANUP;
	    }
	    p_msg1_full->type = TYPE_RA_MSG1;
	    p_msg1_full->size = sizeof(sgx_ra_msg1_t);
	    
	    do
	    {
	        ret = sgx_ra_get_msg1(enclave_info->context, enclave_info->enclave_id, sgx_ra_get_ga, (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full + sizeof(ra_samp_request_header_t)));
	        sleep(1); // Wait between retries
	    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
	    
	    if(SGX_SUCCESS != ret)
	    {
	        ret = -1;
	        fprintf(OUTPUT, "Error, call sgx_ra_get_msg1 fail [%s]. ret = %d\n", __FUNCTION__, ret);
	        goto CLEANUP;
	    }
	    // else
	    // {
	    //     fprintf(OUTPUT, "\nCall sgx_ra_get_msg1 success.\n");
	    //     fprintf(OUTPUT, "\nMSG1 body generated -\n");
	    //     PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
	    // }


	    // The ISV application sends msg1 to the SP to get msg2,
	    // msg2 needs to be freed when no longer needed.
	    // The ISV decides whether to use linkable or unlinkable signatures.
	    
	    ret = ra_network_send_receive_real(socket_num, p_msg1_full, &p_msg2_full);

	    if(ret != 0 || !p_msg2_full)
	    {
	        fprintf(OUTPUT, "Error, ra_network_send_receive for msg1 failed [%s].\n", __FUNCTION__);
	    }
	    else
	    {
	        // Successfully sent msg1 and received a msg2 back.
	        // Time now to check msg2.
	        if(TYPE_RA_MSG2 != p_msg2_full->type)
	        {
	            fprintf(OUTPUT, "Error, didn't get MSG2 in response to MSG1. [%s].\n", __FUNCTION__);
	        }

	        // fprintf(OUTPUT, "\nSent MSG1 to remote attestation service provider. Received the following MSG2:\n");
	        // PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full, sizeof(ra_samp_response_header_t) + p_msg2_full->size);

	        // fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
	        // PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);
	    }

	    fprintf(OUTPUT, "Sent MSG1 to the challenger. Received MSG2 back.\n");

	    sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full + sizeof(ra_samp_response_header_t));

    	uint32_t msg3_size = 0;
	    busy_retry_time = 3;

	    // The ISV app now calls uKE sgx_ra_proc_msg2,
	    // The ISV app is responsible for freeing the returned p_msg3!!
	    do
	    {
	        ret = sgx_ra_proc_msg2(
							enclave_info->context, 
							enclave_info->enclave_id, 
							sgx_ra_proc_msg2_trusted, 
							sgx_ra_get_msg3_trusted, 
							p_msg2_body, 
							p_msg2_full->size, 
							&p_msg3, 
							&msg3_size);
					        } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
		
	    if(!p_msg3)
	    {
	        fprintf(OUTPUT, "Error, call sgx_ra_proc_msg2 fail. p_msg3 = 0x%p [%s].\n", p_msg3, __FUNCTION__);
	        ret = -1;
	        goto CLEANUP;
	    }

	    if(SGX_SUCCESS != (sgx_status_t)ret)
	    {
	        fprintf(OUTPUT, "Error, call sgx_ra_proc_msg2 fail. ret = 0x%08x [%s].\n", ret, __FUNCTION__);
	        ret = -1;
	        goto CLEANUP;
	    }
	    // else
	    // {
	    //     fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2 success.\n");
	    //     fprintf(OUTPUT, "\nMSG3 - \n");
	    //     PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);
	    // }

	    p_msg3_full = (ra_samp_request_header_t*)malloc(sizeof(ra_samp_request_header_t) + msg3_size);
	    if(NULL == p_msg3_full)
	    {
	        ret = -1;
	        goto CLEANUP;
	    }
	    p_msg3_full->type = TYPE_RA_MSG3;
	    p_msg3_full->size = msg3_size;
	    if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size))
	    {
	        fprintf(OUTPUT,"Error: INTERNAL ERROR - memcpy failed in [%s].\n", __FUNCTION__);
	        ret = -1;
	        goto CLEANUP;
	    }

	    // The ISV application sends msg3 to the SP to get the attestation
	    // result message, attestation result message needs to be freed when
	    // no longer needed. The ISV service provider decides whether to use
	    // linkable or unlinkable signatures. The format of the attestation
	    // result is up to the service provider. This format is used for
	    // demonstration.  Note that the attestation result message makes use
	    // of both the MK for the MAC and the socket for the secret. These keys are
	    // established from the SIGMA secure channel binding.
	    
	   	ret = ra_network_send_receive_real(socket_num, p_msg3_full, &p_att_result_msg_full);


	    if(ret || !p_att_result_msg_full)
	    {
	        ret = -1;
	        fprintf(OUTPUT, "Error, sending msg3 failed [%s].\n", __FUNCTION__);
	        goto CLEANUP;
	    }

		sample_ra_att_result_msg_t * p_att_result_msg_body = (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full + sizeof(ra_samp_response_header_t));

	    if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type)
	    {
	        ret = -1;
	        fprintf(OUTPUT, "Error. Sent MSG3 successfully, but the message received was NOT of type att_msg_result. Type = %d. [%s].\n", p_att_result_msg_full->type, __FUNCTION__);
	        goto CLEANUP;
	    }
	    else
	    {
	        fprintf(OUTPUT, "Sent MSG3 to the challenger. Received a result message containing the challenger's secret.\n");
	        // fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED - ");
		    // PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body, p_att_result_msg_full->size);
	    }

	    

	    // Check the MAC using MK on the attestation result message.
	    // The format of the attestation result message is ISV specific.
	    // This is a simple form for demonstration. In a real product,
	    // the ISV may want to communicate more information.
	    ret = ECALL_verify_att_result_mac(
									enclave_info->enclave_id, 
									&status, 
									enclave_info->context, 
									(uint8_t*)&p_att_result_msg_body->platform_info_blob, 
									sizeof(ias_platform_info_blob_t), 
									(uint8_t*)&p_att_result_msg_body->mac, 
									sizeof(sgx_mac_t));

	    if((SGX_SUCCESS != ret) || (SGX_SUCCESS != status))
	    {
	        ret = -1;
	        fprintf(OUTPUT, "Error: INTEGRITY FAILED - attestation result message MK based cmac failed in [%s].\n", __FUNCTION__);
	        goto CLEANUP;
	    }

	    // Check the attestation result for pass or fail.
	    // Whether attestation passes or fails is a decision made by the ISV Server.
	    // When the ISV server decides to trust the enclave, then it will return success.
	    // When the ISV server decided to not trust the enclave, then it will return failure.
	    if(0 != p_att_result_msg_full->status[0] || 0 != p_att_result_msg_full->status[1])
	    {
	        fprintf(OUTPUT, "Error, attestation result message MK based cmac failed in [%s].\n", __FUNCTION__);
	        attestation_passed = false;
	    }

	    // The attestation result message should contain a field for the Platform
	    // Info Blob (PIB).  The PIB is returned by attestation server in the attestation report.
	    // It is not returned in all cases, but when it is, the ISV app
	    // should pass it to the blob analysis API called sgx_report_attestation_status()
	    // along with the trust decision from the ISV server.
	    // The ISV application will take action based on the update_info.
	    // returned in update_info by the API.  
	    // This call is stubbed out for the sample.
	    // 
	    // sgx_update_info_bit_t update_info;
	    // ret = sgx_report_attestation_status(&p_att_result_msg_body->platform_info_blob, attestation_passed ? 0 : 1, &update_info);

	    // Get the shared secret sent by the server using SK (if attestation passed)
	    if(attestation_passed)
	    {
	        ret = ECALL_put_secret_data(
		        				  enclave_info->enclave_id,
	                              &status,
	                              enclave_info->context,
	                              p_att_result_msg_body->secret.payload,
	                              p_att_result_msg_body->secret.payload_size,
	                              p_att_result_msg_body->secret.payload_tag,
	                              (uint8_t)*p_challenger_type);
	        if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status))
	        {    		
	            fprintf(OUTPUT, "Error, attestation result message secret using SK based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x\n", __FUNCTION__, ret, status);
	            goto CLEANUP;
	        }
	    }
	}


CLEANUP:
    // Free up response messages buffer
    ra_free_network_response_buffer(p_msg0_resp_full);
    ra_free_network_response_buffer(p_msg2_full);
    ra_free_network_response_buffer(p_att_result_msg_full);

    // p_msg3 is malloc'd by the untrusted KE library. App needs to free.
    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg0_full);

    return ret;
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



int enclave_compute_task2(enclave_info_t* enclave_info, int DO_ID, int file_num)
{
	FILE* OUTPUT = stdout;
	sgx_status_t status = SGX_SUCCESS;
	int ret = 0;

	char buf1[100], buf2[100];
	sprintf(buf1, "../CloudStorage/Reserved_ML_Data%d/%d.txt", DO_ID, file_num);  // change to DO's folder later!
	sprintf(buf2, "../CloudStorage/Reserved_ML_Data%d/%d_mac.txt", DO_ID, file_num);
	// sprintf(buf3, "../CloudStorage/user%d/%d_result.txt", DO_ID, file_num);
	FILE *ifp_data = fopen(buf1, "rb");
	FILE *ifp_mac = fopen(buf2, "rb");
	// FILE *ofp_result = fopen(buf3, "wb");
	uint32_t ctext_size, mac_size;

	// Computation result message init
	int result_size = sizeof(struct svm_model);
	int comp_result_msg_size = sizeof(computation_result_msg_t) + result_size;
	computation_result_msg_t* p_comp_result_msg = (computation_result_msg_t*) malloc(sizeof(computation_result_msg_t));
	p_comp_result_msg->result_encrypted = (uint8_t*) malloc(result_size);
	p_comp_result_msg->DO_ID = DO_ID;
	p_comp_result_msg->file_num = file_num;

	// Obtain file size
  	fseek(ifp_data, 0, SEEK_END);
  	ctext_size = ftell(ifp_data);
  	rewind(ifp_data);

  	fseek(ifp_mac, 0, SEEK_END);
  	mac_size = ftell(ifp_mac);
  	rewind(ifp_mac); 	

	uint8_t* data;
	uint8_t* data_mac;
	// uint8_t* result;
	data =  (uint8_t*) malloc (sizeof(uint8_t) * ctext_size);
	data_mac = (uint8_t*) malloc (sizeof(uint8_t) * mac_size);
	// result = (uint8_t*) malloc (sizeof(uint8_t) * 4); // The result is stored in a 4-byte char array

	fread(data, 1, ctext_size, ifp_data);
	fread(data_mac, 1, mac_size, ifp_mac);
	fclose(ifp_data);
	fclose(ifp_mac);

	ret = ECALL_compute_task2(
							enclave_info->enclave_id,
							&status,
							enclave_info->context,
							data,
							ctext_size,
							data_mac,
							p_comp_result_msg->result_encrypted,
							1000,
							p_comp_result_msg->result_gcm_mac,
							rand_key_DC_encrypted,
							rand_key_DC_mac);

    if(SGX_SUCCESS != ret || status)
    {
        fprintf(OUTPUT, "\nError, call ECALL_computate_task1 fail [%s]. Session closed.\n", __FUNCTION__);
        return 1;
    }

    /* To do: store the encrypted svm_model result in the cloud */

    return 0;
}





int record_datause(enclave_info_t* enclave_info, char* contract_addr)
{
	int i, ret;
	sgx_status_t status = SGX_SUCCESS;

	uint8_t signature_v_r_s[65] = " ";

    char buffer1[1000], buffer2[1000], nodejs_arg[1000];

    /* Six fields of a nake transaction */
    long gas_price = 1000000000;
    long gasLimit = 200000;
    char to[100];
    long value = 0;
    char data[500];

    /* Convert the rand_key_DC to string: uint8_t => ascii-table 2-digit hex*/
    char rand_key_DC_encrypted_string[100];
    for(i = 0;i < 16;i++)
    {
        sprintf(&rand_key_DC_encrypted_string[2*i], "%02X", rand_key_DC_encrypted[i]);
    }
    
    sprintf(to, "0x%s", contract_addr); // The contract address
    sprintf(data, "0x7bd780c7%s", rand_key_DC_encrypted_string);


    /* Get the digest (RLP_hash) of the nake transaction */
    sprintf(nodejs_arg, "%ld %ld %s %ld %s", gas_price, gasLimit, to, value, data);
    sprintf(buffer1, "node isv_app/txEncode.js %s", nodejs_arg);
    printf("%s\n", buffer1);

    ret = system(buffer1);
    if(ret != 0){return 1;}

    FILE *ifp = fopen("isv_app/txRLP_hash.txt", "rb");

	uint8_t txDigest[32];
	fread(txDigest, sizeof(uint8_t), 32, ifp);
	fclose(ifp);

	/* Sign the transaction inside enclave */
    ECALL_signEthereumTransaction(
                    enclave_info->enclave_id,
                    &status,
                    enclave_info->context,
                    txDigest,
                    signature_v_r_s);

    // printf("\nsignature_v: %02x", signature_v_r_s[0]);

    // printf("\nsignature_r: ");
    // for (i = 1; i <= 32; i++){
    //     printf("%02x", signature_v_r_s[i]);
    // }

    // printf("\nsignature_s: ");
    // for (i = 33; i <= 64; i++){
    //     printf("%02x", signature_v_r_s[i]);
    // }

    /* Marshal the raw transaction hex and publize it */
    FILE *ofp_v = fopen("isv_app/txSignature_v.txt", "wb");
    FILE *ofp_r = fopen("isv_app/txSignature_r.txt", "wb");
    FILE *ofp_s = fopen("isv_app/txSignature_s.txt", "wb");
    fwrite(signature_v_r_s     , sizeof(uint8_t),  1, ofp_v);
    fwrite(signature_v_r_s + 1 , sizeof(uint8_t), 32, ofp_r);
    fwrite(signature_v_r_s + 33, sizeof(uint8_t), 32, ofp_s);
    fclose(ofp_v);
    fclose(ofp_r);
    fclose(ofp_s);

    sprintf(buffer2, "node isv_app/txSend.js %s", nodejs_arg);
    printf("\n\n%s\n", buffer2);

    ret = system(buffer2);
    if(ret != 0){return 1;}

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