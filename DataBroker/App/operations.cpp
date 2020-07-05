#include "operations.h"
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <limits.h>
#include <unistd.h>    //write
#include <dirent.h>
#include <errno.h>

#include "attestation_service.h"
#include "network_ra.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "sgx_ukey_exchange.h"
#include "enclave_u.h"

#define ENCLAVE_PATH "enclave.signed.so"
#define _T(x) x


#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif


/* Global variables */
// rwlock_t lock_eid;
// sgx_enclave_id_t global_eid = 0;

void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len);


bool enclave_init(enclave_info_t* enclave_info)
{
    FILE* OUTPUT = stdout;
    int ret = 0;
    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    sgx_status_t status = SGX_SUCCESS;

    // Enclave config
    enclave_info->enclave_id = 1;
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
    printf("\n-------------------- New attestation --------------------\nDO ID = %u.\n", auth_msg->challenger_type);
    *p_challenger_type = auth_msg->challenger_type;


    /*-------------------------------------
        Call ECALL_enclave_init_ra()
    ---------------------------------------*/
    {
        do
        {
            printf("[ra_init] enclave_info->context = %u\n", enclave_info->context);

            ret = ECALL_enclave_init_ra(enclave_info->enclave_id, &status, false, &enclave_info->context);
        } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

        if(SGX_SUCCESS != ret || status)
        {
            fprintf(OUTPUT, "\nError, call ECALL_enclave_init_ra fail. [%s], error code: 0x%04X", __FUNCTION__, ret);
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
            printf("[get_msg1] enclave_info->context = %u\n", enclave_info->context);

            ret = sgx_ra_get_msg1(enclave_info->context, enclave_info->enclave_id, sgx_ra_get_ga, (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full + sizeof(ra_samp_request_header_t)));
            sleep(0.001); // Wait between retries
        } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
        
        if(SGX_SUCCESS != ret)
        {
            fprintf(OUTPUT, "Error, call sgx_ra_get_msg1 fail [%s]. ret = %d\n", __FUNCTION__, ret);
            ret = -1;
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
            printf("[proc_msg2] enclave_info->context = %u\n", enclave_info->context);

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
            fprintf(OUTPUT, "Error, call sgx_ra_proc_msg2 fail. p_msg3 = 0x%p [%s]. Error code: %d.\n", p_msg3, __FUNCTION__, ret);
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

        // Note: normally DataOwner doesn't need to pass any secret to iDataAgent or DataBroker. But in case it needs to, put_secret_data is still enabled here.
        if(attestation_passed)
        {
            ret = ECALL_put_secret_data(
                                  enclave_info->enclave_id,
                                  &status,
                                  enclave_info->context,
                                  p_att_result_msg_body->secret.payload,
                                  p_att_result_msg_body->secret.payload_size,
                                  p_att_result_msg_body->secret.payload_tag,
                                  auth_msg->challenger_type);
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


int remote_attest_init_enclave(enclave_info_t* enclave_info)
{
    FILE* OUTPUT = stdout;
    sgx_status_t status = SGX_SUCCESS;
    enclave_info->context = INT_MAX;
    int enclave_lost_retry_time = 1;
    int ret = 0;

    /*-------------------------------------
        Call ECALL_enclave_init_ra()
    ---------------------------------------*/
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
    return ret;
}

int remote_attest_enclave_parallel(int socket_num, int* p_challenger_type, enclave_info_t* enclave_info_original)
{
    FILE* OUTPUT = stdout;
    sgx_status_t status = SGX_SUCCESS;
    // enclave_info->context = INT_MAX;
    int busy_retry_time = 5;
    int enclave_lost_retry_time = 1;

    int i;
    enclave_info_t* enclave_info = (enclave_info_t*) malloc(sizeof(enclave_info_t));
    /* Attestation context for each thread */
    // for(i = 0; i < N; i++)
    // {
    //     enclave_info_local[i]->enclave_id = enclave_info->enclave_id;
    //     enclave_info_local[i]->context = INT_MAX;
    //     enclave_info_local[i]->extended_epid_group_id = enclave_info->extended_epid_group_id;
    // }
    enclave_info->enclave_id = enclave_info_original->enclave_id;
    enclave_info->context = INT_MAX;
    enclave_info->extended_epid_group_id = enclave_info_original->extended_epid_group_id;

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
    printf("\n-------------------- New attestation --------------------\nDO ID = %u.\n", auth_msg->challenger_type);
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
            fprintf(OUTPUT, "\nError, call ECALL_enclave_init_ra fail. [%s], error code: 0x%04X", __FUNCTION__, ret);
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
            
            sleep(0.001); // Wait between retries
        } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

        if(SGX_SUCCESS != ret)
        {
            fprintf(OUTPUT, "Error, call sgx_ra_get_msg1 fail [%s]. error code = 0x%04X\n", __FUNCTION__, ret);
            ret = -1;
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
            fprintf(OUTPUT, "Error, call sgx_ra_proc_msg2 fail. p_msg3 = 0x%p [%s]. Error code: 0x%04X\n", p_msg3, __FUNCTION__, ret);
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

        // Note: normally DataOwner doesn't need to pass any secret to iDataAgent or DataBroker. But in case it needs to, put_secret_data is still enabled here.
        if(attestation_passed)
        {
            ret = ECALL_put_secret_data(
                                  enclave_info->enclave_id,
                                  &status,
                                  enclave_info->context,
                                  p_att_result_msg_body->secret.payload,
                                  p_att_result_msg_body->secret.payload_size,
                                  p_att_result_msg_body->secret.payload_tag,
                                  auth_msg->challenger_type);
            if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status))
            {           
                fprintf(OUTPUT, "Error, attestation result message secret using SK based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x\n", __FUNCTION__, ret, status);
                goto CLEANUP;
            }
        }

        

    }

    /* update the original ra context */
    enclave_info_original->context = enclave_info->context;


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


// sock_num: the socket connecting to the CEE
// type: 1: DC, 2: iDataAgent
int remote_attest_challenger(int sock_num, int type, uint8_t* secret, int secret_size)
{
	char msg_recv[2048] = {0};
    int ret = 0;
    int status = 0;
    FILE* OUTPUT = stdout;

	// Pre-allocate space for messages
    int auth_msg_size = sizeof(auth_msg_header_t);
	int msg0_size = sizeof(ra_samp_request_header_t) + sizeof(uint32_t);
	int msg1_size = sizeof(ra_samp_request_header_t) + 68;
    int msg2_size = sizeof(ra_samp_response_header_t) + 168;
    int msg3_size = sizeof(ra_samp_request_header_t) + 1452;
    int att_res_size = sizeof(ra_samp_response_header_t) + 145 + secret_size; // att msg body without payload: 145 bytes
    auth_msg_header_t* auth_msg = (auth_msg_header_t*)malloc(auth_msg_size);
	ra_samp_request_header_t* msg0_full = (ra_samp_request_header_t*)malloc(msg0_size);
    ra_samp_request_header_t* msg1_full = (ra_samp_request_header_t*)malloc(msg1_size);
    ra_samp_response_header_t* msg2_full = (ra_samp_response_header_t*)malloc(msg2_size);
    ra_samp_request_header_t* msg3_full = (ra_samp_request_header_t*)malloc(msg3_size);
    ra_samp_response_header_t* att_res_full = (ra_samp_response_header_t*)malloc(att_res_size);

    // Send authentication message to TCE
    auth_msg->challenger_type = type;
    if ( write(sock_num, auth_msg, auth_msg_size) < 0 ) {
    	printf("Send authentication message failed.\n");
    	goto CLEANUP;
    }

    // Receive msg0 from the TCE
    if( read(sock_num, msg_recv , msg0_size) < 0) {
        printf("Receive MSG0 failed.\n");
        goto CLEANUP;
    }
    msg0_full = (ra_samp_request_header_t*) msg_recv;
    printf("\nMSG0 received. Body size: %d.\n", msg0_full->size);
    //PRINT_BYTE_ARRAY(OUTPUT, msg0_full->body, msg0_full->size);


    ret = sp_ra_proc_msg0_req((const sample_ra_msg0_t*)((uint8_t*)msg0_full + sizeof(ra_samp_request_header_t)), msg0_full->size);
    if (0 != ret)
    {   
        fprintf(stderr, "Error, call sp_ra_proc_msg0_req fail [%s].\n", __FUNCTION__);
    }

    // Receive msg1 from and send msg2 to the TCE
    
    if( read(sock_num, msg_recv , msg1_size) < 0)
    {
        printf("Receive MSG1 failed.\n");
        goto CLEANUP;
    }
    msg1_full = (ra_samp_request_header_t*) msg_recv;
    printf("MSG1 received. Body size: %d.\n", msg1_full->size);
    // PRINT_BYTE_ARRAY(OUTPUT, msg1_full->body, msg1_full->size);	    

	ret = sp_ra_proc_msg1_req((const sample_ra_msg1_t*)((uint8_t*)msg1_full + sizeof(ra_samp_request_header_t)), msg1_full->size, &msg2_full);
    if(0 != ret)
    {   
        fprintf(stderr, "Error, call sp_ra_proc_msg1_req fail [%s].\n", __FUNCTION__);
    }
    if( write(sock_num , msg2_full , msg2_size) < 0)
    {
        puts("Send MSG2 failed.\n");
        goto CLEANUP;
    }

    printf("MSG2 sent. Body size: %d.\n", msg2_full->size);


    // Receive msg3 from the CCE    
    if( read(sock_num, msg_recv , msg3_size) < 0)
    {
        printf("Receive MSG3 failed.\n");
        goto CLEANUP;
    }
    msg3_full = (ra_samp_request_header_t*) msg_recv;
    printf("MSG3 containing attestation report received. Body size: %d \n", msg3_full->size);
    // PRINT_BYTE_ARRAY(OUTPUT, msg3_full->body, msg3_full->size);

    ret = sp_ra_proc_msg3_req((const sample_ra_msg3_t*)((uint8_t*)msg3_full + sizeof(ra_samp_request_header_t)), msg3_full->size, &att_res_full, secret, secret_size);
    if(0 != ret)
    {   
        fprintf(stderr, "\nError, call sp_ra_proc_msg3_req fail [%s].\n", __FUNCTION__);
        goto CLEANUP;
    }

    printf("\nAttestation accepted!\n");

    // Provision the secret
    if( write(sock_num , att_res_full , att_res_size) < 0)
    {
        puts("\nSecret provisioning failed.\n");
        goto CLEANUP;
    }

    printf("\nProvisioning data keys to CEE. SUCCESS!.\n");
 
    // PRINT_BYTE_ARRAY(OUTPUT, att_res_full->body, att_res_full->size);

CLEANUP:
	// close(sock_num);
	ra_free_network_response_buffer(msg2_full);
	ra_free_network_response_buffer(att_res_full);
    free(auth_msg);

    return ret;
}




/* Encrypt DO's data with ran_key_DO and store it in cloud */
// int process_DO_data(enclave_info_t* enclave_info, int DO_ID, uint8_t* p_data, int data_size, uint8_t* p_data_gcm_mac)
int process_DO_data(enclave_info_t* enclave_info, do_provision_data_header_t* DO_msg_header,  uint8_t* DO_data)
{
    sgx_status_t status = SGX_SUCCESS;
    int i, ret = 0;
    uint8_t* result_encrypted = (uint8_t*) malloc(DO_msg_header->data_size);
    uint8_t result_gcm_mac[SAMPLE_AESGCM_MAC_SIZE];

    /* Put DO data in enclave, encrypt them using DO_data_key, and get them out */
    ret = ECALL_encrypt_DO_data(
                        enclave_info->enclave_id,
                        &status,
                        enclave_info->context,
                        DO_msg_header->DO_ID,
                        DO_data,
                        DO_msg_header->data_size,
                        DO_msg_header->data_mac,
                        result_encrypted,
                        result_gcm_mac);

    /* Store the encrypted DO data in cloud */
    char buf1[100], buf2[100];
    sprintf(buf1, "../CloudStorage/DO%d_%d_en.txt",  DO_msg_header->DO_ID, DO_msg_header->data_num);
    sprintf(buf2, "../CloudStorage/DO%d_%d_mac.txt", DO_msg_header->DO_ID, DO_msg_header->data_num);
    FILE *ofp_ctext = fopen(buf1, "wb");
    FILE *ofp_mac = fopen(buf2, "wb");

    fwrite(result_encrypted, 1, DO_msg_header->data_size, ofp_ctext);
    fwrite(result_gcm_mac,   1, SAMPLE_AESGCM_MAC_SIZE,   ofp_mac);
    fclose(ofp_ctext);
    fclose(ofp_mac);

    printf("Encrypted and stored in cloud.\n");

    free(result_encrypted);
    
    return ret;
}


int checkContractStatus(char* ContractAddress)
{
    char buffer1[1000];
    sprintf(buffer1, "node App/txCheckContract.js 0x%s", ContractAddress);
    printf("%s\n", buffer1);
    system(buffer1);
}

int confirmRegistries(char* ContractAddress)
{
    int ret = 0;
    char buffer1[1000], nodejs_arg[1000];

    /* Six fields of a naked transaction */
    long gas_price = 1000000000;
    long gasLimit = 4000000;
    char to[100];
    long value = 0; // unit: wei
    char data[500];

    sprintf(to, "0x%s", ContractAddress);
    sprintf(data, "0x7022b58e"); // Function: request()

    /* Get the digest (RLP_hash) of the nake transaction */
    sprintf(nodejs_arg, "%ld %ld %s %ld %s", gas_price, gasLimit, to, value, data);
    sprintf(buffer1, "node App/txSendDirectly.js %s", nodejs_arg);
    printf("%s\n", buffer1);

    ret = system(buffer1);
    return ret;
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




/* OCall functions */

/* To display content in enclave */
void OCALL_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate the input string to prevent buffer overflow. */
    printf("%s", str);
}

/*  */