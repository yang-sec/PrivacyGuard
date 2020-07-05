#ifndef _ENCLAVE_OPERATION_H_
#define _ENCLAVE_OPERATION_H_


#include "isv_enclave_u.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "remote_attestation_result.h"

// #include <omp.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define AESGCM_KEY_SIZE 16
#define AESGCM_MAC_SIZE 16
#define KECCAK_HASH_SIZE 32

#define TASK1_RESULT_SIZE 4       // Bytes. Summation of single digits
#define TASK2_RESULT_SIZE 1000    // Bytes. SVM model
#define TASK3_RESULT_SIZE 10000   // Bytes. ANN model



/* Enum for all possible operation message types (except for attestation related) between CEE and DC, iDA*/
typedef enum _op_msg_type_t
{
     TYPE_OP_AUTH,       // Authentication message
     TYPE_OP_COMP_RES,   // computation result message
}op_msg_type_t;

typedef struct _enclave_info_t{
	sgx_enclave_id_t enclave_id;
	sgx_ra_context_t context;
	uint32_t extended_epid_group_id;
}enclave_info_t;

typedef struct _auth_msg_header_t{
    uint8_t type; 
    uint8_t challenger_type;   
}auth_msg_header_t;

typedef struct _computation_result_msg_t{
    uint8_t type;
    int DO_ID;
    int file_num;
    uint8_t result_gcm_mac[AESGCM_MAC_SIZE];
    uint8_t* result_encrypted;
}computation_result_msg_t;



bool enclave_init(enclave_info_t* enclave_info);

int remote_attest_enclave(int sock_num, int* p_challenger_type, enclave_info_t* enclave_info);

int enclave_close(enclave_info_t* enclave_info);

int enclave_compute_task1(enclave_info_t* enclave_info, int user_ID, int file_num);

// int enclave_compute_task(enclave_info_t* enclave_info, int task_num, int user_ID, int file_num);
int enclave_compute_task(enclave_info_t* enclave_info, int Request_DC, int Request_type, int Request_start, int Request_end, int Request_operation);

int enclave_compute_task_normal(int Request_type, int Request_start, int Request_end, int Request_operation);

// Produce an off-line transaction that invokes the record() function in the contract
// The transaction is marshalled outside the enclave but signed inside enclave
int record_datause(enclave_info_t* enclave_info,  char* contract_addr);

int encrypt_file(int DO_ID, int file_num);


#if defined(__cplusplus)
}
#endif
#endif