#ifndef _OPERATIONS_H_
#define _OPERATIONS_H_


#include <stdint.h>
#include "enclave_u.h"
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "remote_attestation_result.h"
#include "network_ra.h"


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

// typedef struct _auth_msg_header_t{
//     uint8_t type; 
//     uint8_t challenger_type;   
// }auth_msg_header_t;

typedef struct _computation_result_msg_t{
    uint8_t type;
    int DO_ID;
    int file_num;
    uint8_t result_encrypted[4];
    uint8_t result_gcm_mac[16];
}computation_result_msg_t;

typedef struct _operation_config_msg_t{
    int DC_ID;
    int type;
    int start;
    int end;
    int operation;
}operation_config_msg_t;

typedef struct _K_result_msg_t{  // to iDA/DB
    int DO_ID;
    int file_num;
    uint8_t K_result_en[AESGCM_KEY_SIZE];
    uint8_t K_result_mac[AESGCM_MAC_SIZE];
}K_result_msg_t;


bool enclave_init(enclave_info_t* enclave_info);

int remote_attest_enclave(int sock_num, int* p_challenger_type, enclave_info_t* enclave_info);

int enclave_close(enclave_info_t* enclave_info);

int remote_attest_challenger(int sock_num, int type, uint8_t* secret, int secret_size);

int process_DO_data(enclave_info_t* enclave_info, do_provision_data_header_t* DO_msg_header, uint8_t* DO_data);

int checkContractStatus(char* contract_addr);

#if defined(__cplusplus)
}
#endif
#endif