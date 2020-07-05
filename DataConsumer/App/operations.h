#ifndef _OPERATIONS_H_
#define _OPERATIONS_H_

#include "remote_attestation_result.h"
#include "string"

#if defined(__cplusplus)
extern "C" {
#endif


#define AESGCM_KEY_SIZE 16
#define AESGCM_MAC_SIZE 16
#define KECCAK_HASH_SIZE 32

#define TASK1_RESULT_SIZE 4       // Bytes. Summation of single digits
#define TASK2_RESULT_SIZE 1000    // Bytes. SVM model
#define TASK3_RESULT_SIZE 10000   // Bytes. ANN model


typedef struct _K_result_hash_msg_t{  // to DC
    int DO_ID;
    int file_num;
    uint8_t K_result_hash_en[KECCAK_HASH_SIZE];
    uint8_t K_result_hash_mac[AESGCM_MAC_SIZE];
    uint8_t C_result_hash_en[KECCAK_HASH_SIZE]; // Hash of the encrypted result
    uint8_t C_result_hash_mac[AESGCM_MAC_SIZE];
}K_result_hash_msg_t;

typedef struct _operation_config_msg_t{
    int DC_ID;
    int type;
    int start;
    int end;
    int operation;
}operation_config_msg_t;

void u_array2c_array(char *c_arr, uint8_t *u_arr, int len);

void string2u_array(uint8_t *u_arr, std::string str, int len);

int request_Contract(char* ContractAddress, int range_start, int range_end, int operation, double payment);

int cancelTransaction(char* contract_addr);


#if defined(__cplusplus)
}
#endif
#endif