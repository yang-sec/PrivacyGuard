#ifndef _ENCLAVE_UTILITIES_H
#define _ENCLAVE_UTILITIES_H

#define LIBSVM_VERSION 323

#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

void printf(const char *fmt, ...);

double s2dou(uint8_t* str, int len);

void u_array2c_array(char *c_arr, uint8_t *u_arr, int len);

void string2u_array(uint8_t *u_arr, std::string str, int len);

float fann_rand(float min_value, float max_value);

#ifdef __cplusplus
}
#endif

#endif /* _ENCLAVE_UTILITIES_H */