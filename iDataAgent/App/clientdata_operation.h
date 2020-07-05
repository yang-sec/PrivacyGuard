#ifndef _CLIENTDATA_OPERATION_H_
#define _CLIENTDATA_OPERATION_H_


#if defined(__cplusplus)
extern "C" {
#endif



/* Generate AES key shell command
openssl enc -aes-128-cbc -k secret -P -md sha256 -nosalt
*/



int getdata_encrypt_store();
int encrypt_store();

// int VerifyDeposit();

#if defined(__cplusplus)
}
#endif

#endif