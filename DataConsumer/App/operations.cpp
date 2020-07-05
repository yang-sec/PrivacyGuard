#include "operations.h"
#include <stdio.h>
#include <stdlib.h>


/* Send a transaction invoking the request function of DO or DB's contract */
// payment unit: ether
// For DO's contract: [range_start, range_end] refers to the range of data files
// For DB's contract: [range_start, range_end] refers to the range of DOs
int request_Contract(char* ContractAddress, int range_start, int range_end, int operation, double payment)
{
    int ret = 0;
    char buffer1[1000], nodejs_arg[1000];

    /* Six fields of a naked transaction */
    long gas_price = 1000000000;
    long gasLimit = 6000000;
    char to[100];
    long long int value = payment * 1000 * 1e15; // unit: wei (1 ether = 1e18 wei)
    char data[500];

    sprintf(to, "0x%s", ContractAddress);
    sprintf(data, "0xad352967%064x%064x%064x", range_start, range_end, operation);

    /* Get the digest (RLP_hash) of the nake transaction */
    sprintf(nodejs_arg, "%ld %ld %s %lld %s", gas_price, gasLimit, to, value, data);
    sprintf(buffer1, "node App/txSendDirectly.js %s", nodejs_arg);
    printf("%s\n", buffer1);

    ret = system(buffer1);
    return ret;
}

/* Send a transaction invoking the cancel function of DO or DB's contract */
int cancelTransaction(char* contract_addr)
{
    int ret = 0;
    char buffer1[1000], nodejs_arg[1000];

    /* Six fields of a naked transaction */
    long gas_price = 1000000000;  // unit: wei
    long gasLimit = 500000;
    char to[100];
    long value = 0; // unit: wei
    char data[500];

    sprintf(to, "0x%s", contract_addr);
    sprintf(data, "0xea8a1af0");

    /* Get the digest (RLP_hash) of the nake transaction */
    sprintf(nodejs_arg, "%ld %ld %s %ld %s", gas_price, gasLimit, to, value, data);
    sprintf(buffer1, "node App/txSendDirectly.js %s", nodejs_arg);
    printf("%s\n", buffer1);

    ret = system(buffer1);
    return ret;
}

/* Convert uint8_t array to char array like this: {0x12, 0xde} ==> "12de" */
void u_array2c_array(char *c_arr, uint8_t *u_arr, int len)
{
    int i;
    for(i = 0; i < len; i++)
    {
        sprintf(&c_arr[2*i], "%02x", u_arr[i]);
    }
}

/* Convert string to uint8_t array like this: "12de" ==> {0x12, 0xde} */
// len: size of the output u_arr (Bytes)
void string2u_array(uint8_t *u_arr, std::string str, int len)
{
    int i;
    char c1, c2, high, low;
    for(i = 0; i < len; i++)
    {
        c1 = str[2*i];
        c2 = str[2*i+1];

        if(c1 < 0x40) // number char
        {
            high = c1 - 48;
        }
        else
        {
            high = c1 - 87;
        }

        if(c2 < 0x40) // number char
        {
            low = c2 - 48;
        }
        else
        {
            low = c2 - 87;
        }

        u_arr[i] = high * 16 + low;
    }
}