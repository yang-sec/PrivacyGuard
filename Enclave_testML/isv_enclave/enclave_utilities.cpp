#include "include/enclave_utilities.h"
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "isv_enclave_t.h"  /* print_string */
#include "mbusafecrt.h"

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    OCALL_print_string(buf);
}


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

/* Convert uint8_t array to char array like this: {0x12, 0xde} ==> "12de" */
// len: size of the input u_arr (Bytes)
void u_array2c_array(char *c_arr, uint8_t *u_arr, int len)
{
    int i;
    for(i = 0; i < len; i++)
    {
        sprintf_s(&c_arr[2*i], 4, "%02x", u_arr[i]);
    }
}

/* Convert string to uint8_t array like this: "12de" ==> {0x12, 0xde} */
// len: size of the output u_arr (Bytes)
void string2u_array(uint8_t *u_arr, std::string str, int len)
{
    int i;
    char c1, c2, high, low;
    for(i = 0; i < 32; i++)
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

/* Return a random number from a certain range */
float fann_rand(float min_value, float max_value)
{
    /* Using SGX's random number generator */
    sgx_status_t sgx_ret = SGX_SUCCESS;
    unsigned char rand_buff[4];
    sgx_ret = sgx_read_rand(rand_buff, 4);
    int rand_num = (int)(rand_buff[0]) + 16*(int)(rand_buff[1]) + 16*16*(int)(rand_buff[2]) + 16*16*16*(int)(rand_buff[3]);
    float rand_num_01 = (float)(rand_num % 100000) / 100000;
    return (min_value + (max_value - min_value) * rand_num_01);
}