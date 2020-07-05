#include "operations.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cstdlib>
#include <time.h>
#include <fstream>
#include <sys/time.h>
using namespace std;


double sstime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (double)tp.tv_sec + (double)tp.tv_usec / 1000000;
}

/* Data preparation. */
// dataType = 1: For simple summation.
// dataType = 2: For machine learning operations. Each data point is a vector. 
int generate_data_type(int DO_ID, int data_counter, int num_data_points, int dataType)
{
    int index = data_counter + 1;

    switch(dataType)
    {
        case 1:
        {
            int j;
            srand(time(NULL));
            ofstream outfile ("DataFiles/DO" + to_string(DO_ID) + "_" + to_string(index) + ".txt");
            for (j = 1; j <= num_data_points; j++)
            {
                outfile << rand() % 10; // data range: 0~9
            }       
            outfile.close();
            break;
        }

        case 2:
        {
            char buffer1[1000];
            sprintf(buffer1, "python3 process_adult_data.py %d %d %d", DO_ID, index, num_data_points);
            system(buffer1);
        }
    }
    return index;
}

/* Send a transaction invoking the register function of DO's/DB's contract */
// payment unit: ether
int register_data_on_Contract(double* fTime, char *contract_addr, char *DO_address, char *DO_pkey, int contractType, int data_num, int operation, double price, char* DC_addr, int DC_action)
{
    int ret = 0;
    char buffer1[1000], nodejs_arg[1000];

    /* Six fields of a naked transaction */
    long gas_price = 1000000000;
    long gasLimit = 300000;
    char to[100];
    long value = 0; // unit: wei
    char data[500];

    char address[100], pkey[200];
    sprintf(to, "%s", contract_addr);
    sprintf(address, "%s", DO_address);
    sprintf(pkey, "%s", DO_pkey);

    long price_wei = price * 1000000000000000000;

    switch(contractType)
    {
        case 0: // DO's own contract
            sprintf(data, "0xcc527740%064X%064X%064lX%024X%s%064X", data_num, operation, price_wei, 0, DC_addr, DC_action);
            break;
        case 1: // DB contract
            sprintf(data, "0x80ac1323%064X%064lX%024X%s%064X", operation, price_wei, 0, DC_addr, DC_action);
    }
    

    /* Get the digest (RLP_hash) of the nake transaction */
    sprintf(nodejs_arg, "%ld %ld %s %ld %s %s %s", gas_price, gasLimit, to, value, data, address, pkey);
    sprintf(buffer1, "node App/txSendDirectly.js %s", nodejs_arg);
    printf("%s\n", buffer1);

    ret = system(buffer1);
    *fTime = sstime();

    return ret;
}