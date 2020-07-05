/* 
* Contract Execution Environment (CEE)
* 
* PrivacyGuard Project (2018), Virginia Tech CNSR Lab
*/



#include <stdio.h>
#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>  //inet_addr
#include <sys/time.h>

#include <thread>
#include <vector>

#include <limits.h>
#include <unistd.h>
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"
// #include "isv_enclave_u.h"
// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"
#include "network_ra.h"
// Needed to create enclave and do ecall.
#include "sgx_urts.h"
// Needed to query extended epid group id.
#include "sgx_uae_service.h"
#include "service_provider.h"
#include "operations.h"



using namespace std;

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#define N_TCS 4


double stime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (double)tp.tv_sec + (double)tp.tv_usec / 1000000;
}


// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
// #define _T(x) x
int main(int argc, char* argv[])
{
    bool running = true;
    bool enclave_on = false;
    enclave_info_t enclave_info;
    double tic, toc;
    

    /* Communication config */
    int socket_init;
    bool sock_on = false;
    int sock_num[2]; // 0: DC, 1: iDA

    /* Init enclave*/
    enclave_on = enclave_init(&enclave_info); 

    while(running)
    {
        char inputChar;
        
        cout << "\n## CEE ## ready to roll:" << endl
        << "Press 1: Computation task 1. (averaging)" << endl
        << "Press 2: Computation task 2. (training svm model)." << endl
        << "Press 3: Computation task 3. (training nn model)." << endl
        << "Press 4: Computation task 3. (training nn model) outside enclave." << endl
        << "Press 5: Computation task 3. (training nn model) multi-threading." << endl
        << "Press 6: Computation task 3. (training nn model) outside enclave multi-threading." << endl
        << "Press 0: Exit." << endl;
        cin >> inputChar;

        switch(inputChar)
        {
            case '0':
            {
                running = false;

                if (enclave_on) 
                {
                    enclave_close(&enclave_info);
                }
                break;
            }

            case '1':
            {
                enclave_compute_task1(&enclave_info, 1, 1); // DO 1's file 1 (will change later)
                break;
            }

            case '2':
            {
                encrypt_file(1, 102);
                // enclave_compute_task(&enclave_info, 2, 1, 102); // operation 2, user 1's file 102
                break;
            }

            case '3':
            {
                int i, N, ret;
                double tTotal = 0;

                // if(enclave_on)
                // {
                //     enclave_close(&enclave_info);
                // }
                // enclave_on = enclave_init(&enclave_info); 

                cout << "Number of files: ";
                cin  >> N;

                sgx_status_t status = SGX_SUCCESS;
                ret = ECALL_enclave_DO_config(
                        enclave_info.enclave_id,
                        &status,
                        N);

                /* Encrypt all data files with the known key */
                for(i = 0; i < N; i++)
                {
                    // int encrypt_file(int DO_ID, int file_num)
                    encrypt_file(1, i+1);
                }
                
                tic = stime(); 
                // enclave_compute_task(&enclave_info, Request_DC, Request_type, Request_start, Request_end, Request_operation);
                // enclave_compute_task(&enclave_info, 1, 0, 1, N, 3);
                ECALL_test_enclave(enclave_info.enclave_id, &status);
                toc = stime(); 
                tTotal += (toc - tic);
                
                printf("\nAverage time for Computing task 3: %f seconds\n", tTotal);
                break;
            }

            case '4':
            {
                int i, N, sum;
                double tTotal = 0;

                cout << "Number of files: ";
                cin  >> N;

                tic = stime(); 
                // enclave_compute_task_normal(0, 1, N, 3);

                /* Test C++ performance */
                for(i = 0; i < 10000000; i++)
                {
                    sum = sum + i;
                }

                toc = stime(); 
                tTotal += (toc - tic);
                
                printf("\nAverage time for Computing task 3: %f seconds\n", tTotal);
                break;
            }

            case '5':
            {
                int th, i, N, ret;
                double tTotal = 0;

                vector<std::thread> threads;

                // if(enclave_on)
                // {
                //     enclave_close(&enclave_info);
                // }
                // enclave_on = enclave_init(&enclave_info); 

                cout << "Number of files: ";
                cin  >> N;

                sgx_status_t status = SGX_SUCCESS;
                ret = ECALL_enclave_DO_config(
                        enclave_info.enclave_id,
                        &status,
                        N);

                /* Encrypt all data files with the known key */
                for(i = 0; i < N; i++)
                {
                    // int encrypt_file(int DO_ID, int file_num)
                    encrypt_file(1, i+1);
                }

                tic = stime(); 

                /* Parallel execution */
                for(th = 0; th < N_TCS; th++)
                {
                    threads.emplace_back(enclave_compute_task, &enclave_info, 1, 0, 1, N, 3);
                }

                for (thread & t : threads) 
                {
                    t.join();
                }
                threads.clear();
                
                toc = stime(); 
                tTotal += (toc - tic);
                
                printf("\nAverage time for Computing task 3: %f seconds\n", tTotal);
                break;
            }

            case '6':
            {
                int th, i, N;
                double tTotal = 0;

                vector<std::thread> threads;

                cout << "Number of files: ";
                cin  >> N;

                tic = stime(); 

                /* Parallel execution */
                for(th = 0; th < N_TCS; th++)
                {
                    threads.emplace_back(enclave_compute_task_normal, 0, 1, N, 3);
                }

                for (thread & t : threads) 
                {
                    t.join();
                }
                threads.clear();

                toc = stime(); 
                tTotal += (toc - tic);
                
                printf("\nAverage time for Computing task 3: %f seconds\n", tTotal);
                break;
            }
        }
    }
	
    return 0;
}