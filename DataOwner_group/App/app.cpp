/* 
* DataOwner (DO): app.cpp
* 
* PrivacyGuard Project (2018), Virginia Tech CNSR Lab
*/

#include <stdio.h>
#include <iostream>
#include <thread>
#include <vector>
#include <math.h>       /* sqrt */
// #include <ctime>       //time()
#include <sys/time.h>
#include <string.h>    //strlen
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
// #include "operations_dc.h"
#include "attestation_service.h"
#include "network_ra.h"
#include "operations.h"
#include "DO_sim.h"
using namespace std;

#define N_THREADS 160

/* ------- Parameters -------- */
int DO_ID[N_THREADS];
char DO_Address[N_THREADS][200];
char DO_PrivateKey[N_THREADS][200];
char DO_ContractAddress[N_THREADS][200];

// char ContractAddress[100]     = "0x208D3CEdFE8918298A726264B578A9BA2AE8c85B"; // DO's own contract
char DBContractAddress[100]   = "0x7CAC532e3E93666247a56D987e25AEa5050B8cee";
char DataConsumerAddress[100] =   "65843BE2Dd4ad3bC966584E2Fcbb38838d49054B";
int N_data = 100;       // Number of data points per file
int dataType = 2;       // 2: Labeled training set
double price = 0.01;    // ethers
int OperationNum = 3;   // 3: Training ANN classifier 
/* --------------------------- */



uint8_t DO_nonce[4] = {0xFF, 0xFF, 0xFF, 0xFF};


double stime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (double)tp.tv_sec + (double)tp.tv_usec / 1000000;
}


int main(int argc , char **argv)
{
    int k, ret;
    int data_counter = 0;
    double tic, toc;

    bool running = true, iDA_connected = false;

    /* DO config */
    int DO_NUM;
    cout << "Enter number of DataOwners (max: " << N_THREADS << "): ";
    cin >> DO_NUM;

    /* Communication config */
    int socket_iDA;
    struct sockaddr_in server_iDA;
    socket_iDA = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_iDA == -1) { printf("Could not create socket."); return 1;}
    server_iDA.sin_family = AF_INET;
    server_iDA.sin_addr.s_addr = inet_addr("192.168.1.178"); // iDA's IP address
    server_iDA.sin_port = htons( 8001 );

    /* DO config: assign each DO an account address and a contract address */ 
    for(k = 0; k < DO_NUM; k++)
    {
        DO_ID[k] = k+1;
        memcpy(DO_Address[k], DO_sim_CandidateSet[k][0], 200);
        memcpy(DO_PrivateKey[k], DO_sim_CandidateSet[k][1], 200);
        memcpy(DO_ContractAddress[k], DO_sim_CandidateSet[k][2], 200);
        // cout << DO_Address[k] << " " << DO_PrivateKey[k] << " " << DO_ContractAddress[k] << endl;
    }
    cout << DO_NUM << "DataOwners assigned" << endl;

    /* Operation begins */
    while(running)
    {
        char inputChar;
        cout << "\n## DataOwner Group ## ready to roll." << endl
        << "Press 1: Attest iDataAgent/DataBroker's enclave." << endl
        << "Press 2: Generate a new data file." << endl
        << "Press 3: Register the new data on my own contract." << endl
        << "Press 4: Register the new data on DataBroker's contract" << endl
        << "Press 5: Provision the new data to iDataAgent/DataBroker." << endl
        << "Press 0: Exit." << endl;
        cin >> inputChar;

        switch(inputChar)
        {
            case '0':
                running = false;
                close(socket_iDA);
                printf("\nAll sockets closed.\n");
                break;       
                
            case '1':
            {
                int i, pid;

                for(i = 0; i < DO_NUM; i++)
                {
                    /* Create child process */
                    pid = fork();
                    // printf("pid = %d\n", pid);

                    if (pid < 0) {perror("ERROR on fork"); exit(1);}

                    if (pid == 0) // Child process
                    {
                        /* Connect to iDA */
                        if(iDA_connected)
                        {
                            close(socket_iDA);
                        }
                        socket_iDA = socket(AF_INET , SOCK_STREAM , 0);
                        iDA_connected = true;

                        if(connect(socket_iDA , (struct sockaddr *)&server_iDA , sizeof(server_iDA)) < 0) {printf("connect error.\n"); break;}
                        
                        /* Begin attesting */
                        ret = remote_attest_challenger(socket_iDA, i+1, DO_nonce, sizeof(DO_nonce)); // No need to provision anything at this time
                        if ( ret != 0 )
                        {
                            printf("\nAttestation to iDataAgent's enclave failed. Terminate.\n");
                        }
                        else
                        {
                            printf("\nAttestation to iDataAgent/DataBroker's enclave success!\n");
                        }

                        close(socket_iDA);
                        // printf("End of the child process\n");
                        exit(0);
                    }
                }
                
                break;
            }

            case '2':
            {
                vector<thread> threads;

                

                for(k = 0; k < DO_NUM; k++)
                {
                    threads.emplace_back(generate_data_type, DO_ID[k], data_counter, N_data, dataType);
                    // data_counter = generate_data_type(DO_ID[k], data_counter, N_data, dataType); // data points per file
                    printf("DO%d_%d.txt generated.\n", DO_ID[k], data_counter);
                }

                for (thread & t : threads) 
                {
                    t.join();
                }
                threads.clear();

                data_counter ++;                

                break;
            }

            case '3':
            {
                vector<std::thread> threads;
                double times[DO_NUM], time_sum = 0, diff_square_sum = 0, time_avg, time_std;

                tic = stime();

                for(k = 0; k < DO_NUM; k++)
                {
                    threads.emplace_back(register_data_on_Contract, &times[k], DO_ContractAddress[k], DO_Address[k], DO_PrivateKey[k], 0, data_counter, OperationNum, price, DataConsumerAddress, 0);
                    // register_data_on_Contract(&times[k], DO_ContractAddress[k], DO_Address[k], DO_PrivateKey[k], 0, data_counter, OperationNum, price, DataConsumerAddress, 0);
                }
                for (thread & t : threads) 
                {
                    t.join();
                }

                /* Compute average and std */
                for(k = 0; k < DO_NUM; k++)
                {
                    time_sum += (times[k] - tic);
                }

                time_avg = time_sum / DO_NUM;

                for(k = 0; k < DO_NUM; k++)
                {
                    diff_square_sum += (times[k] - tic - time_avg) * (times[k] - tic - time_avg);
                }
                time_std = sqrt(diff_square_sum / DO_NUM);
                printf("Average time for DataOwner registering: %f seconds. STD: %f\n", time_avg, time_std);
                threads.clear();

                break;
            }

            case '4':
            {
                vector<std::thread> threads;
                double times[DO_NUM], time_sum = 0, diff_square_sum = 0, time_avg, time_std;

                tic = stime();

                for(k = 0; k < DO_NUM; k++)
                {
                    threads.emplace_back(register_data_on_Contract, &times[k], DBContractAddress, DO_Address[k], DO_PrivateKey[k], 1, 0, OperationNum, price, DataConsumerAddress, 0);
                    // register_data_on_Contract(&times[k], DBContractAddress, DO_Address[k], DO_PrivateKey[k], 1, 0, OperationNum, price, DataConsumerAddress, 0);
                }
                for (thread & t : threads) 
                {
                    t.join();
                }

                /* Compute average and std */
                for(k = 0; k < DO_NUM; k++)
                {
                    time_sum += (times[k] - tic);
                }

                time_avg = time_sum / DO_NUM;

                for(k = 0; k < DO_NUM; k++)
                {
                    diff_square_sum += (times[k] - tic - time_avg) * (times[k] - tic - time_avg);
                }
                time_std = sqrt(diff_square_sum / DO_NUM);
                printf("Average time for DataOwner registering: %f seconds. STD: %f\n", time_avg, time_std);
                threads.clear();

                break;
            }

            case '5':
            {
                int i, pid;
                for(i = 0; i < DO_NUM; i++)
                {
                    // /* Create child process */
                    // pid = fork();
                    // // printf("pid = %d\n", pid);

                    // if (pid < 0) {perror("ERROR on fork"); exit(1);}

                    // if (pid == 0) // Child process
                    // {
                    //     /* Connect to iDA */
                    //     if(iDA_connected)
                    //     {
                    //         close(socket_iDA);
                    //     }
                    //     socket_iDA = socket(AF_INET , SOCK_STREAM , 0);
                    //     iDA_connected = true;

                    //     if(connect(socket_iDA , (struct sockaddr *)&server_iDA , sizeof(server_iDA)) < 0) {printf("connect error.\n"); break;}
                        
                    //     ret = provision_data(socket_iDA, DO_ID[i], data_counter);

                    //     if(ret == 0){
                    //         printf("Provisioning file %d-%d.txt to iDA/DB [SUCCESS].\n", DO_ID[i], data_counter);
                    //     }
                    //     else{
                    //         printf("Provisioning file %d-%d.txt to iDA/DB [FAILED].\n", DO_ID[i], data_counter);
                    //     }

                    //     close(socket_iDA);
                    //     // printf("End of the child process\n");
                    //     exit(0);
                    // }
                    
                    /* Connect to iDA */
                    if(iDA_connected)
                    {
                        close(socket_iDA);
                    }
                    socket_iDA = socket(AF_INET , SOCK_STREAM , 0);
                    iDA_connected = true;

                    if(connect(socket_iDA , (struct sockaddr *)&server_iDA , sizeof(server_iDA)) < 0) {printf("connect error.\n"); break;}
                    
                    ret = provision_data(socket_iDA, DO_ID[i], data_counter);

                    if(ret == 0){
                        printf("Provisioning file %d-%d.txt to iDA/DB [SUCCESS].\n", DO_ID[i], data_counter);
                    }
                    else{
                        printf("Provisioning file %d-%d.txt to iDA/DB [FAILED].\n", DO_ID[i], data_counter);
                    }

                    close(socket_iDA);
                }

                break;
            }
        }
    }	
    return 0;
}


