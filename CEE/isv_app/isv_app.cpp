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
// #include <ctime>       //time()
#include <sys/time.h>
#include <thread>
#include <vector>

#include <limits.h>
#include <unistd.h>
#include "remote_attestation_result.h" // Needed for definition of remote attestation messages.
#include "isv_enclave_u.h"
#include "sgx_ukey_exchange.h" // Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "network_ra.h"
#include "sgx_urts.h" // Needed to create enclave and do ecall.
#include "sgx_uae_service.h" // Needed to query extended epid group id.
#include "service_provider.h"
#include "operations.h"


using namespace std;

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif


#define N_TCS 4

int DataOwner_ID = 0;
int DataOwner_data_num = 0;
int Operation_num = 0;


double stime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (double)tp.tv_sec + (double)tp.tv_usec / 1000000;
}


int main(int argc, char* argv[])
{
    bool running = true;
    bool enclave_on = false;
    enclave_info_t enclave_info;
    double tic, toc, ttic, ttoc;
    char transactionType[2][20] = {"DataOwner", "DataBroker"};

    int Request_DC;
    int Request_type;
    int Request_start;
    int Request_end;
    int Request_operation;


    /* Communication config */
    int socket_init, sock_iDA_DB, sock_DC;
    bool socks_on = false;

    // Socket config
    int socket_new, c;
    struct sockaddr_in self_server, challenger_client;
    int sock_opt_enabled = 1;
    char* msg_sent;
    char msg_recv[2048];

    /* For parallel attesting to DOs */
    int sock_DO_init, sock_DO;
    struct sockaddr_in server_DO, client_DO;
    sock_DO_init = socket(AF_INET , SOCK_STREAM , 0);
    setsockopt(sock_DO_init, SOL_SOCKET, SO_REUSEADDR, &sock_opt_enabled, sizeof(int));
    if (sock_DO_init == -1) { printf("Could not create socket for DO."); return 1;}
    server_DO.sin_family = AF_INET;
    server_DO.sin_addr.s_addr = INADDR_ANY;
    server_DO.sin_port = htons( 8001 );
    if( bind(sock_DO_init,(struct sockaddr *)&server_DO , sizeof(server_DO)) < 0) { printf("bind failed"); return 1;}

    // Create socket
    socket_init = socket(AF_INET , SOCK_STREAM , 0);
    setsockopt(socket_init, SOL_SOCKET, SO_REUSEADDR, &sock_opt_enabled, sizeof(int));
    if (socket_init == -1) { printf("Could not create socket."); }
    socks_on = true;

    self_server.sin_family = AF_INET;
    self_server.sin_addr.s_addr = INADDR_ANY;
    self_server.sin_port = htons( 8888 );

    //Bind
    if( bind(socket_init,(struct sockaddr *)&self_server , sizeof(self_server)) < 0) { printf("bind failed"); return 0;}

    int ret;
    int challenger_type; // 1: DataConsumer, 2: iDataAgent
    char challenger[2][20] = {"DataConsumer", "iDataAgent"};

    operation_config_msg_t *operation_config_msg = (operation_config_msg_t *) malloc(sizeof(operation_config_msg_t));


    while(running)
    {
        char inputChar;
        
        cout << "\n## CEE ## ready to roll:" << endl
        << "Press #: Initiate an enclave then attest to all DataOwners parallely." << endl
        << "Press 1: Initiate an enclave then attest to iDataAgent and DataConsumer." << endl
        << "Press 2: Perform the computation task requested by DataConsumer." << endl
        << "Press 3: Send K_result to iDA/DB and {K_result_hash, C_result_hash} to DC." << endl
        << "Press 0: Exit." << endl;
        cin >> inputChar;

        switch(inputChar)
        {
            case '0':
            {
                running = false;
                if(socks_on == true)
                {
                    close(sock_iDA_DB);
                    close(sock_DC);
                    close(socket_init);
                    printf("All sockets closed.\n");
                }

                if (enclave_on) 
                {
                    enclave_close(&enclave_info);
                }
                break;
            }

            case '#':
            {
                int DO_NUM;
                cout << "Enter number of DataOwners: ";
                cin >> DO_NUM;

                int pid;
                sgx_status_t status = SGX_SUCCESS;

                vector<std::thread> threads;

                /* Temporary variables */
                int tmp_DO_ID;
                bool DO_attested[DO_NUM] = {false};
                int num_DO_attested = 0, num_threads = 0;

                /* Init enclave */
                int enclave_id = 1;
                if (!enclave_on)
                {
                    enclave_on = enclave_init(&enclave_info);
                }

                /* Configure the enclave to assign space for DOs' data keys */
                ret = ECALL_enclave_DO_config(enclave_info.enclave_id, &status, DO_NUM);

                /* Init RA */
                // ret = remote_attest_init_enclave(&enclave_info);

                /* Wait and listen for connections */
                printf("Please connect the DataOwner to this address: 192.168.0.24:8001\n");
                listen(sock_DO_init, DO_NUM);
                c = sizeof(struct sockaddr_in);

                while(num_DO_attested < DO_NUM && num_threads < N_TCS)
                {
                    printf("\nWaiting for attestation request from DOs [%d remain]... \n", DO_NUM - num_DO_attested);

                    sock_DO = accept(sock_DO_init, (struct sockaddr *)&client_DO, (socklen_t*)&c);

                    if(num_DO_attested == 0) ttic = stime();  
                    // tic = stime();

                    if (sock_DO < 0) 
                    {
                        perror("accept failed");
                        close(sock_DO);
                        break;
                    }

                    threads.emplace_back(remote_attest_enclave_parallel, sock_DO, &tmp_DO_ID, &enclave_info);
                    
                    num_DO_attested ++;
                    num_threads ++;
                    // close(sock_DO);

                    if(num_threads == N_TCS || num_DO_attested == DO_NUM)
                    {
                        for (thread & t : threads) 
                        {
                            t.join();
                        }
                        threads.clear();
                        num_threads = 0;
                    }
                }

                toc = stime();
                printf("\n----- Attestation to DOs is successful. Time: %f seconds -----\n", toc-ttic);
                
                break;
            }

            case '1':
            {
                bool ra_flag[2] = {false, false};

                
                /* Init enclave*/
                if (!enclave_on)
                {
                    tic = stime();
                    enclave_on = enclave_init(&enclave_info);
                    toc = stime();
                    printf("Enclave initialization time: %f\n", toc-tic);
                }


                /* Attest to DC and iDA */
                listen(socket_init , 3);
                c = sizeof(struct sockaddr_in);
                printf("Please connect the challenger to this address: 192.168.0.24:8888\n");

                while(!(ra_flag[0] && ra_flag[1]))
                { 
                    socket_new = accept(socket_init, (struct sockaddr *)&challenger_client, (socklen_t*)&c);

                    if (socket_new < 0)
                    {
                        perror("accept failed");
                        close(socket_new);
                        continue;
                    }

                    /* Receive operation configuration */
                    if( read(socket_new, operation_config_msg, sizeof(operation_config_msg_t)) < 0)
                    {
                        printf("recv failed.\n");
                        continue;
                    }

                    // printf("%s\n", (char *)operation_config_msg);

                    Request_DC        = operation_config_msg->DC_ID;
                    Request_type      = operation_config_msg->type;
                    Request_start     = operation_config_msg->start;
                    Request_end       = operation_config_msg->end;
                    Request_operation = operation_config_msg->operation;
                    printf("\nDataConsumer%d requests [%s]'s contract. Requested range: %d ~ %d, Operation: %d\n", Request_DC, transactionType[Request_type], Request_start, Request_end, Request_operation);
                
                    /* Config the enclave to assign space for DOs' data keys */
                    sgx_status_t status = SGX_SUCCESS;
                    ret = ECALL_enclave_DO_config(
                            enclave_info.enclave_id,
                            &status,
                            Request_end - Request_start + 1);

                    /* Begin attestation */
                    tic = stime(); 

                    ret = remote_attest_enclave(socket_new, &challenger_type, &enclave_info);
                    if ( ret != 0 )
                    {
                        printf("\nAttestation to %s failed. Please restart the attestation.\n\n", challenger[challenger_type-1]);
                        close(socket_new);
                        continue;
                    }
    
                    printf("-------- Attestation for %s is completed --------\n", challenger[challenger_type-1]); 
                    ra_flag[challenger_type-1] = true;

                    /* Save socket state */
                    switch(challenger_type)
                    {
                        case 1: sock_DC = socket_new; break;
                        case 2: sock_iDA_DB = socket_new; break;
                    }

                    toc = stime(); 
                    printf("Time for CEE attesting to %s: %f seconds\n", challenger[challenger_type-1], toc-tic);
                }

                printf("\n## CEE has attested for both DataConsumner and iDataAgent. Please proceed to the computation task.\n\n");

                break;
            }

            case '2':
            {
                tic = stime();
                enclave_compute_task(&enclave_info, Request_DC, Request_type, Request_start, Request_end, Request_operation);
                toc = stime(); 
                printf("Time for CEE computation task: %f seconds\n", toc-tic);
                break;
            }

            case '3':
            {
                tic = stime();
                send_K_result_msgs(&enclave_info, sock_iDA_DB, sock_DC);
                toc = stime(); 
                printf("Time for CEE sending results to DC and iDA/DB: %f seconds\n", toc-tic);

                printf("\n\nCEE's job is Completed. Next for DC and DB/iDA:");
                printf("\n1. DC: Call the contract's computationComplete() with K_result_hash.");
                printf("\n2. DB/iDA: Call the contract's completeTransaction() with K_result.");
                printf("\n3. DC: fetch K_result from contract if it is available. Or cancel if timeout. \n\n");
    
                break;
            }
        }
    }
	
    return 0;
}
