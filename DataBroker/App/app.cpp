/* 
* iDataAgent
* 
* PrivacyGuard Project (2018), Virginia Tech CNSR Lab
*/


#include <stdio.h>
#include <string.h>    //strlen
#include <stdint.h>
// #include <ctime>       //time()
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include <iostream>
#include <cstdlib>
#include <thread>
#include <vector>

#include "network_ra.h"
#include "clientdata_operation.h"
#include "operations.h"
#include "attestation_service.h"
#include "enclave_u.h"
using namespace std;



/* ------- Parameters -------- */
#define N_TCS 128
char ContractAddress[100]   = "7CAC532e3E93666247a56D987e25AEa5050B8cee"; // DB
/* --------------------------- */


double stime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (double)tp.tv_sec + (double)tp.tv_usec / 1000000;
}


int main(int argc , char **argv)
{
    double tic, toc, ttic, ttoc;
    bool running = true;
    bool enclave_on = false;
    bool ready_to_attest_CEE = false;
    uint32_t cur_DC_ID;
    enclave_info_t enclave_info;

    int i;
    int Operation_num = 0;

    K_result_msg_t *K_result_msg = (K_result_msg_t *) malloc(sizeof(K_result_msg_t));

    /* DO config */
    int DO_NUM;
    cout << "Enter number of DataOwners: ";
    cin >> DO_NUM;

    int DO_List[DO_NUM]; // number of files stored

    /* Socket communication config */
    char msg_recv[2048] = {0};
    int sock_DO_init, sock_DC_init;                      // Local sockets for accepting incoming connections
    int sock_DO, sock_DC, sock_CEE;                      // Outgoing sockets
    int sock_opt_enabled = 1;
    struct sockaddr_in server_DO, server_DC, server_CEE;
    struct sockaddr_in client_DO, client_DC;
    int c, ret = 0;

    sock_DO_init = socket(AF_INET , SOCK_STREAM , 0);
    setsockopt(sock_DO_init, SOL_SOCKET, SO_REUSEADDR, &sock_opt_enabled, sizeof(int));
    if (sock_DO_init == -1) { printf("Could not create socket for DO."); return 1;}
    server_DO.sin_family = AF_INET;
    server_DO.sin_addr.s_addr = INADDR_ANY;
    server_DO.sin_port = htons( 8001 );
    if( bind(sock_DO_init,(struct sockaddr *)&server_DO , sizeof(server_DO)) < 0) { printf("bind failed"); return 1;}

    sock_DC_init = socket(AF_INET , SOCK_STREAM , 0);
    setsockopt(sock_DC_init, SOL_SOCKET, SO_REUSEADDR, &sock_opt_enabled, sizeof(int));
    if (sock_DC_init == -1) { printf("Could not create socket for DC."); return 1;}
    server_DC.sin_family = AF_INET;
    server_DC.sin_addr.s_addr = INADDR_ANY;
    server_DC.sin_port = htons( 8002 );
    if( bind(sock_DC_init,(struct sockaddr *)&server_DC , sizeof(server_DC)) < 0) { printf("bind failed"); return 1;}

    /* To record operation request from DC */
    int Request_DC, Request_type, Request_start, Request_end, Request_operation;
    char transactionType[2][20] = {"iDataAgent", "DataBroker"};

    /* Service begins */
    while(running)
    {
        char inputChar;
        cout << "\n## DataBroker ## ready to roll:" << endl
        << "Press 1: Attest enclave to DataOwners." << endl
        << "Press #: Attest enclave tp DataOwners parallely." << endl
        << "Press 2: Listen for DataOwners' data provisions." << endl
        << "Press 3: Confirm new registries on contract." << endl
        << "Press 4: Listen for requests from DataConsumers." << endl
        << "Press 5: Attest the CEE enclave, provision DataOwner's decrypting key." << endl
        << "Press 6: Send completeTransaction to contract." << endl
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
                close(sock_DO);
                close(sock_DC);
                close(sock_CEE);
                close(sock_DC_init);
                close(sock_DO_init);
                break;
            }

            case '1':
            {
                /* Init enclave */
                int enclave_id = 1;
                if (!enclave_on)
                {
                    tic = stime();
                    enclave_on = enclave_init(&enclave_info);
                    toc = stime();
                    printf("Enclave initialization time: %f\n", toc-tic);
                }

                /* Config the enclave to assign space for DOs' data keys */
                sgx_status_t status = SGX_SUCCESS;
                ret = ECALL_enclave_DO_config(
                        enclave_info.enclave_id,
                        &status,
                        DO_NUM);

                /* Temporary variables */
                int tmp_DO_ID;
                bool DO_attested[DO_NUM] = {false};
                int num_DO_attested = 0;
                
                /* Wait and listen for connections */
                printf("Please connect the DataOwner to this address: 192.168.0.24:8001\n");
                listen(sock_DO_init, DO_NUM);
                c = sizeof(struct sockaddr_in);

                while(num_DO_attested < DO_NUM)
                {
                    printf("\nWaiting for attestation request from DOs [%d remain]... \n", DO_NUM - num_DO_attested);

                    sock_DO = accept(sock_DO_init, (struct sockaddr *)&client_DO, (socklen_t*)&c);

                    if(num_DO_attested == 0) ttic = stime();

                    tic = stime();

                    if (sock_DO < 0) 
                    {
                        perror("accept failed");
                        close(sock_DO);
                        break;
                    }

                    // Perform remote attestation to the challenger
                    ret = remote_attest_enclave(sock_DO, &tmp_DO_ID, &enclave_info);
                    if ( ret != 0 )
                    {
                        printf("\nAttestation failed. Please restart the attestation.\n\n");
                        close(sock_DO);
                        break;
                    }
                    
                    toc = stime();
                    printf("\n----- Attestation to DO %d is successful. Time: %f seconds -----\n", tmp_DO_ID, toc-tic);

                    if(!DO_attested[tmp_DO_ID-1])
                    {
                        DO_attested[tmp_DO_ID-1] = true;
                        num_DO_attested ++;
                    }

                    close(sock_DO);
                }

                ttoc = stime();
                printf("\nAttestation to the %d DOs is completed. Total time: %f seconds\n", DO_NUM, ttoc-ttic);
                
                
                // close(sock_DO_init);
                break;
            }

            case '#':
            {
                int pid;
                sgx_status_t status = SGX_SUCCESS;

                // thread th[DO_NUM];
                vector<thread> threads;

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

                    ////////////////////////////////////////////////////////////////////////////////////
                    // /* Create child process */
                    // pid = fork();
                    // printf("pid = %d\n", pid);

                    // if (pid < 0) {perror("ERROR on fork"); exit(1);}

                    // if (pid == 0) // Child process
                    // { 
                    //     /* Init enclave */
                    //     // int enclave_id = 1;
                    //     // if (!enclave_on)
                    //     // {
                    //     //     enclave_on = enclave_init(&enclave_info);
                    //     // }

                    //     // /* Configure the enclave to assign space for DOs' data keys */
                    //     // ret = ECALL_enclave_DO_config(enclave_info.enclave_id, &status, DO_NUM);

                    //     /* Perform remote attestation to the challenger */
                    //     tic = stime();
                    //     // ret = remote_attest_enclave(sock_DO, &tmp_DO_ID, &enclave_info);
                    //     ret = remote_attest_enclave_parallel(sock_DO, &tmp_DO_ID, &enclave_info);

                    //     if ( ret != 0 )
                    //     {
                    //         printf("\nAttestation failed. Please restart the attestation.\n\n");
                    //         close(sock_DO);
                    //         enclave_close(&enclave_info);
                    //         printf("End of the child process\n");
                    //         exit(0);
                    //     }
                        
                    //     toc = stime();
                    //     printf("\n----- Attestation to DO %d is successful. Time: %f seconds -----\n", tmp_DO_ID, toc-ttic);

                    //     close(sock_DO);
                    //     enclave_close(&enclave_info);
                    //     printf("End of the child process\n");
                    //     exit(0);
                    // }
                    ////////////////////////////////////////////////////////////////////////////////////

                    /* Perform remote attestation to the challenger */
                    tic = stime();
                    threads.emplace_back(remote_attest_enclave_parallel, sock_DO, &tmp_DO_ID, &enclave_info);
            
                    num_DO_attested ++;
                    num_threads ++;
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

                // th[0].join();
                toc = stime();
                printf("\n----- Attestation to DOs is successful. Time: %f seconds -----\n", toc-ttic);
                // close(sock_DO);

                break;
            }

            case '2':
            {
                int do_data_msg_header_size = sizeof(do_provision_data_header_t);
                do_provision_data_header_t* do_data_msg_header = (do_provision_data_header_t*) malloc(do_data_msg_header_size);
                uint8_t* do_data;

                bool DO_provisioned[DO_NUM] = {false};
                int num_DO_provisioned = 0;

                //Listen
                printf("Please connect the DataOwner to this address: 192.168.0.24:8001\n");
                listen(sock_DO_init , DO_NUM);

                while(num_DO_provisioned < DO_NUM)
                {
                    printf("\nWaiting for incoming data transfer from DOs [%d remain]... \n", DO_NUM - num_DO_provisioned);

                    sock_DO = accept(sock_DO_init, (struct sockaddr *)&client_DO, (socklen_t*)&c);

                    if(num_DO_provisioned == 0) ttic = stime();

                    tic = stime();

                    /* Receive the header first */
                    if( read(sock_DO, do_data_msg_header, do_data_msg_header_size) < 0)
                    {
                        printf("recv failed.\n");
                        goto CLEANUP2;
                    }

                    cout << "--------------------------------------------" << endl;
                    printf("DO%d_%d.txt received. Size: %d Bytes\n", do_data_msg_header->DO_ID, do_data_msg_header->data_num, do_data_msg_header->data_size);

                    /* Receive the data body */
                    do_data = (uint8_t*) malloc(do_data_msg_header->data_size);
                    if( read(sock_DO, do_data, do_data_msg_header->data_size) < 0)
                    {
                        printf("recv failed.\n");
                        goto CLEANUP2;
                    }

                    /* Encrypt and store this data file in cloud */
                    process_DO_data(&enclave_info, do_data_msg_header, do_data);
                    toc = stime();
                    printf("# Receiving data from DO %d is successful. Time: %f seconds\n", do_data_msg_header->DO_ID, toc-tic);

                    /* Register this data file locally */
                    DO_List[do_data_msg_header->DO_ID-1] = do_data_msg_header->data_num;

                    if(!DO_provisioned[do_data_msg_header->DO_ID-1])
                    {
                        DO_provisioned[do_data_msg_header->DO_ID-1] = true;
                        num_DO_provisioned ++;
                    }
                }

                ttoc = stime();
                printf("\n## Receiving data from the %d DOs is completed. Total time: %f seconds\n", DO_NUM, ttoc-ttic);

                CLEANUP2:
                free(do_data_msg_header);
                free(do_data);
                close(sock_DO);
                // close(sock_DO_init);
                break;
            }

            case '3':
            {
                tic = stime();
                confirmRegistries(ContractAddress);
                toc = stime();
                printf("Time for DataBroker calling contract's confirm(): %f seconds\n", toc-tic);
                break;
            }

            case '4':
            { 
                int num_DO_avail = 0;
                int dc_request_msg_size = sizeof(dc_request_msg_header_t);
                int ida_approve_msg_size = sizeof(ida_approve_msg_header_t);
                dc_request_msg_header_t* dc_request_msg = (dc_request_msg_header_t*)malloc(dc_request_msg_size);
                ida_approve_msg_header_t* ida_approve_msg = (ida_approve_msg_header_t*)malloc(ida_approve_msg_size);
                
                printf("Please connect the DataConsumer to this address: 192.168.0.24:8002\n");
                 
                // Listen
                listen(sock_DC_init , 3);
                c = sizeof(struct sockaddr_in);
                sock_DC = accept(sock_DC_init, (struct sockaddr *)&client_DC, (socklen_t*)&c);
                if (sock_DC < 0)
                {
                    perror("accept failed");
                    goto CLEANUP4;
                }
                printf("\nDataConsumer connected.\n");

                /* Deal with DataConsumer's request */
                if( read(sock_DC, msg_recv, dc_request_msg_size) < 0)
                {
                    printf("recv failed.\n");
                    goto CLEANUP4;
                }
                dc_request_msg = (dc_request_msg_header_t*) msg_recv;
                
                /* Check if the request type is correct (should be 1 for DB) */
                if(dc_request_msg->type != 1)
                {
                    ida_approve_msg->flag = 0x08;
                    ready_to_attest_CEE = false;
                    printf("\nThe DC requested a DO. But this is a DB\n");
                    goto CLEANUP4;
                }

                /* Check if the data is registered and Dataconsumer's deposit is in place */
                ret = checkContractStatus(ContractAddress);
                
                if(ret != 0)
                {
                    ida_approve_msg->flag = 0x09;
                    ready_to_attest_CEE = false;
                    printf("\nNo deposit in contract\n");
                    goto CLEANUP4;
                }

                /* Check if the requested DO's data is available locally */
                for(i = dc_request_msg->start; i <= dc_request_msg->end; i++)
                {
                    if(DO_List[i-1] > 0) num_DO_avail ++;
                }

                if(num_DO_avail < dc_request_msg->end - dc_request_msg->start + 1) 
                {
                    ida_approve_msg->flag = 0x02;
                    ready_to_attest_CEE = false;
                    printf("\nData unavailable (DC_ID: %u)\n", dc_request_msg->DC_ID);
                }                      
                else
                {
                    ida_approve_msg->flag = 0x00;
                    ready_to_attest_CEE = true;
                    cur_DC_ID = dc_request_msg->DC_ID;
                    printf("\nApproved! (DC_ID: %u)\n", dc_request_msg->DC_ID);

                    /* Record this request locally */
                    Request_DC        = dc_request_msg->DC_ID;
                    Request_type      = dc_request_msg->type;
                    Request_start     = dc_request_msg->start;
                    Request_end       = dc_request_msg->end;
                    Request_operation = dc_request_msg->operation;
                }

                /* Inform the DataConsumer the decision */
                if ( write(sock_DC, ida_approve_msg, ida_approve_msg_size) < 0 ) 
                {
                    printf("Send approve message failed.\n");
                    goto CLEANUP4;
                }

                CLEANUP4:
                close(sock_DC);
                // close(sock_DC_init);
                break;
            }

            case '5':
            {                      
                uint8_t DO_data_keys[AESGCM_KEY_SIZE * DO_NUM];
                sgx_status_t status = SGX_SUCCESS;

                operation_config_msg_t *operation_config_msg = (operation_config_msg_t *) malloc(sizeof(operation_config_msg_t));

                operation_config_msg->DC_ID     = Request_DC;
                operation_config_msg->type      = Request_type;  // 0: DO, 1: DB
                operation_config_msg->start     = Request_start;
                operation_config_msg->end       = Request_end;
                operation_config_msg->operation = Request_operation;

                if(ready_to_attest_CEE == false)
                {
                    printf("\nAin't no approved DC's request yet\n");
                    goto CLEANUP5;
                }

                sock_CEE = socket(AF_INET , SOCK_STREAM , 0);
                if (sock_CEE == -1) { printf("Could not create socket for CEE."); return 1;}
                server_CEE.sin_family = AF_INET;
                server_CEE.sin_addr.s_addr = inet_addr("192.168.0.24"); // CEE's IP address
                server_CEE.sin_port = htons( 8888 );

                // Connect to CEE server
                if (connect(sock_CEE , (struct sockaddr *)&server_CEE , sizeof(server_CEE)) < 0)
                {
                    printf("connect error.\n");
                    goto CLEANUP5;
                }

                /* Transmit operation details to CEE */
                if ( write(sock_CEE, operation_config_msg, sizeof(operation_config_msg_t)) < 0 ) {
                    printf("Send operation_config_msg message failed.\n");
                    goto CLEANUP5;
                }
                printf("Request [%s]'s contract. Requested range: %d ~ %d, Operation: %d\n", transactionType[Request_type], Request_start, Request_end, Request_operation);

                /* Begin attesting */
                ret = ECALL_get_DO_data_key(
                        enclave_info.enclave_id,
                        &status,
                        DO_data_keys,
                        AESGCM_KEY_SIZE,
                        DO_NUM,
                        sizeof(DO_data_keys));

                ret = remote_attest_challenger(sock_CEE, 2, DO_data_keys, sizeof(DO_data_keys)); // Attest CEE and provision DO_data_key
                if ( ret != 0 )
                {
                    printf("\nAttestation to CEE failed. Terminate.\n\n");
                }

                /* Waiting for K_result from CEE */
                printf("\nWaiting for K_result from CEE...\n");
                if( read(sock_CEE, msg_recv, sizeof(K_result_msg_t)) < 0)
                {
                    printf("recv failed.\n");
                    goto CLEANUP5;
                }
                K_result_msg = (K_result_msg_t *) msg_recv;

                CLEANUP5:
                // close(sock_CEE);
                break;
            }

            case '6':
            {
                /* Process K_result_msg and send K_result to contract */
                tic = stime();
                completeTransaction(ContractAddress, K_result_msg);
                toc = stime();
                printf("Time for DataBroker calling contract's completeTransaction(): %f seconds\n", toc-tic);
            }
        }
    }    	

    return 0;
}


// void attest_enclave_thread()