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

#include "network_ra.h"
#include "clientdata_operation.h"
#include "operations.h"
#include "attestation_service.h"
#include "enclave_u.h"
using namespace std;



/* ------- Parameters -------- */
#define DataOwner_ID 1
#define MAX_DATA_NUM 1000    // currently support up to 1000 data files
char ContractAddress[100]     = "208D3CEdFE8918298A726264B578A9BA2AE8c85B"; // iDA
/* --------------------------- */


double stime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (double)tp.tv_sec + (double)tp.tv_usec / 1000000;
}


int main(int argc , char **argv)
{
    int i;
    double tic, toc;
    bool data_List[MAX_DATA_NUM] = {false}; 
    bool running = true;
    bool enclave_on = false;
    bool ready_to_attest_CEE = false;
    uint32_t cur_DC_ID;
    enclave_info_t enclave_info;

    K_result_msg_t *K_result_msg = (K_result_msg_t *) malloc(sizeof(K_result_msg_t));

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
        cout << "\n## iDataAgent ## ready to roll:" << endl
        << "Press 1: Attest enclave to DataOwner." << endl
        << "Press 2: Listen for DataOwner's data provisions." << endl
        << "Press 3: Listen for requests from DataConsumers." << endl
        << "Press 4: Attest the CEE enclave, provision DataOwner's decrypting key." << endl
        << "Press 5: Send completeTransaction to contract." << endl
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
                    enclave_on = enclave_init(&enclave_info);
                }

                int challenger_type;
                
                //Listen
                printf("Please connect the DataOwner to this address: 192.168.0.24:8001\n");
                listen(sock_DO_init , 3);
                c = sizeof(struct sockaddr_in);

                sock_DO = accept(sock_DO_init, (struct sockaddr *)&client_DO, (socklen_t*)&c);

                tic = stime();

                if (sock_DO < 0) 
                {
                    perror("accept failed");
                    close(sock_DO);
                    break;
                }

                // Perform remote attestation to the challenger
                ret = remote_attest_enclave(sock_DO, &challenger_type, &enclave_info);
                if ( ret != 0 )
                {
                    printf("\nAttestation failed. Please restart the attestation.\n\n");
                    close(sock_DO);
                    break;
                }
                
                printf("\n## Attestation to DataOwner is successful.\n");

                toc = stime(); 
                printf("Time for iDA attesting to DataOwner: %f seconds\n", toc-tic);
                
                // close(sock_DO);
                // close(sock_DO_init);
                break;
            }

            case '2':
            {
                int N;
                int do_data_msg_header_size = sizeof(do_provision_data_header_t);
                do_provision_data_header_t* do_data_msg_header = (do_provision_data_header_t*) malloc(do_data_msg_header_size);
                uint8_t* do_data;

                cout << "Number of files to receive: ";
                cin >> N;

                //Listen
                printf("\nPlease connect the DataOwner to this address: 192.168.0.24:8001\n");
                listen(sock_DO_init , 3);
                printf("Waiting for incoming data transfer from DO ... \n");

                

                for(i = 0; i < N; i++)
                {
                    sock_DO = accept(sock_DO_init, (struct sockaddr *)&client_DO, (socklen_t*)&c);
                
                    /* Receive the header first */
                    if( read(sock_DO, do_data_msg_header, do_data_msg_header_size) < 0)
                    {
                        printf("recv failed.\n");
                        goto CLEANUP2;
                    }

                    printf("\nDO%d_%d.txt received. Size: %d Bytes. ", do_data_msg_header->DO_ID, do_data_msg_header->data_num, do_data_msg_header->data_size);

                    /* Receive the data body */
                    do_data = (uint8_t*) malloc(do_data_msg_header->data_size);
                    if( read(sock_DO, do_data, do_data_msg_header->data_size) < 0)
                    {
                        printf("recv failed.\n");
                        goto CLEANUP2;
                    }

                    /* Encrypt and store this data file in cloud */
                    process_DO_data(&enclave_info, do_data_msg_header, do_data);

                    /* Register this data file locally */
                    data_List[do_data_msg_header->data_num-1] = true;
                }
                printf("\n");

                CLEANUP2:
                free(do_data_msg_header);
                free(do_data);
                // close(sock_DO);
                // close(sock_DO_init);
                break;
            }

            case '3':
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
                    goto CLEANUP3;
                }
                printf("\nDataConsumer connected.\n");

                // Deal with DataConsumer's request
                if( read(sock_DC, msg_recv, dc_request_msg_size) < 0)
                {
                    printf("recv failed.\n");
                    goto CLEANUP3;
                }
                dc_request_msg = (dc_request_msg_header_t*) msg_recv;
                

                /* TCheck if the data is registered and Dataconsumer's deposit is in place */
                ret = checkContractStatus(ContractAddress);
                
                if(ret != 0)
                {
                    ida_approve_msg->flag = 0x09;
                    ready_to_attest_CEE = false;
                    printf("\nNo deposit in contract\n");
                    goto CLEANUP3;
                }

                for(i = dc_request_msg->start; i <= dc_request_msg->end; i++)
                {
                    if(data_List[i-1]) num_DO_avail ++;
                    // printf("num_DO_avail: %d\n", num_DO_avail);
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
                    printf("\nApproved! (DC_ID: %u, number of data files: %d)\n", dc_request_msg->DC_ID, num_DO_avail);

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
                    goto CLEANUP3;
                }

                CLEANUP3:
                close(sock_DC);
                // close(sock_DC_init);
                break;
            }

            case '4':
            {                      
                uint8_t DO_data_key[AESGCM_KEY_SIZE];
                uint8_t DO_data_keys[AESGCM_KEY_SIZE * (Request_end - Request_start + 1)];
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
                    goto CLEANUP4;
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
                    goto CLEANUP4;
                }

                /* Transmit operation details to CEE */
                if ( write(sock_CEE, operation_config_msg, sizeof(operation_config_msg_t)) < 0 ) {
                    printf("Send operation_config_msg message failed.\n");
                    goto CLEANUP4;
                }
                printf("Request [%s]'s contract. Requested range: %d ~ %d, Operation: %d\n", transactionType[Request_type], Request_start, Request_end, Request_operation);

                /* Begin attesting */
                ret = ECALL_get_DO_data_key(
                        enclave_info.enclave_id,
                        &status,
                        enclave_info.context,
                        DO_data_key,
                        16);

                /* Replicate this data key for each data file */
                for(i = 0; i < Request_end - Request_start + 1; i++)
                {
                    memcpy(&DO_data_keys[i*AESGCM_KEY_SIZE], DO_data_key, AESGCM_KEY_SIZE);
                }

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
                    goto CLEANUP4;
                }
                K_result_msg = (K_result_msg_t *) msg_recv;

                CLEANUP4:
                // close(sock_CEE);
                break;
            }

            case '5':
            {
                /* Process K_result_msg and send K_result to contract */
                tic = stime();
                completeTransaction(ContractAddress, K_result_msg);
                toc = stime();
                printf("Time for iDataAgent calling contract's completeTransaction(): %f seconds\n", toc-tic);
            }
        }
    }    	

    return 0;
}

