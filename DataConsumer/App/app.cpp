/* 
* DataConsumer (DC): app.cpp
* 
* PrivacyGuard Project (2018), Virginia Tech CNSR Lab
*/

#include <stdio.h>
#include <iostream>
// #include <ctime>       //time()
#include <sys/time.h>
#include <string.h>    //strlen
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include "attestation_service.h"
#include "network_ra.h"
#include "operations.h"
using namespace std;


/* Parameters */
#define unit_price 0.01 // in ether

char ContractAddressDO[100] = "208D3CEdFE8918298A726264B578A9BA2AE8c85B"; // DO
char ContractAddressDB[100] = "7CAC532e3E93666247a56D987e25AEa5050B8cee"; // DB

/* --------------------------- */


// DataConsumer's Ethereum private key: to be provisioned to the CCE (256-bit (32-Byte) ECDSA private key)
uint8_t DC_secret[32] = 
{0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde }; // dummy

double stime()
{
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (double)tp.tv_sec + (double)tp.tv_usec / 1000000;
}


int main(int argc , char **argv)
{
    double tic, toc;
    bool running = true;
    bool ida_approval = false;
    char msg_recv[2048] = {0};
    K_result_hash_msg_t *K_result_hash_msg = (K_result_hash_msg_t *) malloc(sizeof(K_result_hash_msg_t));
    char transactionType[2][20] = {"iDataAgent", "DataBroker"};

    /* Config the DataConsumer */
    int DataConsumer_ID;
    int Request_type;   // 0: from iDA, 1: from DB
    int Request_start;
    int Request_end;
    int Request_operation;
    double Request_price;
    char ContractAddress[100];

    cout << "DC ID: "; cin >> DataConsumer_ID;

    /* Begin Operation */
    while(running)
    {
        char inputChar;
        cout << "\n## DataConsumer ## ready to roll. What can I do for you?" << endl
        << "Press 1: What to you request? " << endl
        << "Press #: Invoke the contract. " << endl
        << "Press 2: Request the iDataAgent/DataBroker. " << endl
        << "Press 3: Attest the CEE enclave, provide operation configurations." << endl
        << "Press 4: Send computationComplete to contract." << endl
        << "Press 5: Cancel the current data transaction and get refund." << endl
        << "Press 0: Exit." << endl;
        cin >> inputChar;

        switch(inputChar)
        {
            case '0':
                running = false;
                break;

            case '1':
            {
                /* Invoke DO's contract */
                cout << "Request Type (0: DO, 1: DB): "; cin >> Request_type;
                cout << "Request Start: "; cin >> Request_start;
                cout << "Request End: "; cin >> Request_end;
                cout << "Request Operation: "; cin >> Request_operation;

                Request_price = unit_price * (Request_end - Request_start + 1);
                cout << endl << "Requesting " << transactionType[Request_type] << "'s Contract\nTotal Cost: " << Request_price << " ethers" << endl;

                switch(Request_type)
                {
                    case 0: sprintf(ContractAddress, "%s", ContractAddressDO); break;
                    case 1: sprintf(ContractAddress, "%s", ContractAddressDB); break;
                }
                
                break;
            }

            case '#':
            {
                printf("\n\nSend a request transaction to contract.\n");
                tic = stime();
                request_Contract(ContractAddress, Request_start, Request_end, Request_operation, Request_price); // data range, operation number, 0.01 ethers
                toc = stime();
                printf("Time for requesting contract: %f seconds\n", toc-tic);
                break;
            }

            case '2':
            {
                /* Request the iDA */
                printf("\n\nSend a request to iDataAgent/DataBroker.\n");
                ida_approval = false;

                char msg_recv[2048] = {0};
                int dc_request_msg_size = sizeof(dc_request_msg_header_t);
                int ida_approve_msg_size = sizeof(ida_approve_msg_header_t);
                dc_request_msg_header_t *dc_request_msg = (dc_request_msg_header_t *) malloc(dc_request_msg_size);
                ida_approve_msg_header_t *ida_approve_msg = (ida_approve_msg_header_t *) malloc(ida_approve_msg_size);

                int socket_init;
                struct sockaddr_in iDA_server;

                // Create socket
                socket_init = socket(AF_INET , SOCK_STREAM , 0);
                if (socket_init == -1)
                {
                    printf("\nCould not create socket.\n");
                    goto CLEANUP1;
                }

                // Prepare the sockaddr_in structure for iDataAgent server
                iDA_server.sin_family = AF_INET;
                iDA_server.sin_addr.s_addr = inet_addr("192.168.0.24");
                iDA_server.sin_port = htons( 8002 );


                tic = stime();

                // Connect to iDataAgent server
                if (connect(socket_init , (struct sockaddr *)&iDA_server , sizeof(iDA_server)) < 0)
                {
                    printf("\nconnect error.\n");
                    goto CLEANUP1;
                }

                // Send a request to iDataAgent - TO UPDATE
                dc_request_msg->DC_ID = DataConsumer_ID;  
                dc_request_msg->type  = Request_type;   
                dc_request_msg->start = Request_start;
                dc_request_msg->end   = Request_end;
                dc_request_msg->operation = Request_operation;

                if ( write(socket_init, dc_request_msg, dc_request_msg_size) < 0 ) {
                    printf("Send request message failed.\n");
                    goto CLEANUP1;
                }

                // Receive iDataAgent's approval
                if( read(socket_init, msg_recv, ida_approve_msg_size) < 0)
                {
                    printf("Read failed.\n");
                    goto CLEANUP1;
                }
                ida_approve_msg = (ida_approve_msg_header_t*) msg_recv;

                switch(ida_approve_msg->flag)
                {
                    case 0x00:
                        printf("\n%s approved! Please proceed to attesting CEE enclave.\n", transactionType[Request_type]);
                        ida_approval = true;
                        break;
                    case 0x01:
                        printf("\niDataAgent doesn't approved! You requested wrong DO_ID.\n");
                        break;
                    case 0x02:
                        printf("\n%s doesn't approved! The data you requested doesn't exist.\n", transactionType[Request_type]);
                        break;
                    case 0x08:
                        printf("\nDataBroker doesn't approved! You requested an iDataAgent.\n");
                        break;
                    case 0x09:
                        printf("\n%s doesn't approved! No deposit in contract.\n", transactionType[Request_type]);
                        break;
                }

                toc = stime();
                printf("Time for DataConsumer getting iDA's approval: %f seconds\n", toc - tic);

                CLEANUP1:
                close(socket_init);
                break;
            }
                
            case '3':
            {
                int ret;
                int sock_CEE;
                struct sockaddr_in CCE_server;
                operation_config_msg_t *operation_config_msg = (operation_config_msg_t *) malloc(sizeof(operation_config_msg_t));

                operation_config_msg->DC_ID     = DataConsumer_ID;
                operation_config_msg->type      = Request_type;  // 0: DO, 1: DB
                operation_config_msg->start     = Request_start;
                operation_config_msg->end       = Request_end;
                operation_config_msg->operation = Request_operation;

                if (ida_approval == false)
                {
                    printf("Ain't no iDataAgent approval yet. Need to request first!\n");
                    break;
                }


                printf("\n\nBegin attesting CEE enclave.\n");

                // Create socket
                sock_CEE = socket(AF_INET , SOCK_STREAM , 0);
                if (sock_CEE == -1)
                {
                    printf("Could not create socket.");
                    goto CLEANUP3;
                }

                // Prepare the sockaddr_in structure for CEE server
                CCE_server.sin_family = AF_INET;
                CCE_server.sin_addr.s_addr = inet_addr("192.168.0.24");
                CCE_server.sin_port = htons( 8888 );

                // Connect to CEE server
                if (connect(sock_CEE , (struct sockaddr *)&CCE_server , sizeof(CCE_server)) < 0)
                {
                    printf("connect error.\n");
                    goto CLEANUP3;
                }

                /* Transmit operation details to CEE */
                if ( write(sock_CEE, operation_config_msg, sizeof(operation_config_msg_t)) < 0 ) {
                    printf("Send operation_config_msg message failed.\n");
                    goto CLEANUP3;
                }
                printf("Request [%s]'s contract. Requested range: %d ~ %d, Operation: %d\n", transactionType[Request_type], Request_start, Request_end, Request_operation);

                /* Begin attesting */
                ret = remote_attest_challenger(sock_CEE, 1, DC_secret, sizeof(DC_secret)); // Secret key should be provisioned in this function
                if ( ret != 0 )
                {
                    printf("Attestation to CEE failed. Terminate.\n");
                    goto CLEANUP3;
                }

                /* Waiting for K_result from CEE */
                printf("\nWaiting for {K_result_hash, C_result_hash} from CEE...\n");
                if( read(sock_CEE, msg_recv, sizeof(K_result_hash_msg_t)) < 0)
                {
                    printf("recv failed.\n");
                    goto CLEANUP3;
                }
                K_result_hash_msg = (K_result_hash_msg_t *) msg_recv;

                CLEANUP3:
                close(sock_CEE);
                break;
            }

            case '4':
            {
                /* Process K_result_msg and send K_result to contract */
                tic = stime();
                computationComplete(K_result_hash_msg, ContractAddress, DataConsumer_ID, Request_operation);
                toc = stime();
                printf("Time for DataConsumer calling contract's computationComplete(): %f seconds\n", toc-tic);
                break;
            }

            case '5':
            {
                tic = stime();
                cancelTransaction(ContractAddress);
                toc = stime();
                printf("Time for DataConsumer calling contract's cancel(): %f seconds\n", toc-tic);
                break;
            }
        }
    }	
    return 0;
}


