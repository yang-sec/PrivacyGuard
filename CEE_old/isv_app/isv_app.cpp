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
    

    /* Communication config */
    int socket_init;
    bool sock_on = false;
    int sock_num[2]; // 0: DC, 1: iDA


    while(running)
    {
        char inputChar;
        
        cout << "\n## CEE ## ready to roll:" << endl
        << "Press 1: Initiate an enclave then attest to iDataAgent and DataConsumer." << endl
        << "Press 2: Perform the computation task." << endl
        << "Press 3: Test ECALL_compute_task2 (svm)." << endl
        << "Press 4: Record data usage on contract." << endl
        << "Press 0: Exit." << endl;
        cin >> inputChar;

        switch(inputChar)
        {
            case '0':
            {
                running = false;
                // if(sock_on == true)
                // {
                //     close(sock_num[0]);
                //     close(sock_num[1]);
                //     close(socket_init);
                //     printf("All sockets closed.\n");
                // }

                if (enclave_on) 
                {
                    enclave_close(&enclave_info);
                }
                break;
            }

            case '1':
            {
                /* Init enclave*/
                if (enclave_on)
                {
                    printf("\nClosing the current enclave...\n");
                    enclave_close(&enclave_info);
                    enclave_on = false;
                }
                enclave_on = enclave_init(&enclave_info); 

                /* Attest to DC and iDA */
                if(sock_on == true)
                {
                    close(socket_init);
                    close(sock_num[0]);
                    close(sock_num[1]);
                }

                if(!enclave_on)
                {
                    printf("\nPlease initiate an enclave first.\n");
                    break;
                }

                // Socket config
                int socket_new, c;
                struct sockaddr_in self_server, challenger_client;
                char* msg_sent;
                char msg_recv[2048] = {0};

                int ret;
                int challenger_type; // 1: DataConsumer, 2: iDataAgent
                char challenger[2][20] = {"DataConsumer", "iDataAgent"};
                bool ra_flag[2] = {false, false};

                // Create socket
                socket_init = socket(AF_INET , SOCK_STREAM , 0);
                if (socket_init == -1) { printf("Could not create socket."); }
                sock_on = true;

                self_server.sin_family = AF_INET;
                self_server.sin_addr.s_addr = INADDR_ANY;
                self_server.sin_port = htons( 8888 );

                //Bind
                if( bind(socket_init,(struct sockaddr *)&self_server , sizeof(self_server)) < 0) { printf("bind failed"); break; }
                
                //Listen
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

                    // Perform remote attestation to the challenger
                    ret = remote_attest_enclave(socket_new, &challenger_type, &enclave_info);
                    if ( ret != 0 )
                    {
                        printf("\nAttestation to %s failed. Please restart the attestation.\n\n", challenger[challenger_type-1]);
                        close(socket_new);
                        continue;
                    }
    
                    printf("-------- Attestation for %s is completed --------\n", challenger[challenger_type-1]); 
                    ra_flag[challenger_type-1] = true;

                    // close(socket_new);
                    sock_num[challenger_type-1] = socket_new;
                }

                printf("\n## CEE has attested for both DataConsumner and iDataAgent. Please proceed to the computation task.\n\n");
                
                close(sock_num[0]);
                close(sock_num[1]);
                close(socket_init);
                    
                break;
            }

            case '2':
            {
                enclave_compute_task1(&enclave_info, 1, 1); // DO 1's file 1 (will change later)
                break;
            }

            case '3':
            {
                /*Test svm */
                enclave_compute_task2(&enclave_info, 1, 101); // user 1's file 101 (will change later)
                break;
            }

            case '4':
            {
                char contract_addr[100];
                sprintf(contract_addr, "992d8b41E547D40920172E5369fe0fA0d769BC5c"); // Contract address

                record_datause(&enclave_info, contract_addr);
                printf("\nRecording Completed. DataConsumer please do the next:\n1. Fetch the encrypted random key from DO contract's data records.\n2. Decrypy the random key with the sk_key established during the last remote attestation.\n3. Use the random key to decrypt the computation result stored in cloud. \n\n");
    
                break;
            }
        }
    }
	
    return 0;
}