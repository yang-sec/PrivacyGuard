/* 
* DataOwner (DO): app.cpp
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
// #include "operations_dc.h"
#include "attestation_service.h"
#include "network_ra.h"
#include "operations.h"
#include "DO_sim.h"
using namespace std;


/* ------- Parameters -------- */
int DO_ID;
char DO_Address[200];
char DO_PrivateKey[200];

char ContractAddress[100]     = "0x208D3CEdFE8918298A726264B578A9BA2AE8c85B"; // DO's own contract
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
    int ret;
    int data_counter = 0;
    double tic, toc;

    bool running = true, iDA_connected = false;

    /* Communication config */
    int socket_iDA;
    struct sockaddr_in server_iDA;
    socket_iDA = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_iDA == -1) { printf("Could not create socket."); return 1;}
    server_iDA.sin_family = AF_INET;
    server_iDA.sin_addr.s_addr = inet_addr("192.168.0.24"); // iDA's IP address
    server_iDA.sin_port = htons( 8001 );

    /* DO config */
    cout << "Enter DataOwner ID number (>0):";
    cin >> DO_ID;  
    memcpy(DO_Address, DO_sim_CandidateSet[DO_ID-1][0], sizeof(DO_Address));
    memcpy(DO_PrivateKey, DO_sim_CandidateSet[DO_ID-1][1], sizeof(DO_PrivateKey));
    cout << "ID: " << DO_ID << "\tAddress: " << DO_Address << endl;

    /* Operation begins */
    while(running)
    {
        char inputChar;
        cout << "\n## DataOwner ## ready to roll. What can I do for you?" << endl
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
                /* Connect to iDA */
                if(iDA_connected)
                {
                    close(socket_iDA);
                }
                socket_iDA = socket(AF_INET , SOCK_STREAM , 0);
                iDA_connected = true;

                if(connect(socket_iDA , (struct sockaddr *)&server_iDA , sizeof(server_iDA)) < 0) {printf("connect error.\n"); break;}
                
                /* Begin attesting */
                ret = remote_attest_challenger(socket_iDA, DO_ID, DO_nonce, sizeof(DO_nonce)); // No need to provision anything at this time
                if ( ret != 0 )
                {
                    printf("\nAttestation to iDataAgent's enclave failed. Terminate.\n");
                }
                else
                {
                    printf("\nAttestation to iDataAgent's enclave success!\n");
                }
                break;
            }

            case '2':
            {
                data_counter = generate_data_type(DO_ID, data_counter, N_data, dataType); // data points per file
                printf("DO%d_%d.txt generated.\n", DO_ID, data_counter);
                break;
            }

            case '3':
            {
                tic = stime();
                register_data_on_Contract(ContractAddress, DO_Address, DO_PrivateKey, 0, data_counter, OperationNum, price, DataConsumerAddress, 0);
                toc = stime();
                printf("Time for DataOwner registering new data on my own contract: %f seconds\n", toc-tic);
                break;
            }

            case '4':
            {
                tic = stime();
                register_data_on_Contract(DBContractAddress, DO_Address, DO_PrivateKey, 1, 0, OperationNum, price, DataConsumerAddress, 0);
                toc = stime();
                printf("Time for DataOwner registering new data on DB's contract: %f seconds\n", toc-tic);
                break;
            }

            case '5':
            {
                // data_counter ++; // to be deleted

                /* Connect to iDA */
                if(iDA_connected)
                {
                    close(socket_iDA);
                }
                socket_iDA = socket(AF_INET , SOCK_STREAM , 0);
                iDA_connected = true;

                if(connect(socket_iDA , (struct sockaddr *)&server_iDA , sizeof(server_iDA)) < 0) {printf("connect error.\n"); break;}
                ret = provision_data(socket_iDA, DO_ID, data_counter);

                if(ret == 0){
                    printf("\nProvisioning file %d-%d.txt to iDA/DB [SUCCESS].\n", DO_ID, data_counter);
                }
                else{
                    printf("\nProvisioning file %d-%d.txt to iDA/DB [FAILED].\n", DO_ID, data_counter);
                }
                break;
            }
        }
    }	
    return 0;
}


