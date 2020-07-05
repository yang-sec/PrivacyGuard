#include "clientdata_operation.h"
#include "sample_libcrypto.h"

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <openssl/aes.h> // sudo apt-get install libssl-dev
// #include <sample_libcrypto.h>
using namespace std;

#include <cstdlib>
#include <time.h>


/* These are used for user data simulation */
#define USER_ID 1
#define NUM_FILES 2
#define NUM_DATA_POINTS_PER_FILE 50
/* --------------------------------------- */


int getdata_encrypt_store()
{
	/* Get user data. Currently it is simulated with random text */
	{
		srand(time(NULL));
		int i, j;
		for (i = 1; i <= NUM_FILES; i++)
		{
			ofstream outfile ("UserData/" + to_string(i) + ".txt");
			for (j = 1; j <= NUM_DATA_POINTS_PER_FILE; j++)
			{
				outfile << rand() % 10;
				// if (j < NUM_DATA_POINTS_PER_FILE) outfile << '\n';
			}		
			outfile.close();
		}
	}



	/* Encrypt user data files and store them in cloud */
	{
		sample_aes_gcm_128bit_key_t DO_skey[SAMPLE_AESGCM_KEY_SIZE] = {0xED, 0x96, 0x3C, 0x5E, 0xD8, 0x3B, 0x86, 0xCE, 0xBD, 0x56, 0x4A, 0xFA, 0xAA, 0xD8, 0xB0, 0x35};
		sample_aes_gcm_128bit_tag_t DO_out_mac[SAMPLE_AESGCM_MAC_SIZE];
		uint8_t aes_gcm_iv[12] = {0};

		int ret = 0, i;


		for (i = 1; i <= NUM_FILES; i++)
		{
			char buf1[100], buf2[100], buf3[100];
			sprintf(buf1, "UserData/%d.txt", i);
			sprintf(buf2, "../CloudStorage/user%d/%d.txt", USER_ID, i);
			sprintf(buf3, "../CloudStorage/user%d/%d_mac.txt", USER_ID, i);
			FILE *ifp = fopen(buf1, "rb");
			FILE *ofp_ctext = fopen(buf2, "wb");
			FILE *ofp_mac = fopen(buf3, "wb");
			int lSize;

			// Obtain file size
		  	fseek(ifp, 0, SEEK_END);
		  	lSize = ftell(ifp);
		  	rewind(ifp);

			// Use AES-GCM provided in sample_crypto.h
			uint8_t* indata;
			uint8_t* outdata;
			indata =  (uint8_t*) malloc (sizeof(uint8_t)*lSize);
			outdata = (uint8_t*) malloc (sizeof(uint8_t)*lSize);

			fread(indata, 1, lSize, ifp);

	        ret = sample_rijndael128GCM_encrypt(
								            DO_skey,
								            indata,
								            lSize,
								            outdata, // Output
								            &aes_gcm_iv[0],
								            12,
								            NULL,
								            0,
								            DO_out_mac); // Output

			fwrite(outdata, 1, lSize, ofp_ctext);
			fwrite(DO_out_mac, 1, SAMPLE_AESGCM_MAC_SIZE, ofp_mac);

			fclose(ifp);
			fclose(ofp_ctext);
			fclose(ofp_mac);
		}
	}

	return 0;

}



#define FILE_NUM 101 // for SVM experiment only

/* Encrypted a file */
int encrypt_store()
{
	sample_aes_gcm_128bit_key_t DO_skey[SAMPLE_AESGCM_KEY_SIZE] = {0xED, 0x96, 0x3C, 0x5E, 0xD8, 0x3B, 0x86, 0xCE, 0xBD, 0x56, 0x4A, 0xFA, 0xAA, 0xD8, 0xB0, 0x35};
	sample_aes_gcm_128bit_tag_t DO_out_mac[SAMPLE_AESGCM_MAC_SIZE];
	uint8_t aes_gcm_iv[12] = {0};

	int ret = 0;

	char buf1[100], buf2[100], buf3[100];
	sprintf(buf1, "UserData/%d.txt", FILE_NUM);
	sprintf(buf2, "../CloudStorage/user%d/%d.txt", USER_ID, FILE_NUM);
	sprintf(buf3, "../CloudStorage/user%d/%d_mac.txt", USER_ID, FILE_NUM);
	FILE *ifp = fopen(buf1, "rb");
	FILE *ofp_ctext = fopen(buf2, "wb");
	FILE *ofp_mac = fopen(buf3, "wb");
	int lSize;

	// Obtain file size
  	fseek(ifp, 0, SEEK_END);
  	lSize = ftell(ifp);
  	rewind(ifp);

	// Use AES-GCM provided in sample_crypto.h
	uint8_t* indata;
	uint8_t* outdata;
	indata =  (uint8_t*) malloc (sizeof(uint8_t)*lSize);
	outdata = (uint8_t*) malloc (sizeof(uint8_t)*lSize);

	fread(indata, 1, lSize, ifp);

    ret = sample_rijndael128GCM_encrypt(
							        DO_skey,
							        indata,
							        lSize,
							        outdata, // Output
							        &aes_gcm_iv[0],
							        12,
							        NULL,
							        0,
							        DO_out_mac); // Output

	fwrite(outdata, 1, lSize, ofp_ctext);
	fwrite(DO_out_mac, 1, SAMPLE_AESGCM_MAC_SIZE, ofp_mac);

	fclose(ifp);
	fclose(ofp_ctext);
	fclose(ofp_mac);

	return ret;
}