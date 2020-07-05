/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>    //write

#include "network_ra.h"
// #include "service_provider.h"
#include "sgx_key_exchange.h"


// Send requests to and get response from the remote address
// [SOCKET COMM]
//
// @param socket_desc Socket number to the remote address.
// @param p_req Pointer to the message to be sent.
// @param p_resp Pointer to a pointer of the response message.

// @return int

int ra_network_send_receive_real(
		const int socket_desc,
		const ra_samp_request_header_t *p_req,
		ra_samp_response_header_t **p_resp)
{
	int msg_sent_size = sizeof(ra_samp_request_header_t) + p_req->size;
	int msg_recv_size;
	char msg_recv[2048] = {0};
	bool expectingRecv = true;
    ra_samp_response_header_t* p_resp_msg;

	// Determine the type of message to send and the type of message to receive
	switch(p_req->type)
	{
		case TYPE_RA_MSG0:
			expectingRecv = false;
	        break;

		case TYPE_RA_MSG1:
	    	msg_recv_size = sizeof(ra_samp_response_header_t) + sizeof(sgx_ra_msg2_t);
		    break;

		case TYPE_RA_MSG3:
	    	msg_recv_size = sizeof(ra_samp_response_header_t) + 177;
	        break;

		default:
			printf("Unknown message to send.\n");
			return -1;
	}

    // Send message to the challenger
	if(write(socket_desc , p_req , msg_sent_size) < 0)
    {
        printf("Send failed.\n");
        return 1;
    }

	if(expectingRecv == false) {return 0;}

    // Receive the response from the challenger
	p_resp_msg = (ra_samp_response_header_t*) malloc(msg_recv_size);
    if(read(socket_desc, p_resp_msg , msg_recv_size) < 0)
    {
        printf("Read failed");
        return 1;
    }

	*p_resp = p_resp_msg;
    return 0;
}


// Used to free the response messages.  In the sample code, the
// response messages are allocated by the SP code.
//
//
// @param resp Pointer to the response buffer to be freed.

void ra_free_network_response_buffer(ra_samp_response_header_t *resp)
{
    if(resp!=NULL)
    {
        free(resp);
    }
}
