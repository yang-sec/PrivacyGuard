#ifndef _OPERATIONS_H_
#define _OPERATIONS_H_


#if defined(__cplusplus)
extern "C" {
#endif


int generate_data_type(int DO_ID, int data_counter, int num_data_points, int dataType);

int register_data_on_Contract(double* fTime, char* contract_addr, char *DO_address, char *DO_pkey, int contractType, int data, int operation, double price, char* DC_addr, int DC_action);


#if defined(__cplusplus)
}
#endif
#endif