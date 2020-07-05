pragma solidity ^0.4.0;

contract Datause {
    address public DataOwner; 
    uint public price; // unit: wei
    bool public isOnHold; // true: waiting for record msg; false: waiting for request msg
    address public DC_cur; // Current DataConsumer
    int op_cur;
    int data_cur;
    
    int data_list;
    int op_list;
    
    struct dataRecord {
        address dc;
        int op_num;
        int data_num;
    }
    
    mapping(address => dataRecord) public dataRecords;

    constructor() public {
        DataOwner = msg.sender;
        price = 0.01 * 1000000000000000000; // wei
        data_list = 1;
        op_list = 1;
        isOnHold = false;
    }

    // Handle request transaction
    function request(int data, int op) public payable returns(int)
    {
        if(isOnHold == true) // Contract onhold, unable to accept new request
        { 
            msg.sender.transfer(msg.value); // Return the value
            return 1;
        }
        
        if(msg.value < price || data != data_list || op != op_list) // Insufficient fund or wrong data / operation
        { 
            msg.sender.transfer(msg.value); // Return the value
            return 2;
        }
        else if(msg.value > price) // Return the overpaid amount if any
        {
            msg.sender.transfer(msg.value - price);
        }
        
        DC_cur = msg.sender;
        op_cur = op;
        data_cur = data;
        isOnHold = true;
        return 0;
    }

    // Handle record transaction
    function record() public returns(int)
    {
        if(isOnHold == false || msg.sender != DC_cur) { // Contract is not onhold or wrong data consumer
            return 1;
        } 
        
        /* Write the record in the record history */
        dataRecords[DC_cur].dc = DC_cur;
        dataRecords[DC_cur].op_num = op_cur;
        dataRecords[DC_cur].data_num = data_cur;
        
        DataOwner.transfer(price); // Transfer the frozen cash to data owner
        isOnHold = false;
        return 0;
    }
    
    // Return the balance of this contract to DataOwner if there is any
    function getBalance() public
    {
        if(isOnHold == false && address(this).balance > 0)
        {
            DataOwner.transfer(address(this).balance);
        }
    }
    
    // Revoke the contract
    function revoke() public
    {
        if(isOnHold == false && msg.sender == DataOwner)
        {
            selfdestruct(DataOwner);
        }
    }
}
