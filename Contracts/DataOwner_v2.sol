pragma solidity ^0.4.0;

contract DataOwner_v2 {
    /* Public viewable valiables */
    address public DO;                       // The DataOwner - owner of this contract
    int public Data_List_Length;             // Length of the above data list
    int public taskCount;                    // Number of DataConsumer records so far
    uint public waitTimeOut;                 // Length of time DC needs to wait before asking for refund
    int public status;                       // 0: waiting for request(), 1: waiting for computationComplete(),
                                             // 2: waiting for completeTransaction()
    /* Internal variables */
    uint totalPrice;
    address DC_cur;
    int op_cur;
    int avail_source_num;
    mapping(int => uint) data_WorkingList;
    struct dataSource_t {                    // Single data source type
        int data;
        int op;
        uint price;
        mapping(address => bool) DC_auth_list;
    }
    struct dataRecord_t {                    // Single data record type
        address DC;
        int op;
        uint DC_CompleteTime;                // The time point when receiving computationComplete() from DC
        uint TransactionTime;                // The time point when receiving completeTransaction() from DO/DB
        string Data_used;                    // List of data used for computation
        string K_result;                     // A AESGCM-128 key (16 Bytes) for DC to decrypt computation result
        bytes32 K_result_hash;               // SHA3 (keccak256) hash of K_result
    }
    
    /* Addition public viewable variables for book keeping */
    mapping(int => dataSource_t) public dataSourceList;
    mapping(int => dataRecord_t) public dataRecordList;

    /* Contract creation */
    constructor() public {
        DO = msg.sender;
        Data_List_Length = 0;
        taskCount = 0;
        status = 0;
        waitTimeOut = 600;  // 10 min. increase it to 2 hrs in real case.
    }

    /* Handle register tx from DO: (Current design) all attributes can be changed simultaneously. */
    // The value of data starts from 1 (data == 0 means no data).
    // To add a new DC: assign DC_action = 0. 
    // To ban a old DC: assign DC_action = else.
    function register(int data, int op, uint price, address DC, int DC_action) public {
        if(msg.sender == DO) {
            if(dataSourceList[data-1].data == 0) { // new DO registration
                Data_List_Length ++;
            }
            dataSourceList[data-1].data = data;
            dataSourceList[data-1].op = op;
            dataSourceList[data-1].price = price; // in wei. When using remix, change to price*1000000000000000000 for convenience
            dataSourceList[data-1].DC_auth_list[DC] = (DC_action==0);   // 0 <=> true
        }
    }

    /* Handle request tx from DC. */
    // Assume the DC requests a specific data with desired operation.
    function request(int data_range_start, int data_range_end, int op) public payable {
        if(status != 0) {                               // Contract onhold, unable to accept new request from DC
            msg.sender.transfer(msg.value);             // Return the value
            return;
        }
        
        totalPrice = 0;
        avail_source_num = 0; // avail_source_num is no bigger than 1 in this version
        
        for(int i=data_range_start-1; i<data_range_end && i<Data_List_Length; i++) { // Check only those data in range
            dataSource_t storage tmpDS = dataSourceList[i];
            if(tmpDS.data != 0 && tmpDS.op == op && tmpDS.DC_auth_list[msg.sender] == true) {
                data_WorkingList[avail_source_num] = uint(i+1);
                avail_source_num ++;
                totalPrice += tmpDS.price;
            }
        }
        if(avail_source_num == 0 || msg.value < totalPrice) { // No available data sources or insufficient fund
            msg.sender.transfer(msg.value);                   // Return the value
            return;
        }
        if(msg.value > totalPrice) { 
            msg.sender.transfer(msg.value - totalPrice);      // Return the overpaid amount if there is any
        }
        DC_cur = msg.sender;
        op_cur = op;
        status = 1;
    }

    /* Handle computationComplete tx from DC */
    function computationComplete(bytes32 K_result_hash) public {
        if(status != 1 || msg.sender != DC_cur) {
            return;
        } 
        dataRecordList[taskCount].DC = msg.sender;
        dataRecordList[taskCount].op = op_cur;
        dataRecordList[taskCount].DC_CompleteTime = block.timestamp;
        dataRecordList[taskCount].K_result_hash = K_result_hash;
        
        for(int i=0; i<avail_source_num; i++) {
            dataRecordList[taskCount].Data_used = appendUintToString(dataRecordList[taskCount].Data_used, data_WorkingList[i]);
        }
        status = 2;
    }
    
    /* Handle cancel tx from DC */
    // Refund DC if timeout is met
    function cancel() public {
        if(status != 2 || msg.sender != DC_cur) {
            return;
        } 
        if((block.timestamp - waitTimeOut) > dataRecordList[taskCount].DC_CompleteTime) {
            dataRecordList[taskCount].TransactionTime = block.timestamp;
            dataRecordList[taskCount].K_result = "Cancelled by DC.";
            taskCount ++;
            msg.sender.transfer(totalPrice);
            status = 0;
        }
    } 
    
    /* Handle completeTransaction tx from DO/DB */
    function completeTransaction(string K_result) public {
        if(status != 2 || msg.sender != DO) {
            return;
        } 
        if(keccak256(abi.encodePacked(K_result)) == dataRecordList[taskCount].K_result_hash) {
            dataRecordList[taskCount].TransactionTime = block.timestamp;
            dataRecordList[taskCount].K_result = K_result;
            DO.transfer(totalPrice);
            taskCount ++;
            status = 0;
        }
    }
    
    /* Handle revoke tx from DB: Revoke the contract */
    function revoke() public {
        if(status == 0 && msg.sender == DO) {
            if(address(this).balance > 0) {
                DO.transfer(address(this).balance);
            }
            selfdestruct(DO);
        }
    }
    
    /* Internal use: add uint to string */
    function appendUintToString(string inStr, uint v) internal pure returns(string) {
        uint maxlength = 100;
        bytes memory reversed = new bytes(maxlength);
        uint i = 0;
        uint j;
        while (v != 0) {
            uint remainder = v % 10;
            v = v / 10;
            reversed[i++] = byte(48 + remainder);
        }
        bytes memory inStrb = bytes(inStr);
        bytes memory s = new bytes(inStrb.length + i + 1);
        for (j = 0; j < inStrb.length; j++) {
            s[j] = inStrb[j];
        }
        for (j = 0; j < i; j++) {
            s[j + inStrb.length] = reversed[i - 1 - j];
        }
        return(string(s));
    }
}