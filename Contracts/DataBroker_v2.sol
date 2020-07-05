pragma solidity ^0.4.0;

contract DataBroker_v2 {
    /* Public viewable valiables */
    address public DB;                        // The DataBroker - owner of this contract
    int public DO_List_Length;                // Length of the above DO list
    int public taskCount;                     // Number of DataConsumer records so far
    uint public waitTimeOut;                 // Length of time DC needs to wait before asking for refund
    int public status;                        // 0: waiting for request(), 1: waiting for computationComplete(),
                                              // 2: waiting for completeTransaction()
    /* Internal variables */
    uint totalPrice;
    address DC_cur;
    int op_cur;
    int avail_source_num;
    mapping(int => uint) DO_WorkingList;
    struct dataSource_t {                      // Atomic data source type
        int DO_ID;                             // Starts from 1
        address DO;
        int op;
        uint price;
        mapping(address => bool) DC_auth_list;
        bool isConfirmed;
    }
    struct dataRecord_t {                    // Atomic data record type
        address DC;
        int op;
        uint DC_CompleteTime;                // The time point when receiving computationComplete() from DC
        uint TransactionTime;                // The time point when receiving completeTransaction() from DO/DB
        string DOs_used;                     // List of DOs used for computation
        string K_result;                     // A AESGCM-128 key (16 Bytes) for DC to decrypt computation result
        bytes32 K_result_hash;               // SHA3 (keccak256) hash of K_result
    }
    
    /* Addition public viewable variables for book keeping */
    mapping(address => int) public DO_List;
    mapping(int => dataSource_t) public dataSourceList;
    mapping(int => dataRecord_t) public dataRecordList;

    constructor() public {
        DB = msg.sender;
        DO_List_Length = 0;
        taskCount = 0;
        status = 0;
        waitTimeOut = 600;  // 10 min. increase it to 2 hrs in real case.
    }

    /* Handle register tx from DO: (Current design) all attributes can be changed simultaneously.
       To add a new DC: assign DC_action = 0. 
       To ban a old DC: assign DC_action = else. */
    function register(int op, uint price, address DC, int DC_action) public {
        if(DO_List[msg.sender] == 0) { // new DO registration
            dataSourceList[DO_List_Length].DO_ID = DO_List_Length + 1;
            DO_List[msg.sender] = DO_List_Length + 1;
            dataSourceList[DO_List_Length].DO = msg.sender;
            DO_List_Length ++;
            
        }
        int tmpDO_ID = DO_List[msg.sender];
        dataSourceList[tmpDO_ID-1].op = op;
        dataSourceList[tmpDO_ID-1].price = price; // in wei. 1 eth = 1000000000000000000 wei
        dataSourceList[tmpDO_ID-1].DC_auth_list[DC] = (DC_action==0);   // 0 => true 
        dataSourceList[tmpDO_ID-1].isConfirmed = false;
    }

    /* Handle confirm tx from DB: confirms all DOs' registrations 
       Note: if the DB does't want to confirm, it may off-line ask some DOs to re-register to desired info. */
    function confirm() public {
        if(msg.sender == DB) {
            for(int i=0; i<DO_List_Length; i++) {
                dataSourceList[i].isConfirmed = true;
            }
        }
    }

    /* Handle request tx from DC.
       Assume the DC requests for all DO's data, except those don't have this DC is list or with different op. */
    function request(int DO_range_start, int DO_range_end, int op) public payable {
        if(status != 0) {                               // Contract onhold, unable to accept new request from DC
            msg.sender.transfer(msg.value);             // Return the value
            return;
        }
        totalPrice = 0;
        avail_source_num = 0;
        
        for(int i=DO_range_start-1; i<DO_range_end && i<DO_List_Length; i++) {
            dataSource_t storage tmpDS = dataSourceList[i];
            if(tmpDS.isConfirmed == true && tmpDS.DO_ID !=0 && tmpDS.op == op && tmpDS.DC_auth_list[msg.sender] == true) {
                DO_WorkingList[avail_source_num] = uint(i+1);
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
            dataRecordList[taskCount].DOs_used = appendUintToString(dataRecordList[taskCount].DOs_used, DO_WorkingList[i]);
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
        if(status != 2 || msg.sender != DB) {
            return;
        } 
        if(keccak256(abi.encodePacked(K_result)) == dataRecordList[taskCount].K_result_hash) {
            dataRecordList[taskCount].TransactionTime = block.timestamp;
            dataRecordList[taskCount].K_result = K_result;
            
            address tmpDO;
            for(int i=0; i<avail_source_num; i++) {
                tmpDO = dataSourceList[int(DO_WorkingList[i])-1].DO;
                tmpDO.transfer(dataSourceList[int(DO_WorkingList[i])-1].price);
            }
            taskCount ++;
            status = 0;
        }
    }
    
    /* Handle revoke tx from DB: Revoke the contract */
    function revoke() public {
        if(status == 0 && msg.sender == DB) {
            if(address(this).balance > 0) {
                DB.transfer(address(this).balance);
            }
            selfdestruct(DB);
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