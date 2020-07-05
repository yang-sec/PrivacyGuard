pragma solidity ^0.4.0;

contract DataOwner_v1 {
    /* Public viewable valiables */
    address public DO;                        // The DataOwner - owner of this contract
    int public Data_List_Length;                     // Length of the above data list
    int public taskCount;                     // Number of DataConsumer records so far
    bool public isWorking;                    // true: still waiting for the record() transaction (blocking)
    
    /* Internal variables */
    uint totalPrice;
    address DC_cur;
    int data_cur;
    int op_cur;
    int avail_source_num;
    mapping(int => int) data_WorkingList;
    
    struct dataSource_t {                      // Atomic data source type
        int data;
        int op;
        uint price;
        mapping(address => bool) DC_auth_list;
    }
    struct dataRecord_t {                    // Atomic data record type
        address DC;
        int op;
        uint time;
        bytes16 key_ran_en;                  // Encrypted random key (128-bit AESGCM key)
        int [] data_used_List;
    }
    
    /* Addition public viewable variables for book keeping */
    mapping(int => dataSource_t) public dataSourceList;
    mapping(int => dataRecord_t) public dataRecordList;

    constructor() public {
        DO = msg.sender;
        Data_List_Length = 0;
        taskCount = 0;
        isWorking = false;
    }

    /* Handle register tx from DO: (Current design) all attributes can be changed simultaneously.
       The value of data starts from 1 (data == 0 means no data).
       To add a new DC: assign DC_action = 0. 
       To ban a old DC: assign DC_action = else. */
    function register(int data, int op, uint price, address DC, int DC_action) public {
        if(msg.sender == DO) {
            Data_List_Length ++;
            dataSourceList[data-1].data = data;
            dataSourceList[data-1].op = op;
            dataSourceList[data-1].price = price; // in wei. When using remix, change to price*1000000000000000000 for convenience
            dataSourceList[data-1].DC_auth_list[DC] = (DC_action==0);   // 0 <=> true
        }
    }

    /* Handle request tx from DC.
       Assume the DC requests a specific data with desired operation. */
    function request(int data_range_start, int data_range_end, int op) public payable {
        if(isWorking == true) {                               // Contract onhold, unable to accept new request from DC
            msg.sender.transfer(msg.value);                   // Return the value
            return;
        }
        
        totalPrice = 0;
        avail_source_num = 0; // avail_source_num is no bigger than 1 in version_1
        
        for(int i=data_range_start-1; i<data_range_end && i<Data_List_Length; i++) { // Check only those data in range
            dataSource_t storage tmpDS = dataSourceList[i];
            if(tmpDS.op == op && tmpDS.DC_auth_list[msg.sender] == true) {
                data_WorkingList[avail_source_num] = i+1;
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
        isWorking = true;
    }

    /* Handle record tx from CEE */
    function record(bytes16 key_ran_en) public {
        if(isWorking == false || msg.sender != DC_cur) {      // Contract is not onhold or wrong data consumer
            return;
        } 
        
        dataRecordList[taskCount].DC = msg.sender;
        dataRecordList[taskCount].op = op_cur;
        dataRecordList[taskCount].time = block.timestamp;
        dataRecordList[taskCount].key_ran_en = key_ran_en;
        
        for(int i=0; i<avail_source_num; i++) {
            dataRecordList[taskCount].data_used_List.push(data_WorkingList[i]);
        }
        DO.transfer(totalPrice);
        taskCount ++;
        isWorking = false;
    }
    
    /* Handle revoke tx from DB: Revoke the contract */
    function revoke() public {
        if(isWorking == false && msg.sender == DO) {
            if(address(this).balance > 0) {
                DO.transfer(address(this).balance);
            }
            selfdestruct(DO);
        }
    }
}