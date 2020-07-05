pragma solidity ^0.4.0;

contract DataBroker_v1 {
    /* Public viewable valiables */
    address public DB;                        // The DataBroker - owner of this contract
    mapping(int => address) public DO_List;   // A list of registered DO addresses
    int public DO_List_length;                // Length of the above DO list
    int public taskCount;                     // Number of DataConsumer records so far
    bool public isWorking;                    // true: still waiting for the record() transaction (blocking)
    
    /* Internal variables */
    uint totalPrice;
    int  avail_source_num;
    address DC_cur;
    int op_cur;
    mapping(int => address) DO_WorkingList;
    struct dataSource {                      // Atomic data source type
        int data;
        int op;
        uint price;
        mapping(address => bool) DC_auth_list;
        bool isConfirmed;
    }
    struct dataRecord_t {                    // Atomic data record type
        address DC;
        int op;
        uint time;
        bytes16 key_ran_en;                  // Encrypted random key (128-bit AESGCM key)
        address[] DO_RecordList;
    }
    
    /* Addition public viewable variables for book keeping */
    mapping(address => dataSource) public dataSourceList;
    mapping(int => dataRecord_t) public dataRecordList;

    constructor() public {
        DB = msg.sender;
        DO_List_length = 0;
        taskCount = 0;
        isWorking = false;
    }

    /* Handle register tx from DO: (Current design) all attributes can be changed simultaneously.
       The value of new data cannot be 0 (data == 0 means no data).
       To add a new DC: assign DC_action = 0. 
       To ban a old DC: assign DC_action = else. */
    function register(int data, int op, uint price, address DC, int DC_action) public {
        if(dataSourceList[msg.sender].data == 0) { // new registration
            DO_List[DO_List_length] = msg.sender;
            DO_List_length ++;
        }
        dataSourceList[msg.sender].data = data;
        dataSourceList[msg.sender].op = op;
        dataSourceList[msg.sender].price = price; // in wei. When using remix, change to price*1000000000000000000 for convenience
        dataSourceList[msg.sender].DC_auth_list[DC] = (DC_action==0);   // 0 => true 
        dataSourceList[msg.sender].isConfirmed = false;
    }

    /* Handle confirm tx from DB: confirms all DOs' registrations 
       Note: if the DB does't want to confirm, it may off-line ask some DOs to re-register to desired info. */
    function confirm() public {
        if(msg.sender == DB && isWorking == false) {
            for(int i=0; i<DO_List_length; i++) {
                dataSourceList[DO_List[i]].isConfirmed = true;
            }
        }
    }

    /* Handle request tx from DC.
       Assume the DC requests for all DO's data, except those don't have this DC is list or with different op. */
    function request(int DO_range_start, int DO_range_end, int op) public payable {
        if(isWorking == true) {                               // Contract onhold, unable to accept new request from DC
            msg.sender.transfer(msg.value);                   // Return the value
            return;
        }
        
        totalPrice = 0;
        avail_source_num = 0;
        
        for(int i=0; i<DO_List_length; i++) {
            dataSource storage tmpDS = dataSourceList[DO_List[i]];
            if(i >= DO_range_start-1 && i <= DO_range_end-1 && tmpDS.isConfirmed == true && tmpDS.op == op && tmpDS.DC_auth_list[msg.sender] == true) {
                DO_WorkingList[avail_source_num] = DO_List[i];
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
            address tmpDO = DO_WorkingList[i];
            dataRecordList[taskCount].DO_RecordList.push(tmpDO);
            tmpDO.transfer(dataSourceList[tmpDO].price);
        }
        taskCount ++;
        isWorking = false;
    }
    
    /* Handle revoke tx from DB: Revoke the contract */
    function revoke() public {
        if(isWorking == false && msg.sender == DB) {
            if(address(this).balance > 0) {
                DB.transfer(address(this).balance);
            }
            selfdestruct(DB);
        }
    }
}