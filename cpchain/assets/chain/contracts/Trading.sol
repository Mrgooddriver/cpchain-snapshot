pragma solidity ^0.4.0;

contract Trading {

    enum State {
        Created,
        Delivered,
        Confirmed,
        Finished,
        Rated,
        Disputed,
        Withdrawn
    }

    struct OrderInfo {
        bytes32 descHash;
        bytes buyerRSAPubkey;
        address buyerAddress;
        address sellerAddress;
        address proxyAddress;
        address secondaryProxyAddress;
        uint offeredPrice;
        uint proxyFee;
        bytes32 deliverHash;
        uint endTime;
        State state;
    }

    uint public numOrders = 0;
    mapping(uint => OrderInfo) public orderRecords;

    mapping(address => uint) public proxyCredits;

    modifier onlyBefore(uint time) { require(now < time); _; }
    modifier onlyAfter(uint time) { require(now > time); _; }
    modifier onlyBuyer(uint id) { require(msg.sender == orderRecords[id].buyerAddress); _; }
    modifier onlySeller(uint id) { require(msg.sender == orderRecords[id].sellerAddress); _; }
    modifier onlyProxy(uint id) {
        require(
            msg.sender == orderRecords[id].proxyAddress ||
            msg.sender == orderRecords[id].secondaryProxyAddress
        );
        _;
    }
    modifier inState(uint id, State _state) { require(orderRecords[id].state == _state); _; }

    function Trading() public {
    }

    function() payable {
    }

    event OrderInitiated(
        address from,
        uint orderId,
        uint value
    );
    event OrderWithdrawn(address from);
    event OrderConfirmed(address from);
    event OrderDisputed(address from);
    event SellerClaimTimeout(address from);
    event ProxyClaimRelay(address from);
    event ProxyHandleDispute(address from);
    event ProxyRated(address from);
    event OrderFinalized(uint id);


    function placeOrder(
        bytes32 descHash,
        bytes buyerRSAPubkey,
        address seller,
        address proxy,
        address secondaryProxy,
        uint proxyFee,
        uint timeAllowed
    )
        public
        payable
    {
        uint thisID = numOrders++;
        orderRecords[thisID] = OrderInfo({
            descHash: descHash,
            buyerRSAPubkey: buyerRSAPubkey,
            buyerAddress: msg.sender,
            sellerAddress: seller,
            proxyAddress: proxy,
            secondaryProxyAddress: secondaryProxy,
            deliverHash: bytes32(0),
            offeredPrice: msg.value,
            proxyFee: proxyFee,
            endTime: now + timeAllowed,
            state: State.Created
        });
        OrderInitiated(msg.sender, thisID, msg.value);
    }

    function buyerWithdraw(uint id)
        public
        onlyBuyer(id)
        onlyBefore(orderRecords[id].endTime)
        inState(id, State.Created)
    {
        orderRecords[id].state = State.Withdrawn;
        orderRecords[id].buyerAddress.transfer(orderRecords[id].offeredPrice);
        OrderWithdrawn(msg.sender);
    }

    function buyerDispute(uint id)
        public
        onlyBuyer(id)
        onlyBefore(orderRecords[id].endTime)
        inState(id, State.Delivered)
    {
        orderRecords[id].state = State.Disputed;
        OrderDisputed(msg.sender);
    }

    function proxyJudge(uint id, bool decision)
        public
        onlyProxy(id)
        onlyBefore(orderRecords[id].endTime)
        inState(id, State.Disputed)
    {
        if (decision == true)
            finalizeOrder(id, orderRecords[id].sellerAddress);
        else
            finalizeOrder(id, orderRecords[id].buyerAddress);

        ProxyHandleDispute(msg.sender);
    }

    function deliverMsg(bytes32 deliverHash, uint id)
        public
        onlyProxy(id)
        onlyBefore(orderRecords[id].endTime)
        inState(id, State.Created)
    {
        orderRecords[id].deliverHash = deliverHash;
        orderRecords[id].state = State.Delivered;
        ProxyClaimRelay(msg.sender);
    }

    function confirmDeliver(uint id)
        public
        onlyBuyer(id)
        onlyBefore(orderRecords[id].endTime)
        inState(id, State.Delivered)
    {
        orderRecords[id].state = State.Confirmed;
        finalizeOrder(id, orderRecords[id].sellerAddress);
        OrderConfirmed(msg.sender);
    }

    function sellerClaimTimedOut(uint id)
        public
        onlySeller(id)
        inState(id, State.Delivered)
        onlyAfter(orderRecords[id].endTime)
    {
        finalizeOrder(id, orderRecords[id].sellerAddress);
        SellerClaimTimeout(msg.sender);
    }

    function sellerRateProxy(uint id, uint rate)
        public
        onlySeller(id)
        inState(id, State.Finished)
    {
        require(rate >= 0 && rate <= 100);
        orderRecords[id].state = State.Rated;
        proxyCredits[orderRecords[id].proxyAddress] =
            proxyCredits[orderRecords[id].proxyAddress] + rate;
        proxyCredits[orderRecords[id].secondaryProxyAddress] =
            proxyCredits[orderRecords[id].secondaryProxyAddress] + rate;
        ProxyRated(msg.sender);
    }

    function buyerRateProxy(uint id, uint rate)
        public
        onlyBuyer(id)
        inState(id, State.Finished)
    {
        require(rate >= 0 && rate <= 100);
        orderRecords[id].state = State.Rated;
        proxyCredits[orderRecords[id].proxyAddress] =
            proxyCredits[orderRecords[id].proxyAddress] + rate;
        proxyCredits[orderRecords[id].secondaryProxyAddress] =
            proxyCredits[orderRecords[id].secondaryProxyAddress] + rate;
        ProxyRated(msg.sender);
    }

    function finalizeOrder(uint id, address beneficiary)
        private
    {
        orderRecords[id].state = State.Finished;
        uint payProxy = orderRecords[id].proxyFee;
        uint payBeneficiary = orderRecords[id].offeredPrice - payProxy * 2;
        beneficiary.transfer(payBeneficiary);
        orderRecords[id].proxyAddress.transfer(payProxy);
        orderRecords[id].secondaryProxyAddress.transfer(payProxy);
        OrderFinalized(id);
    }
}
