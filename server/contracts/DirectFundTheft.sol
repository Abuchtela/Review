// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title L1CrossDomainMessengerMock
 * @notice Mock implementation of L1CrossDomainMessenger for testing
 */
contract L1CrossDomainMessengerMock {
    address private xDomainMsgSender;
    
    function setXDomainMessageSender(address _sender) external {
        xDomainMsgSender = _sender;
    }
    
    function xDomainMessageSender() external view returns (address) {
        return xDomainMsgSender;
    }
    
    function sendMessage(address _target, bytes memory _message, uint32 _gasLimit) external {
        // Just a mock that does nothing
    }
}

/**
 * @title L2BridgeMock
 * @notice Mock implementation of L2 bridge for reference
 */
contract L2BridgeMock {
    // Empty placeholder contract
}

/**
 * @title VulnerableL1StandardBridge
 * @notice A simplified version of the L1StandardBridge with vulnerabilities
 */
contract VulnerableL1StandardBridge {
    address public immutable MESSENGER;
    address public immutable L2_BRIDGE;
    
    mapping(address => uint256) public deposits;
    
    event ETHDepositInitiated(address indexed from, address indexed to, uint256 amount);
    event ETHWithdrawalFinalized(address indexed from, address indexed to, uint256 amount);
    
    constructor(address _messenger, address _l2Bridge) {
        MESSENGER = _messenger;
        L2_BRIDGE = _l2Bridge;
    }
    
    // Deposit ETH function
    function depositETH(address _to) external payable {
        deposits[msg.sender] += msg.value;
        
        emit ETHDepositInitiated(msg.sender, _to, msg.value);
        
        // Simplified message sending, in reality would cross domains
        bytes memory message = abi.encodeWithSignature(
            "finalizeDeposit(address,address,uint256)",
            msg.sender,
            _to,
            msg.value
        );
        
        // Send message to L2 (simplified for this example)
        IL1CrossDomainMessenger(MESSENGER).sendMessage(L2_BRIDGE, message, 100000);
    }
    
    // VULNERABLE: Missing proper validation of the sender
    // This function should only be callable via a cross-domain message
    function finalizeETHWithdrawal(
        address _from,
        address _to,
        uint256 _amount
    ) external {
        // VULNERABILITY: No validation that this was called via cross-domain message
        // Anyone can call this function directly and drain funds
        
        // Should check: require(msg.sender == MESSENGER && 
        //               IL1CrossDomainMessenger(MESSENGER).xDomainMessageSender() == L2_BRIDGE)
        
        (bool success, ) = _to.call{value: _amount}("");
        require(success, "ETH transfer failed");
        
        emit ETHWithdrawalFinalized(_from, _to, _amount);
    }
    
    // VULNERABLE: Anyone can call this emergency function
    function emergencyWithdraw(address _to, uint256 _amount) external {
        // VULNERABILITY: No access control
        // Should have: require(msg.sender == owner, "Not authorized");
        
        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Emergency withdraw failed");
    }
    
    // For receiving ETH
    receive() external payable {}
}

/**
 * @title SimpleBank
 * @notice A simple bank contract that will be targeted by an exploit
 */
contract SimpleBank {
    mapping(address => uint256) public balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw(address _to, uint256 _amount) external {
        // VULNERABLE: No access control, anyone can withdraw to any address
        require(_amount > 0, "Amount must be greater than 0");
        require(address(this).balance >= _amount, "Insufficient contract balance");
        
        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Withdrawal failed");
        
        emit Withdrawal(_to, _amount);
    }
    
    receive() external payable {}
}

interface IL1CrossDomainMessenger {
    function sendMessage(address _target, bytes memory _message, uint32 _gasLimit) external;
    function xDomainMessageSender() external view returns (address);
}
