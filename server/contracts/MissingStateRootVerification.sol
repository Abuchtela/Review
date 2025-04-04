// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title L2OracleMock
 * @notice Mock implementation of the L2 oracle
 */
contract L2OracleMock {
    // This would typically store historical state roots
    mapping(uint256 => bytes32) public stateRoots;
    
    function setStateRoot(uint256 _blockNumber, bytes32 _stateRoot) external {
        stateRoots[_blockNumber] = _stateRoot;
    }
    
    function getStateRoot(uint256 _blockNumber) external view returns (bytes32) {
        return stateRoots[_blockNumber];
    }
}

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
    
    // Vulnerable functions from the vulnerability report
    function lockFunds() external payable {
        // Vulnerability: No recovery mechanism, funds could be locked indefinitely
        // This function just accepts funds but has no way to retrieve them
    }
    
    function releaseFunds() external {
        // This function is intentionally empty to simulate a non-functional rescue mechanism
        revert("Function disabled");
    }
    
    // Receive ETH function
    receive() external payable {}
}

/**
 * @title SimpleBank
 * @notice A simple bank contract that can be targeted by the missing state root verification exploit
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
