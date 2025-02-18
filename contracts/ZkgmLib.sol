// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

interface IZkgm {
    struct Instruction {
        uint8 version;
        uint8 opcode;
        bytes operand;
    }

    function send(
        uint32 channelId,
        uint64 timeoutHeight,
        uint64 timeoutTimestamp,
        bytes32 salt,
        Instruction calldata instruction
    ) external;
}

/**
 * @title ZkgmLib
 * @notice A minimal library for encoding cross-chain messages for the Zkgm protocol.
 */
library ZkgmLib {
    // Protocol version constant
    uint8 public constant ZKGM_VERSION_0 = 0x00;
    // Opcode constant for the multiplex operation
    uint8 public constant OP_MULTIPLEX = 0x01;

    address public constant ZKGM_ADDRESS =
        0x7B7872fEc715C787A1BE3f062AdeDc82b3B06144;

    /**
     * @notice Structure representing a multiplex message payload.
     * @param sender The sender's address encoded as bytes.
     * @param eureka Flag indicating whether Eureka mode is enabled.
     * @param contractAddress The target contract address on the destination chain.
     * @param contractCalldata The calldata to be executed on the target contract.
     */
    struct Multiplex {
        bytes sender;
        bool eureka;
        bytes contractAddress;
        bytes contractCalldata;
    }

    /**
     * @notice Structure representing a Zkgm packet to be sent cross-chain.
     * @param salt Unique salt for the packet.
     * @param path The channel path (for routing), can be 0 for default.
     * @param instruction The instruction to be executed on the destination.
     */
    struct ZkgmPacket {
        bytes32 salt;
        uint256 path;
        IZkgm.Instruction instruction;  // Use IZkgm.Instruction here
    }

    event MessageSent(
        uint256 indexed channelId,
        address indexed sender,
        string message
    );

    /**
     * @notice Encodes a Multiplex structure into ABI-encoded bytes.
     * @param multiplex The Multiplex structure to encode.
     * @return The encoded bytes representing the multiplex payload.
     */
    function encodeMultiplex(
        Multiplex memory multiplex
    ) internal pure returns (bytes memory) {
        return
            abi.encode(
                multiplex.sender,
                multiplex.eureka,
                multiplex.contractAddress,
                multiplex.contractCalldata
            );
    }

    /**
     * @notice Encodes a ZkgmPacket structure into ABI-encoded bytes.
     * @param packet The ZkgmPacket structure to encode.
     * @return The encoded bytes representing the Zkgm packet.
     */
    function encode(
        ZkgmPacket memory packet
    ) internal pure returns (bytes memory) {
        return abi.encode(packet.salt, packet.path, packet.instruction);
    }

    /**
     * @dev Decodes a ZkgmPacket from bytes
     * @param data The bytes to decode
     * @return packet The decoded ZkgmPacket structure
     */
    function decodeZkgmPacket(
        bytes memory data
    ) internal pure returns (ZkgmPacket memory packet) {
        (packet.salt, packet.path, packet.instruction) = abi.decode(
            data,
            (bytes32, uint256, IZkgm.Instruction)
        );
    }

    /**
     * @dev Decodes a Multiplex from bytes
     * @param data The bytes to decode
     * @return multiplex The decoded Multiplex structure
     */
    function decodeMultiplex(
        bytes memory data
    ) internal pure returns (Multiplex memory multiplex) {
        (
            multiplex.sender,
            multiplex.eureka,
            multiplex.contractAddress,
            multiplex.contractCalldata
        ) = abi.decode(data, (bytes, bool, bytes, bytes));
    }

    /**
     * @dev Decodes an Instruction from bytes
     * @param data The bytes to decode
     * @return instruction The decoded Instruction structure
     */
    function decodeInstruction(
        bytes memory data
    ) internal pure returns (IZkgm.Instruction memory instruction) {
        (instruction.version, instruction.opcode, instruction.operand) = abi
            .decode(data, (uint8, uint8, bytes));
    }

    function sendZkgmMessage(
        bytes memory targetContractAddress,
        uint256 id
    ) internal {
        Multiplex memory multiplexData = Multiplex({
            sender: abi.encodePacked(address(this)),
            eureka: false,
            contractAddress: targetContractAddress,
            contractCalldata: abi.encode(id)
        });
        bytes memory multiplexEncoded = encodeMultiplex(multiplexData);
        IZkgm.Instruction memory instruction = IZkgm.Instruction({  // Use IZkgm.Instruction here
            version: ZKGM_VERSION_0,
            opcode: OP_MULTIPLEX,
            operand: multiplexEncoded
        });
        ZkgmPacket memory packet = ZkgmPacket({
            salt: keccak256(abi.encodePacked(block.timestamp)),
            path: 0,
            instruction: instruction
        });

        try
            IZkgm(ZKGM_ADDRESS).send(
                47, // Channel ID (Holesky -> Sepolia)
                0, // timeoutHeight
                18446744073709551500, // timeoutTimestamp
                packet.salt,
                instruction
            )
        {
            emit MessageSent(
                9,
                address(bytes20(targetContractAddress)),
                "Message Sent"
            );
        } catch Error(string memory reason) {
            revert(string(abi.encodePacked("Zkgm send failed: ", reason)));
        } catch (bytes memory) {
            revert("Zkgm send failed with low level error");
        }
    }
}
