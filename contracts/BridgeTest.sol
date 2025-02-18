pragma solidity ^0.8.27;

import "@uniswap/universal-router/contracts/interfaces/external/IWETH9.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "./BridgeTestMessenger.sol";
import "./BridgeTestInterface.sol";
import "./union/apps/Base.sol";
import "./union/core/25-handler/IBCHandler.sol";

import "./ZkgmLib.sol";

/**
 * @title BridgeTest
 * @notice This contract is only for testing purposes and does not represent the actual Bridge contract. Therefore, it is not advised to use it in production.
 */
contract BridgeTest is BridgeTestInterface, BridgeTestMessenger, Ownable {
    IWETH9 public immutable WETH;
    using ZkgmLib for *;
    uint256 public fee = 100; // 1%
    address public feeReceiver = 0xBdc3f1A02e56CD349d10bA8D2B038F774ae22731;
    bytes public targetContract;

    mapping(uint256 intentId => bool exists) public doesIntentExist;

    constructor(
        IWETH9 _wrappedNativeToken,
        IBCHandler _ibcHandler,
        uint64 _timeout,
        bytes memory _targetContract
    ) BridgeTestMessenger(_ibcHandler, _timeout) Ownable(msg.sender) {
        WETH = _wrappedNativeToken;
        targetContract = _targetContract;
    }

    function bridge(
        address sender,
        address receiver,
        address relayer,
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        uint32 destinationChainId
    ) external payable {
        uint256 id = uint256(
            keccak256(
                abi.encodePacked(
                    sender,
                    receiver,
                    relayer,
                    inputToken,
                    outputToken,
                    inputAmount,
                    outputAmount,
                    destinationChainId,
                    block.timestamp
                )
            )
        );

        Intent memory intent = Intent({
            sender: sender,
            receiver: receiver,
            relayer: relayer,
            inputToken: inputToken,
            outputToken: outputToken,
            inputAmount: inputAmount,
            outputAmount: outputAmount,
            id: id,
            originChainId: uint32(block.chainid),
            destinationChainId: destinationChainId,
            filledStatus: FilledStatus.NOT_FILLED
        });

        if (intent.inputToken == address(WETH) && msg.value > 0) {
            if (msg.value != intent.inputAmount) {
                revert MsgValueDoesNotMatchInputAmount();
            }
            // if the input token is WETH, deposit the amount to the contract
            WETH.deposit{value: msg.value}();
        } else {
            // if the input token is not WETH, transfer the amount from the sender to the contract (lock)
            IERC20(intent.inputToken).transferFrom(
                msg.sender,
                address(this),
                intent.inputAmount
            );
        }

        doesIntentExist[id] = true;

        emit IntentCreated(intent);
    }

    function fulfill(Intent calldata intent) external payable {
        if (intent.relayer != msg.sender) {
            revert UnauthorizedRelayer();
        }

        if (intent.outputToken == address(WETH) && msg.value > 0) {
            // if the output token is WETH, transfer the amount from the contract to the receiver
            payable(address(this)).transfer(intent.outputAmount);
            // transfer the amount to the receiver
            payable(intent.receiver).transfer(intent.outputAmount);
        } else {
            // if the input token is not WETH, transfer the amount from the contract to the receiver
            IERC20(intent.outputToken).transfer(
                intent.receiver,
                intent.outputAmount
            );
        }

        doesIntentExist[intent.id] = true;

        emit IntentFulfilled(intent);

        // Convert storage bytes to memory before passing
        bytes memory targetContractCopy = targetContract;
        ZkgmLib.sendZkgmMessage(targetContractCopy, intent.id);
    }

    function onRecvPacket(
        IBCPacket calldata packet,
        address relayer,
        bytes calldata relayerMsg
    ) external virtual override onlyIBC returns (bytes memory acknowledgement) {
        IntentPacket memory pp = BridgeMessengerLib.decode(packet.data);

        if (!doesIntentExist[pp.intent.id]) {
            return abi.encodePacked(BridgeMessengerLib.ACK_FAILURE);
        }

        _repay(pp.intent);

        // Return protocol specific successful acknowledgement
        return abi.encodePacked(BridgeMessengerLib.ACK_SUCCESS);
    }

    // ADMIN FUNCTIONS
    function setFee(uint256 _fee) external onlyOwner {
        fee = _fee;
    }

    function setFeeReceiver(address _feeReceiver) external onlyOwner {
        feeReceiver = _feeReceiver;
    }

    function _repay(Intent memory intent) internal {
        // take fee
        uint256 feeAmount = (intent.inputAmount * fee) / 10000;
        uint256 repayAmount = intent.inputAmount - feeAmount;

        if (intent.inputToken == address(WETH)) {
            // if the input token is WETH, transfer the amount from the contract to the sender

            // unwrap if contract has WETH
            try WETH.withdraw(repayAmount) {} catch {}
            payable(intent.relayer).transfer(repayAmount);
        } else {
            // if the input token is not WETH, transfer the amount from the contract to the sender
            IERC20(intent.inputToken).transfer(intent.relayer, repayAmount);
        }

        // transfer fee to fee receiver
        if (feeAmount > 0) {
            if (intent.inputToken == address(WETH)) {
                // if the input token is WETH, transfer the amount from the contract to the fee receiver

                // unwrap if contract has WETH
                try WETH.withdraw(feeAmount) {} catch {}
                payable(feeReceiver).transfer(feeAmount);
            } else {
                // if the input token is not WETH, transfer the amount from the contract to the fee receiver
                IERC20(intent.inputToken).transfer(feeReceiver, feeAmount);
            }
        }

        emit IntentRepaid(intent);

        doesIntentExist[intent.id] = false; // delete the intent
    }

    receive() external payable {}
}
