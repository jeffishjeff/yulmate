// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

type set is bytes32;

using Set for set global;

library Set {
    bytes32 private constant SALT_PREFIX = "yulmate.set";

    error SetNotInstantiated();
    error SetAlreadyInstantiatedAndNotEmpty();
    error ElementNotInSet();
    error ElementAlreadyInSet();

    function instantiate(string calldata /*salt*/ ) internal view returns (set instance) {
        bytes4 setAlreadyInstantiatedAndNotEmptySelector = SetAlreadyInstantiatedAndNotEmpty.selector;

        assembly {
            let pointer := mload(0x40)
            mstore(pointer, SALT_PREFIX)

            let saltLength := calldataload(0x24)
            calldatacopy(add(pointer, 0x20), 0x44, saltLength)

            instance := keccak256(pointer, add(saltLength, 0x20))
            if sload(instance) {
                mstore(0x00, setAlreadyInstantiatedAndNotEmptySelector)
                revert(0x1c, 0x04)
            }
        }
    }

    function add(set self, bytes32 element) internal {
        bytes4 elementAlreadyInSetSelector = ElementAlreadyInSet.selector;

        if (!tryAdd(self, element)) {
            assembly {
                mstore(0x00, elementAlreadyInSetSelector)
                revert(0x1c, 0x04)
            }
        }
    }

    function tryAdd(set self, bytes32 element) internal returns (bool success) {
        _requireInstantiated(self);

        assembly {
            mstore(0x00, self)
            mstore(0x20, element)
            let elementPositionSlot := keccak256(0x00, 0x40)

            if iszero(sload(elementPositionSlot)) {
                let count_ := add(sload(self), 1)

                sstore(self, count_)
                sstore(add(self, mul(count_, 0x20)), element)
                sstore(elementPositionSlot, count_)

                success := true
            }
        }
    }

    function remove(set self, bytes32 element) internal {
        bytes4 elementNotInSetSelector = ElementNotInSet.selector;

        if (!tryRemove(self, element)) {
            assembly {
                mstore(0x00, elementNotInSetSelector)
                revert(0x1c, 0x04)
            }
        }
    }

    function tryRemove(set self, bytes32 element) internal returns (bool success) {
        _requireInstantiated(self);

        assembly {
            mstore(0x00, self)
            mstore(0x20, element)
            let elementPositionSlot := keccak256(0x00, 0x40)
            let elementPosition := sload(elementPositionSlot)

            if elementPosition {
                let count_ := sload(self)
                let lastElementSlot := add(self, mul(count_, 0x20))
                let lastElement := sload(lastElementSlot)
                mstore(0x20, lastElement)

                sstore(add(self, mul(elementPosition, 0x20)), lastElement)
                sstore(elementPositionSlot, 0)
                sstore(keccak256(0x00, 0x40), elementPosition)
                sstore(lastElementSlot, 0)
                sstore(self, sub(count_, 1))

                success := true
            }
        }
    }

    function clear(set self) internal {
        _requireInstantiated(self);

        assembly {
            mstore(0x00, self)

            for {
                let count_ := sload(self)
                let i := 1
            } lt(i, add(count_, 1)) { i := add(i, 1) } {
                let elementSlot := add(self, mul(i, 0x20))
                mstore(0x20, sload(elementSlot))

                sstore(elementSlot, 0)
                sstore(keccak256(0x00, 0x40), 0)
            }
            sstore(self, 0)
        }
    }

    function count(set self) internal view returns (uint256 count_) {
        _requireInstantiated(self);

        assembly {
            count_ := sload(self)
        }
    }

    function contains(set self, bytes32 element) internal view returns (bool contains_) {
        _requireInstantiated(self);

        assembly {
            mstore(0x00, self)
            mstore(0x20, element)
            contains_ := sload(keccak256(0x00, 0x40))
        }
    }

    function _requireInstantiated(set instance) private pure {
        bytes4 setNotInstantiatedSelector = SetNotInstantiated.selector;

        assembly {
            if iszero(instance) {
                mstore(0x00, setNotInstantiatedSelector)
                revert(0x1c, 0x04)
            }
        }
    }
}
