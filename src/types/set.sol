// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

type set is bytes32;

using Set for set global;

library Set {
    bytes32 private constant SALT_PREFIX = "yulmate.set";

    error Set_IsNotInstantiated();
    error Set_AlreadyInstantiatedAndNotEmpty();
    error Set_DoesNotContainElement();
    error Set_AlreadyContainsElement();
    error Set_IndexOutOfBounds();

    function instantiate(string calldata /*salt*/ ) internal view returns (set instance) {
        bytes4 alreadyInstantiatedAndNotEmptySelector = Set_AlreadyInstantiatedAndNotEmpty.selector;

        assembly {
            let pointer := mload(0x40)
            mstore(pointer, SALT_PREFIX)

            let saltLength := calldataload(0x24)
            calldatacopy(add(pointer, 0x20), 0x44, saltLength)

            instance := keccak256(pointer, add(saltLength, 0x20))
            if sload(instance) {
                mstore(0x00, alreadyInstantiatedAndNotEmptySelector)
                revert(0x1c, 0x04)
            }
        }
    }

    function add(set self, bytes32 element) internal {
        bytes4 alreadyContainsElement = Set_AlreadyContainsElement.selector;

        if (!tryAdd(self, element)) {
            assembly {
                mstore(0x00, alreadyContainsElement)
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
        bytes4 doesNotContainElement = Set_DoesNotContainElement.selector;

        if (!tryRemove(self, element)) {
            assembly {
                mstore(0x00, doesNotContainElement)
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
            } iszero(gt(i, count_)) { i := add(i, 1) } {
                let elementSlot := add(self, mul(i, 0x20))
                mstore(0x20, sload(elementSlot))

                sstore(elementSlot, 0)
                sstore(keccak256(0x00, 0x40), 0)
            }
            sstore(self, 0)
        }
    }

    function foreach(set self, function(bytes32) func) internal {
        _requireInstantiated(self);

        assembly {
            for {
                let count_ := sload(self)
                let i := 1
            } iszero(gt(i, count_)) { i := add(i, 1) } {
                mstore(0x00, sload(add(self, mul(i, 0x20))))

                if iszero(call(gas(), func, 0, 0x00, 0x20, 0, 0)) {
                    let errorSize := returndatasize()

                    if errorSize {
                        let pointer := mload(0x40)

                        returndatacopy(pointer, 0x20, errorSize)
                        revert(pointer, errorSize)
                    }

                    revert(0, 0)
                }
            }
        }
    }

    function at(set self, uint256 index) internal view returns (bytes32 element) {
        _requireInstantiated(self);
        bytes4 indexOutOfBoundsSelector = Set_IndexOutOfBounds.selector;

        assembly {
            let count_ := sload(self)

            if iszero(lt(index, count_)) {
                mstore(0x00, indexOutOfBoundsSelector)
                revert(0x1c, 0x04)
            }

            element := sload(add(self, mul(add(index, 1), 0x20)))
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

    function count(set self) internal view returns (uint256 count_) {
        _requireInstantiated(self);

        assembly {
            count_ := sload(self)
        }
    }

    function isEmpty(set self) internal view returns (bool isEmpty_) {
        _requireInstantiated(self);

        assembly {
            isEmpty_ := iszero(sload(self))
        }
    }

    function values(set self) internal view returns (bytes32[] memory values_) {
        _requireInstantiated(self);

        assembly {
            values_ := mload(0x40)
            let count_ := sload(self)

            mstore(0x40, add(values_, mul(add(count_, 1), 0x20)))
            mstore(values_, count_)
            for { let i := 1 } iszero(gt(i, count_)) { i := add(i, 1) } {
                let offset := mul(i, 0x20)

                mstore(add(values_, offset), sload(add(self, offset)))
            }
        }
    }

    function _requireInstantiated(set instance) private pure {
        bytes4 isNotInstantiatedSelector = Set_IsNotInstantiated.selector;

        assembly {
            if iszero(instance) {
                mstore(0x00, isNotInstantiatedSelector)
                revert(0x1c, 0x04)
            }
        }
    }
}
