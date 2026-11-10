// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract LooseExecutor {
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
