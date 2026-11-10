// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IUniswapV2Router02 {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

contract DeadlinelessTrader {
    IUniswapV2Router02 public router;
    mapping(address => bool) public filled;

    constructor(IUniswapV2Router02 router_) {
        router = router_;
    }

    function swap(uint256 amountIn, uint256 amountOutMin, address[] calldata path) external {
        router.swapExactTokensForTokens(amountIn, amountOutMin, path, msg.sender, type(uint256).max);
        filled[msg.sender] = true;
    }
}
