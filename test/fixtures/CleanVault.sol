// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @dev Deliberately careful vault: CEI ordering, reentrancy guard,
///      zero-address checks, fee-on-transfer measurement, events on admin ops.
contract CleanVault {
    IERC20 public immutable token;
    address public owner;
    bool private _locked;
    mapping(address => uint256) public shares;

    event Withdrawn(address indexed account, uint256 amount);
    event OwnerChanged(address indexed previousOwner, address indexed nextOwner);

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(IERC20 token_, address owner_) {
        require(owner_ != address(0), "zero owner");
        token = token_;
        owner = owner_;
    }

    function setOwner(address nextOwner) external onlyOwner {
        require(nextOwner != address(0), "zero address");
        owner = nextOwner;
        emit OwnerChanged(owner, nextOwner);
    }

    function deposit(uint256 amount) external nonReentrant {
        uint256 before = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        require(token.balanceOf(address(this)) - before == amount, "fee-on-transfer token");
        shares[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
