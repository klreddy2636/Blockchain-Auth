// UserDataStorage.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UserDataStorage {
    mapping(address => string) private userData;

    function storeUserData(string memory data) public {
        userData[msg.sender] = data;
    }

    function getUserData() public view returns (string memory) {
        return userData[msg.sender];
    }
}
