App/App.py verison = 1.1
from flask import Flask, render_template, redirect, url_for, request, session, flash
from web3 import Web3
from eth_account import Account
import hashlib
import os
from hexbytes import HexBytes
from eth_account.messages import encode_defunct

app = Flask(__name__)
app.secret_key = os.urandom(24)
user_data_store = {}

# Connect to an Ethereum node (replace 'http://localhost:8545' with your node's URL)
w3 = Web3(Web3.HTTPProvider('http://localhost:7545'))

if not w3.is_connected():
    raise ConnectionError("Could not connect to Ethereum node. Make sure it's running and the URL is correct.")

# Load the contract ABI and address (replace with your deployed contract's ABI and address)
contract_abi = [
    {
        "inputs": [],
        "name": "constructor",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "user_data",
                "type": "string"
            }
        ],
        "name": "storeUserData",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getUserData",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]  # ABI of UserDataStorage
contract_address = Web3.to_checksum_address('0xDaF7b6CA2F3aC038B440d6f9b6d22F54De510405')
# Set the default account using MetaMask


# Create contract instance
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def hash_message(message):
    # Convert the message to bytes before hashing
    print("In hash_message fn")
    message_bytes = message.encode('utf-8')
    try:
        # Use hashlib to hash the message
        prefixed_message = b'\x19Ethereum Signed Message:\n' + bytes([len(message_bytes)]) + message_bytes
        hashed_message = Web3.keccak(prefixed_message)
    except Exception as e:
        # Use Web3.keccak to hash the message
        print(f"Error Hashing data: {e}")

    return hashed_message

@app.route('/')
def home():
    return render_template('home.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            default_account = None
            
            print(1)
            # Get the signature from the form
            signature = request.form['signature']
            user_data = request.form['user_data']
            #private_key = request.form['private_key']
            if signature:   #Signature is a hexadecimal string of 66 characters
                print(2)
                print(f"user_data: {user_data}")        
                print(f"Signature: {signature}")
                #print(f"Private_key: {private_key}")
                #print(f"hashed Message:{hash_message(user_data)}") 
                # Recover the address from the signature
                #recovered_address = w3.eth.account.recover(hash_message(user_data), signature)
                
                recovered_address = w3.eth.account.recover_message(encode_defunct(text=user_data), signature=HexBytes(signature))
                print(f"Recovered Address: {recovered_address}")
                print(f"Default Account: {default_account}")
                user_data_store[recovered_address] = user_data
                
                
                default_account = recovered_address
                session['default_account'] = recovered_address
                default_account = session.get('default_account', None)
                print(f"Updated Default Account: {default_account}")
                # Ensure the recovered address matches the default account
                if default_account is None or recovered_address.lower() != default_account.lower():
                    flash('Error: Invalid signature or MetaMask account mismatch')
                    print("Error: Invalid signature or MetaMask account mismatch")
                    return redirect(url_for('home'))
                print(f"1. Recovered Address: {recovered_address}")
                print(f"2. Default Account: {default_account}")

            # Assuming you have a form field 'user_data' for user data input
                print(f"user_data: {user_data}")
                if user_data:
                    try:
                        print(3)
                        # Sign the transaction with MetaMask

                        #data = contract.encode_function_input('storeUserData',[user_data])
                        #print(f"data: {data}")
                        
                        #transaction = w3.eth.account.buildTransaction({
                      #  transaction=contract.functions.storeUserData(user_data).buildTransaction({
                        #default_account
                        transaction={
                            'from': default_account,
                            'gas': 2000000,
                            'gasPrice': w3.to_wei('50', 'gwei'),
                            'nonce': w3.eth.get_transaction_count(default_account),
                            'to' : contract_address,
                            'data' : contract.functions.storeUserData(user_data).encodeABI(),
                        }
                        print(f"Transaction: {transaction}")
                        
                        
                        signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=None)
                        transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
                        
                        print(f"3.Signature: {signature}")
                        
                        print('4.User data stored on the blockchain. Transaction Hash: {}'.format(transaction_hash.hex()))
                        flash('User data stored on the blockchain. Transaction Hash: {}'.format(transaction_hash.hex()))
                        
                        print(4)
                    except Exception as e:
                        print(f"Error interacting with the contract: {e}")
                return redirect(url_for('dashboard'))
            else:
                flash('User data cannot be empty.')
        except Exception as e:
            flash(f'Error processing login: {e}')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    try:
        if not w3.is_connected():
            print("Error: Could not connect to Ethereum node.")
            flash("Error: Could not connect to Ethereum node.")
            return redirect(url_for('home'))
        default_account = session.get('default_account', None)
        stored_data = user_data_store.get(default_account, "No data found")

        return render_template('dashboard.html', stored_data=stored_data)
    except Exception as e:
        print(f"Error fetching user data: {e}")
        flash(f"Error fetching user data: {e}")
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)


App/App.py  version = 1.0
from flask import Flask, render_template, redirect, url_for, request, session, flash
from web3 import Web3
from eth_account import Account
import hashlib
import os
from hexbytes import HexBytes
from eth_account.messages import encode_defunct

app = Flask(__name__)
app.secret_key = os.urandom(24)
user_data_store = {}

# Connect to an Ethereum node (replace 'http://localhost:8545' with your node's URL)
w3 = Web3(Web3.HTTPProvider('http://localhost:7545'))

if not w3.is_connected():
    raise ConnectionError("Could not connect to Ethereum node. Make sure it's running and the URL is correct.")

# Load the contract ABI and address (replace with your deployed contract's ABI and address)
contract_abi = [
    {
        "inputs": [],
        "name": "constructor",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "user_data",
                "type": "string"
            }
        ],
        "name": "storeUserData",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getUserData",
        "outputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]  # ABI of UserDataStorage
contract_address = Web3.to_checksum_address('0xDaF7b6CA2F3aC038B440d6f9b6d22F54De510405')
# Set the default account using MetaMask


# Create contract instance
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

def hash_message(message):
    # Convert the message to bytes before hashing
    print("In hash_message fn")
    message_bytes = message.encode('utf-8')
    try:
        # Use hashlib to hash the message
        prefixed_message = b'\x19Ethereum Signed Message:\n' + bytes([len(message_bytes)]) + message_bytes
        hashed_message = Web3.keccak(prefixed_message)
    except Exception as e:
        # Use Web3.keccak to hash the message
        print(f"Error Hashing data: {e}")

    return hashed_message

@app.route('/')
def home():
    return render_template('home.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            default_account = None
            
            print(1)
            # Get the signature from the form
            signature = request.form['signature']
            user_data = request.form['user_data']
            #private_key = request.form['private_key']
            if signature:   
                
                print(2)
                
                print(f"user_data: {user_data}")        
                print(f"Signature: {signature}")
                #print(f"Private_key: {private_key}")
                #print(f"hashed Message:{hash_message(user_data)}") 
                # Recover the address from the signature
                #recovered_address = w3.eth.account.recover(hash_message(user_data), signature)
                
                recovered_address = Account.recover_message(encode_defunct(text=user_data), signature=HexBytes(signature))
                print(f"Recovered Address: {recovered_address}")
                print(f"Default Account: {default_account}")
                user_data_store[recovered_address] = user_data
                
                
                default_account = recovered_address
                session['default_account'] = recovered_address
                default_account = session.get('default_account', None)
                print(f"Updated Default Account: {default_account}")
                # Ensure the recovered address matches the default account
                if default_account is None or recovered_address.lower() != default_account.lower():
                    flash('Error: Invalid signature or MetaMask account mismatch')
                    print("Error: Invalid signature or MetaMask account mismatch")
                    return redirect(url_for('home'))
                print(f"1. Recovered Address: {recovered_address}")
                print(f"2. Default Account: {default_account}")

            # Assuming you have a form field 'user_data' for user data input
                print(f"user_data: {user_data}")
                if user_data:
                    try:
                        print(3)
                        # Sign the transaction with MetaMask

                        data = contract.encode_function_input('storeUserData',[user_data])

                        #transaction = w3.eth.account.buildTransaction({
                      #  transaction=contract.functions.storeUserData(user_data).buildTransaction({
                        transaction={
                            'from': default_account,
                            'gas': 2000000,
                            'gasPrice': w3.to_wei('50', 'gwei'),
                            'nonce': w3.eth.get_transaction_count(default_account),
                            'to' : recovered_address,
                            'data' : data
                        }
                        
                        
                        signed_transaction = w3.eth.account.sign_transaction(transaction, private_key=default_account)
                        transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
                        
                        print(f"3.Signature: {signature}")
                        
                        print('4.User data stored on the blockchain. Transaction Hash: {}'.format(transaction_hash.hex()))
                        flash('User data stored on the blockchain. Transaction Hash: {}'.format(transaction_hash.hex()))
                        
                        print(4)
                    except Exception as e:
                        print(f"Error interacting with the contract: {e}")
                return redirect(url_for('dashboard'))
            else:
                flash('User data cannot be empty.')
        except Exception as e:
            flash(f'Error processing login: {e}')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    try:
        if not w3.is_connected():
            print("Error: Could not connect to Ethereum node.")
            flash("Error: Could not connect to Ethereum node.")
            return redirect(url_for('home'))
        default_account = session.get('default_account', None)
        stored_data = user_data_store.get(default_account, "No data found")

        return render_template('dashboard.html', stored_data=stored_data)
    except Exception as e:
        print(f"Error fetching user data: {e}")
        flash(f"Error fetching user data: {e}")
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)


App/templates/login.html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <!-- Include MetaMask JavaScript library -->
    <script src="https://cdn.jsdelivr.net/gh/ethereum/web3.js/dist/web3.min.js"></script>
    <!-- Include MetaMask JavaScript library -->
<!--<script src="https://unpkg.com/browse/eth-sig-util@3.0.1/dist/index.js"></script>-->

</head>
<body>
    <h2>Login</h2>
    <form method="post" id="loginForm">
        <!-- Add a field for private key (hidden) -->
        <!--  <input type="hidden" name="private_key" id="private_key">       -->
        <!-- Add a field for private key (hidden) -->
        <input type="hidden" name="signature" id="signature">
        <label for="user_data">User Data:</label>
        <input type="text" name="user_data" id="user_data" required>
        <br>
        <!-- Add a button to sign the transaction with MetaMask -->
        <button type="button" onclick="signTransaction()">Sign Transaction with MetaMask</button>
        <br>
        <button type="submit">Login</button>
    </form>
    <script>
        async function signTransaction() {
            try {
                
                const user_data = document.getElementById('user_data').value;
    
                // Use web3 provider from MetaMask
                const provider = window.ethereum;
                await provider.request({method:'eth_requestAccounts'});
                const web3 = new Web3(provider);
    
                // Get the account from MetaMask
                const accounts = await web3.eth.getAccounts();
                const account = accounts[0];
    
                // Create a message to sign
                const message = 'Sign this message to authenticate';
    
                // Sign the message
                const signature = await web3.eth.personal.sign(message, account, '');
    
                // Set the signature in the hidden field
               // document.getElementById('private_key').value = private_key;
                document.getElementById('signature').value = signature;
    
                // Submit the form
                document.getElementById('loginForm').submit();
            } catch (error) {
                console.error('Error signing transaction with MetaMask:', error);
            }
        }
    </script>
</body>
</html>


App/templates/home.html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blockchain Auth - Home</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <div class="container">
        <h1>Welcome to Blockchain Auth</h1>
        <p>This is the home page of your Blockchain authentication application.</p>
        <p>Learn more about your users and their stored data on the Ethereum blockchain.</p>
        <a href="{{ url_for('login') }}">Login</a>
    </div>
</body>
</html>

App/templates/dashboard.html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
</head>
<body>
    <h1>Welcome to Your Dashboard!</h1>

    {% if stored_data %}
        <p>Your stored data: {{ stored_data }}</p>
    {% else %}
        <p>No data available.</p>
    {% endif %}

    <a href="{{ url_for('home') }}">Go back to Home</a>
</body>
</html>


App/UserDataStorage.sol

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
