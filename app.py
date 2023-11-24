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
                        '''
                        transaction={
                            'from': default_account,
                            'gas': 2000000,
                            'gasPrice': w3.to_wei('50', 'gwei'),
                            'nonce': w3.eth.get_transaction_count(default_account),
                            'to' : contract_address,
                            'data' : contract.functions.storeUserData(user_data).encodeABI(),
                        } '''
                        transaction = w3.eth.buildTransaction({
                        'from': default_account,
                        'gas': 2000000,
                        'gasPrice': w3.to_wei('50', 'gwei'),
                        'nonce': w3.eth.get_transaction_count(default_account),
                        'to': contract_address,
                        'data': contract.functions.storeUserData(user_data).buildTransaction({'gas': 2000000})['data'],
                        })
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



##Backup-1
##Uses HArdcoded Private Key from the local ethereum network
'''
from flask import Flask, render_template, redirect, url_for, request, session, flash
from web3 import Web3
from eth_account import Account
import os
from eth_account.messages import defunct_hash_message

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Connect to an Ethereum node (replace 'http://localhost:8545' with your node's URL)
w3 = Web3(Web3.HTTPProvider('http://localhost:7545'))

if not w3.is_connected():
    raise ConnectionError("Could not connect to Ethereum node. Make sure it's running and the URL is correct.")

private_key = "0x62e1a0550ac57ec952bc42d6741da05ddb340b8767fee85af15b48e6a9b50c4e"

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
contract_address = '0xd9145CCE52D386f254917e481eB44e9943F39138'

# Set the default account using the private key
account = Account.from_key(private_key)
w3.eth.default_account = account.address

# Create contract instance
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Generate a private key on the client side using MetaMask
        # Note: This private key should never be stored on the server
        private_key = request.form['private_key']
        print(f"private key: {private_key}")

        if private_key:
            # Set the default account using the provided private key
            account = Account.from_key(private_key)
            w3.eth.default_account = account.address

            # Assuming you have a form field 'user_data' for user data input
            user_data = request.form['user_data']
            print(f"User data: {user_data}")
            if user_data:
                # Sign the transaction with MetaMask private key
                signature = request.form['signature']
                message_hash = defunct_hash_message(text='Sign this message to authenticate')
                signed_transaction = contract.functions.storeUserData(user_data).build_transaction({
                    'from': w3.eth.default_account,
                    'gas': 2000000,
                    'gasPrice': w3.to_wei('50', 'gwei'),
                    'nonce': w3.eth.get_transaction_count(w3.eth.default_account),
                })

                # Attach the MetaMask signature to the transaction
                signed_transaction['r'] = int(signature[2:66], 16)
                signed_transaction['s'] = int(signature[66:130], 16)
                signed_transaction['v'] = int(signature[130:], 16)

                transaction_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)

                print('User data stored on the blockchain. Transaction Hash: {}'.format(transaction_hash.hex()))
                return redirect(url_for('dashboard'))
            else:
                print('User data cannot be empty.')

    return render_template('login.html')

@app.route('/dashboard',methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        # Handle any POST requests (if needed)
        pass

    try:
        stored_data = contract.functions.getUserData().call()
        return render_template('dashboard.html', stored_data=stored_data)
    except Exception as e:
        print(f"Error fetching user data: {e}")
        flash(f"Error fetching user data: {e}")
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)

'''

##  Backup-2
##  USes SQLAlchemy Database
'''
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from eth_account import Account
from passlib.hash import pbkdf2_sha256
import os
import binascii
from web3 import Web3

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)

db = SQLAlchemy(app)

class User(db.Model):
    username = db.column(db.Integer,primary_key=True)
    id = db.Column(db.Integer, primary_key=True)
    private_key = db.Column(db.String(66), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

def hash_password(password):
    return pbkdf2_sha256.hash(password)

def verify_password(password, hashed_password):
    return pbkdf2_sha256.verify(password, hashed_password)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        private_key_hex = request.form['private_key'].strip()
        private_key_hex = private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex
        private_key = binascii.unhexlify(private_key_hex)
        user = User.query.filter_by(private_key=private_key).first()

        if user:
            session['address'] = user.address
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid private key. Please register.')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        private_key = request.form['private_key']
        print(f"Private Key: {private_key}, Length: {len(private_key)}")
        password = request.form['password']
        print(f"Password: {password}")

        if private_key and len(private_key)==64 and password:
            # Use eth_account's privateKeyToAccount to create an Account instance
            print(f"Private Key: {private_key}, Length: {len(private_key)}")
            username = request.form['username']
            account = Account.from_key(private_key)
            address = account.address
            hashed_password = hash_password(password)

            # Save user to the database
            new_user = User(username=username, private_key=private_key, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful. You can now login.')
            return redirect(url_for('login'))

        flash('Both private key and password are required for registration.')

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'address' in session:
        return f"Welcome, {session['private_key']}!"
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        print("Intializing database")
        print("Creating the tables")
        db.create_all()
    print("Starting the application")
    app.run(debug=True)

'''