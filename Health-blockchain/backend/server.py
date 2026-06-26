from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import hashlib
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Generate encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Create storage directory if it doesn't exist
if not os.path.exists("storage"):
    os.makedirs("storage")

def encrypt_data(data):
    """Encrypt data using Fernet symmetric encryption"""
    return cipher_suite.encrypt(data)

def decrypt_data(encrypted_data):
    """Decrypt data using Fernet symmetric encryption"""
    return cipher_suite.decrypt(encrypted_data)

def hash_data(data):
    """Generate SHA-256 hash of data"""
    return hashlib.sha256(data).hexdigest()

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file data
        file_data = file.read()
        
        # Encrypt the file data
        encrypted_data = encrypt_data(file_data)
        
        # Generate hash of encrypted data
        file_hash = hash_data(encrypted_data)
        
        # Store encrypted file
        file_path = f"storage/{file_hash}.enc"
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        return jsonify({
            'message': 'File encrypted & stored',
            'hash': file_hash
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<hash>', methods=['GET'])
def download_file(hash):
    try:
        file_path = f"storage/{hash}.enc"
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Read encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt the data
        decrypted_data = decrypt_data(encrypted_data)
        
        return decrypted_data
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    print("Starting Healthcare Data Server...")
    print("Backend running at http://localhost:3000")
    app.run(host='0.0.0.0', port=3000, debug=True)
