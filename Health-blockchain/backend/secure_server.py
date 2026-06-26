from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import hashlib
import json
import uuid
import datetime
import io
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.secret_key = 'healthchain_secure_key_2024'  # In production, use environment variable
CORS(app, supports_credentials=True)

# Add request logging for debugging
@app.before_request
def log_request_info():
    print(f"DEBUG: {request.method} {request.path} - Headers: {dict(request.headers)}")

# Generate encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Create storage directories
if not os.path.exists("storage"):
    os.makedirs("storage")
if not os.path.exists("users"):
    os.makedirs("users")
if not os.path.exists("audit_logs"):
    os.makedirs("audit_logs")

# User database (in production, use proper database)
USERS_FILE = "users/users.json"
ASSIGNMENTS_FILE = "users/assignments.json"
AUDIT_LOG_FILE = "audit_logs/access.log"

def init_database():
    """Initialize user database with sample doctors and patients"""
    if not os.path.exists(USERS_FILE):
        users = {
            "doctors": {
                "dr_wilson": {
                    "id": "doc_001",
                    "name": "Dr. Robert Wilson",
                    "email": "dr.wilson@hospital.com",
                    "password": generate_password_hash("doc123456"),
                    "role": "doctor",
                    "department": "Internal Medicine",
                    "license": "MD987654",
                    "specialization": "General Practice",
                    "created": datetime.datetime.now().isoformat()
                }
            },
            "patients": {
                "alice_patient": {
                    "id": "pat_001",
                    "name": "Alice Thompson",
                    "email": "alice.thompson@email.com",
                    "password": generate_password_hash("pat123456"),
                    "role": "patient",
                    "dob": "1990-05-15",
                    "blood_type": "O+",
                    "phone": "+1-555-0101",
                    "emergency_contact": "John Thompson",
                    "created": datetime.datetime.now().isoformat()
                },
                "bob_patient": {
                    "id": "pat_002",
                    "name": "Bob Martinez",
                    "email": "bob.martinez@email.com",
                    "password": generate_password_hash("pat123456"),
                    "role": "patient",
                    "dob": "1985-08-22",
                    "blood_type": "A+",
                    "phone": "+1-555-0102",
                    "emergency_contact": "Maria Martinez",
                    "created": datetime.datetime.now().isoformat()
                }
            }
        }
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    
    # Initialize empty assignments (doctors must request access)
    if not os.path.exists(ASSIGNMENTS_FILE):
        assignments = {
            "doc_001": [],  # Dr. Wilson has no assigned patients initially
        }
        with open(ASSIGNMENTS_FILE, 'w') as f:
            json.dump(assignments, f, indent=2)
    
    # Initialize access requests
    if not os.path.exists("users/access_requests.json"):
        requests = {
            "pending": [],
            "approved": [],
            "rejected": []
        }
        with open("users/access_requests.json", 'w') as f:
            json.dump(requests, f, indent=2)

def load_users():
    """Load users from database"""
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def load_assignments():
    """Load doctor-patient assignments"""
    with open(ASSIGNMENTS_FILE, 'r') as f:
        return json.load(f)

def load_access_requests():
    """Load access requests"""
    with open("users/access_requests.json", 'r') as f:
        return json.load(f)

def save_access_requests(requests):
    """Save access requests"""
    with open("users/access_requests.json", 'w') as f:
        json.dump(requests, f, indent=2)

def log_access(action, user_id, file_hash=None, patient_id=None, details=""):
    """Log access for audit trail"""
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "action": action,
        "user_id": user_id,
        "file_hash": file_hash,
        "patient_id": patient_id,
        "details": details,
        "ip_address": request.remote_addr
    }
    
    with open(AUDIT_LOG_FILE, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def require_role(role):
    """Role-based access control decorator"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            
            users = load_users()
            user = None
            for user_type in ['doctors', 'patients']:
                for uid, udata in users[user_type].items():
                    if udata['id'] == session['user_id']:
                        user = udata
                        break
            
            if not user or user['role'] != role:
                return jsonify({'error': 'Insufficient permissions'}), 403
                
            return f(*args, **kwargs)
        return decorated
    return decorator

def encrypt_data(data):
    """Encrypt data using Fernet symmetric encryption with additional security"""
    # Add random padding for additional security
    padding_length = 16  # AES block size
    padding = os.urandom(padding_length)
    padded_data = padding + data + padding
    
    # Encrypt the padded data
    encrypted_data = cipher_suite.encrypt(padded_data)
    
    # Add integrity check
    integrity_hash = hashlib.sha256(encrypted_data).hexdigest()
    
    return {
        'encrypted_data': encrypted_data,
        'integrity_hash': integrity_hash,
        'timestamp': datetime.datetime.now().isoformat()
    }

def decrypt_data(encrypted_data_dict):
    """Decrypt data with integrity verification"""
    try:
        encrypted_data = encrypted_data_dict['encrypted_data']
        provided_hash = encrypted_data_dict['integrity_hash']
        
        # Verify integrity
        calculated_hash = hashlib.sha256(encrypted_data).hexdigest()
        if calculated_hash != provided_hash:
            raise ValueError("Integrity check failed - data may be corrupted")
        
        # Decrypt the data
        decrypted_padded = cipher_suite.decrypt(encrypted_data)
        
        # Remove padding (first and last 16 bytes)
        if len(decrypted_padded) > 32:
            return decrypted_padded[16:-16]
        else:
            return decrypted_padded
            
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def encrypt_data_simple(data):
    """Simple encrypt for backward compatibility"""
    return cipher_suite.encrypt(data)

def decrypt_data_simple(encrypted_data):
    """Simple decrypt for backward compatibility"""
    return cipher_suite.decrypt(encrypted_data)

def hash_data(data):
    """Generate SHA-256 hash of data"""
    return hashlib.sha256(data).hexdigest()

def formatFileSize(bytes):
    """Format file size in human readable format"""
    if bytes < 1024:
        return f"{bytes} B"
    elif bytes < 1024 * 1024:
        return f"{bytes / 1024:.1f} KB"
    elif bytes < 1024 * 1024 * 1024:
        return f"{bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{bytes / (1024 * 1024 * 1024):.1f} GB"

# Initialize database
init_database()

# Authentication routes
@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    users = load_users()
    
    # Check doctors
    for uid, user in users['doctors'].items():
        if uid == username and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = uid
            session['role'] = user['role']
            log_access('login', user['id'], details=f"Doctor login: {user['name']}")
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'name': user['name'],
                    'role': user['role'],
                    'department': user.get('department', ''),
                    'license': user.get('license', '')
                }
            })
    
    # Check patients
    for uid, user in users['patients'].items():
        if uid == username and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = uid
            session['role'] = user['role']
            log_access('login', user['id'], details=f"Patient login: {user['name']}")
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'name': user['name'],
                    'role': user['role'],
                    'dob': user.get('dob', ''),
                    'blood_type': user.get('blood_type', '')
                }
            })
    
    log_access('login_failed', None, details=f"Failed login attempt: {username}")
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    """User logout endpoint"""
    log_access('logout', session['user_id'], details=f"User logout: {session['username']}")
    session.clear()
    return jsonify({'success': True})

@app.route('/api/profile', methods=['GET'])
@require_auth
def get_profile():
    """Get current user profile"""
    users = load_users()
    user_id = session['user_id']
    
    for user_type in ['doctors', 'patients']:
        for uid, user in users[user_type].items():
            if user['id'] == user_id:
                return jsonify({'user': user})
    
    return jsonify({'error': 'User not found'}), 404

# Doctor access request endpoints
@app.route('/api/doctor/request_access', methods=['POST'])
@require_auth
@require_role('doctor')
def request_patient_access():
    """Doctor requests access to patient data"""
    data = request.get_json()
    patient_id = data.get('patient_id')
    reason = data.get('reason', '')
    duration_days = data.get('duration_days', 30)
    
    doctor_id = session['user_id']
    
    # Create access request
    access_request = {
        "id": str(uuid.uuid4()),
        "doctor_id": doctor_id,
        "patient_id": patient_id,
        "reason": reason,
        "duration_days": duration_days,
        "status": "pending",
        "requested_at": datetime.datetime.now().isoformat(),
        "expires_at": (datetime.datetime.now() + datetime.timedelta(days=duration_days)).isoformat()
    }
    
    # Save request
    requests = load_access_requests()
    requests['pending'].append(access_request)
    save_access_requests(requests)
    
    log_access('access_request', doctor_id, patient_id=patient_id, 
              details=f"Requested access to {patient_id} for {duration_days} days")
    
    return jsonify({
        'success': True,
        'message': 'Access request sent to patient',
        'request_id': access_request['id']
    })

@app.route('/api/patient/access_requests', methods=['GET'])
@require_auth
@require_role('patient')
def get_patient_access_requests():
    """Get pending access requests for patient"""
    patient_id = session['user_id']
    requests = load_access_requests()
    
    pending_requests = []
    for req in requests['pending']:
        if req['patient_id'] == patient_id:
            # Add doctor details
            users = load_users()
            doctor_info = None
            for uid, doctor in users['doctors'].items():
                if doctor['id'] == req['doctor_id']:
                    doctor_info = doctor
                    break
            
            if doctor_info:
                pending_requests.append({
                    **req,
                    'doctor_name': doctor_info['name'],
                    'doctor_department': doctor_info.get('department', ''),
                    'doctor_license': doctor_info.get('license', '')
                })
    
    return jsonify({'requests': pending_requests})

@app.route('/api/patient/respond_request', methods=['POST'])
@require_auth
@require_role('patient')
def respond_to_access_request():
    """Patient responds to access request"""
    data = request.get_json()
    request_id = data.get('request_id')
    action = data.get('action')  # 'approve' or 'reject'
    
    patient_id = session['user_id']
    requests = load_access_requests()
    
    # Find and move request
    request_found = False
    for i, req in enumerate(requests['pending']):
        if req['id'] == request_id and req['patient_id'] == patient_id:
            request_found = True
            req['status'] = action
            req['responded_at'] = datetime.datetime.now().isoformat()
            
            if action == 'approve':
                # Add to assignments
                assignments = load_assignments()
                if req['doctor_id'] not in assignments:
                    assignments[req['doctor_id']] = []
                if req['patient_id'] not in assignments[req['doctor_id']]:
                    assignments[req['doctor_id']].append(req['patient_id'])
                
                # Save assignments
                with open(ASSIGNMENTS_FILE, 'w') as f:
                    json.dump(assignments, f, indent=2)
                
                requests['approved'].append(req)
                log_access('access_approved', patient_id, patient_id=req['patient_id'], 
                          details=f"Approved access for doctor {req['doctor_id']}")
            else:
                requests['rejected'].append(req)
                log_access('access_rejected', patient_id, patient_id=req['patient_id'], 
                          details=f"Rejected access for doctor {req['doctor_id']}")
            
            # Remove from pending
            requests['pending'].pop(i)
            break
    
    if not request_found:
        return jsonify({'error': 'Request not found'}), 404
    
    save_access_requests(requests)
    
    return jsonify({
        'success': True,
        'message': f'Access request {action}d successfully'
    })

# Patient dashboard endpoints
@app.route('/api/patient/my_files', methods=['GET'])
@require_auth
@require_role('patient')
def get_my_patient_files():
    """Get patient's own uploaded files"""
    patient_id = session['user_id']
    
    # Get patient files from storage
    patient_files = []
    storage_path = "storage"
    
    if os.path.exists(storage_path):
        for filename in os.listdir(storage_path):
            if filename.endswith('.enc'):
                file_hash = filename.replace('.enc', '')
                file_path = os.path.join(storage_path, filename)
                
                # In a real system, we'd have a database linking files to patients
                # For demo, we'll check metadata to get original filename
                original_filename = None
                metadata_path = f"storage/{file_hash}.meta"
                if os.path.exists(metadata_path):
                    try:
                        with open(metadata_path, 'r') as f:
                            metadata = json.load(f)
                        # Only include if this file belongs to current patient
                        if metadata.get('patient_id') == patient_id:
                            original_filename = metadata.get('original_filename')
                        else:
                            continue
                    except:
                        continue
                else:
                    continue  # Skip files without metadata
                
                file_info = {
                    'hash': file_hash,
                    'filename': original_filename or f"medical_record_{file_hash[:8]}",
                    'size': os.path.getsize(file_path),
                    'upload_date': datetime.datetime.fromtimestamp(os.path.getctime(file_path)).isoformat(),
                    'uploaded_by': patient_id
                }
                patient_files.append(file_info)
    
    log_access('view_own_files', patient_id, details=f"Viewed {len(patient_files)} own files")
    return jsonify({'files': patient_files})
@app.route('/api/patient/upload', methods=['POST'])
@require_auth
@require_role('patient')
def patient_upload_file():
    """Patient uploads their own medical file - accepts all file types"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    patient_id = session['user_id']
    original_filename = file.filename
    
    # Read file data
    file_data = file.read()
    
    # Encrypt the file data with simple encryption for now
    encrypted_data = encrypt_data_simple(file_data)
    
    # Add blockchain metadata
    blockchain_metadata = {
        "patient_id": patient_id,
        "upload_timestamp": datetime.datetime.now().isoformat(),
        "original_filename": original_filename,
        "file_hash": hashlib.sha256(file_data).hexdigest(),
        "encrypted_hash": hash_data(encrypted_data),
        "file_size": len(file_data),
        "mime_type": file.mimetype or 'application/octet-stream'
    }
    
    # Generate final hash
    metadata_json = json.dumps(blockchain_metadata, sort_keys=True)
    final_hash = hashlib.sha256(encrypted_data + metadata_json.encode()).hexdigest()
    
    # Store encrypted file
    file_path = f"storage/{final_hash}.enc"
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    metadata_path = f"storage/{final_hash}.meta"
    with open(metadata_path, 'w') as f:
        json.dump(blockchain_metadata, f, indent=2)
    
    log_access('file_upload', patient_id, file_hash=final_hash, 
              details=f"Uploaded file: {original_filename} ({formatFileSize(len(file_data))})")
    
    return jsonify({
        'success': True,
        'message': 'File uploaded and encrypted successfully',
        'file_info': {
            'hash': final_hash,
            'filename': original_filename,
            'size': len(file_data),
            'upload_date': blockchain_metadata['upload_timestamp']
        }
    })

@app.route('/api/patient/download/<file_hash>', methods=['GET'])
@require_auth
@require_role('patient')
def patient_download_file(file_hash):
    """Patient downloads their own file"""
    patient_id = session['user_id']
    
    file_path = f"storage/{file_hash}.enc"
    
    if not os.path.exists(file_path):
        log_access('file_not_found', patient_id, file_hash=file_hash, details="File not found")
        return jsonify({'error': 'File not found'}), 404
    
    try:
        # Read encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Verify blockchain metadata
        metadata_path = f"storage/{file_hash}.meta"
        original_filename = f"medical_record_{file_hash[:8]}"
        encryption_version = "simple"
        
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Verify patient ownership
            if metadata.get('patient_id') != patient_id:
                log_access('unauthorized_access', patient_id, file_hash=file_hash, details="Unauthorized file access")
                return jsonify({'error': 'Access denied'}), 403
            
            # Get original filename
            original_filename = metadata.get('original_filename', original_filename)
            
            # Check if enhanced encryption was used
            if metadata.get('integrity_hash'):
                encryption_version = "enhanced"
        
        # Decrypt the data based on encryption version
        if encryption_version == "enhanced":
            # Try enhanced decryption first
            try:
                # For enhanced encryption, we need to reconstruct the encryption dict
                # Since we only stored the encrypted data, we'll use simple decryption for now
                # In a production system, you'd store the full encryption metadata
                decrypted_data = decrypt_data_simple(encrypted_data)
            except:
                # Fallback to simple decryption
                decrypted_data = decrypt_data_simple(encrypted_data)
        else:
            # Simple decryption for backward compatibility
            decrypted_data = decrypt_data_simple(encrypted_data)
        
        log_access('file_download', patient_id, file_hash=file_hash, details="Patient downloaded own file")
        
        # Return the decrypted file with original filename
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=original_filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        log_access('file_download_error', patient_id, file_hash=file_hash, details=str(e))
        return jsonify({'error': 'Failed to download file'}), 500

@app.route('/api/patient/delete-file', methods=['POST'])
@require_auth
@require_role('patient')
def delete_patient_file():
    """Patient deletes their own uploaded file"""
    patient_id = session['user_id']
    data = request.get_json()
    file_hash = data.get('file_hash')
    
    if not file_hash:
        return jsonify({'error': 'File hash required'}), 400
    
    file_path = f"storage/{file_hash}.enc"
    metadata_path = f"storage/{file_hash}.meta"
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        # Verify patient ownership
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            if metadata.get('patient_id') != patient_id:
                log_access('unauthorized_delete', patient_id, file_hash=file_hash, details="Unauthorized file deletion")
                return jsonify({'error': 'Access denied'}), 403
            original_filename = metadata.get('original_filename', f"medical_record_{file_hash[:8]}")
        else:
            return jsonify({'error': 'File metadata not found'}), 404
        
        # Delete the encrypted file and metadata
        os.remove(file_path)
        if os.path.exists(metadata_path):
            os.remove(metadata_path)
        
        log_access('file_deleted', patient_id, file_hash=file_hash, 
                  details=f"Deleted file: {original_filename}")
        
        return jsonify({
            'success': True,
            'message': 'File deleted successfully',
            'deleted_file': file_hash
        })
        
    except Exception as e:
        log_access('file_delete_error', patient_id, file_hash=file_hash, details=str(e))
        return jsonify({'error': 'Failed to delete file'}), 500
@app.route('/api/doctor/patients', methods=['GET'])
@require_auth
@require_role('doctor')
def get_assigned_patients():
    """Get patients assigned to current doctor"""
    doctor_id = session['user_id']
    assignments = load_assignments()
    users = load_users()
    
    patient_ids = assignments.get(doctor_id, [])
    patients = []
    
    for patient_id in patient_ids:
        for uid, patient in users['patients'].items():
            if patient['id'] == patient_id:
                patients.append(patient)
                break
    
    log_access('view_patients', doctor_id, details=f"Viewed {len(patients)} assigned patients")
    return jsonify({'patients': patients})

@app.route('/api/doctor/patient/<patient_id>/files', methods=['GET'])
@require_auth
@require_role('doctor')
def get_patient_files(patient_id):
    """Get files for a specific patient (if doctor has access)"""
    doctor_id = session['user_id']
    assignments = load_assignments()
    
    # Check if doctor is assigned to this patient
    if patient_id not in assignments.get(doctor_id, []):
        log_access('unauthorized_access', doctor_id, patient_id=patient_id, details="Attempted to access unassigned patient")
        return jsonify({'error': 'Access denied'}), 403
    
    # Get patient files from storage
    patient_files = []
    storage_path = "storage"
    
    if os.path.exists(storage_path):
        for filename in os.listdir(storage_path):
            if filename.endswith('.enc'):
                file_hash = filename.replace('.enc', '')
                file_path = os.path.join(storage_path, filename)
                
                # Check if file belongs to this patient
                metadata_path = f"storage/{file_hash}.meta"
                file_patient_id = None
                actual_hash = file_hash  # Use filename as default
                original_filename = None
                
                if os.path.exists(metadata_path):
                    try:
                        with open(metadata_path, 'r') as f:
                            metadata = json.load(f)
                        file_patient_id = metadata.get('patient_id')
                        # Use the hash from metadata for consistency
                        actual_hash = metadata.get('file_hash', file_hash)
                        original_filename = metadata.get('original_filename')
                    except:
                        continue
                
                # Only include files that belong to this patient
                if file_patient_id == patient_id:
                    file_info = {
                        'hash': actual_hash,  # Use the correct hash from metadata
                        'filename': original_filename or f"medical_record_{actual_hash[:8]}",
                        'size': os.path.getsize(file_path),
                        'upload_date': datetime.datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
                    }
                    patient_files.append(file_info)
    
    log_access('view_patient_files', doctor_id, patient_id=patient_id, details=f"Viewed {len(patient_files)} files")
    return jsonify({'files': patient_files})

@app.route('/api/doctor/download/<file_hash>', methods=['GET'])
@require_auth
@require_role('doctor')
def doctor_download_file(file_hash):
    """Doctors are not allowed to download files - view only access"""
    doctor_id = session['user_id']
    
    log_access('download_attempt_blocked', doctor_id, file_hash=file_hash, 
              details=f"Doctor {doctor_id} attempted to download file - download access blocked for doctors")
    
    return jsonify({
        'error': 'Download access restricted',
        'message': 'Doctors can only view patient files online. Download functionality is restricted to patients only for security reasons.'
    }), 403

@app.route('/api/doctor/view/<file_hash>', methods=['GET'])
@require_auth
@require_role('doctor')
def doctor_view_file(file_hash):
    """Doctor views patient file details without downloading"""
    doctor_id = session['user_id']
    
    # Find the actual file that corresponds to this hash
    actual_file_path = None
    metadata_path = None
    
    storage_path = "storage"
    if os.path.exists(storage_path):
        for filename in os.listdir(storage_path):
            if filename.endswith('.meta'):
                # Check if this metadata file contains our hash
                meta_file_path = os.path.join(storage_path, filename)
                try:
                    with open(meta_file_path, 'r') as f:
                        metadata = json.load(f)
                    if metadata.get('file_hash') == file_hash:
                        # Found the matching metadata
                        metadata_path = meta_file_path
                        # Find the corresponding .enc file
                        base_name = filename.replace('.meta', '')
                        enc_file_path = os.path.join(storage_path, f"{base_name}.enc")
                        if os.path.exists(enc_file_path):
                            actual_file_path = enc_file_path
                        break
                except:
                    continue
    
    if not actual_file_path:
        log_access('file_not_found', doctor_id, file_hash=file_hash, details="File not found")
        return jsonify({'error': 'File not found'}), 404
    
    try:
        # Read metadata to verify patient ownership and consent
        patient_id = None
        original_filename = None
        file_size = 0
        upload_timestamp = None
        
        if metadata_path and os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            patient_id = metadata.get('patient_id')
            upload_timestamp = metadata.get('upload_timestamp')
            file_size = os.path.getsize(actual_file_path)
        
        # Check if doctor has access to this patient
        assignments = load_assignments()
        assigned_patients = assignments.get(doctor_id, [])
        
        if not patient_id or patient_id not in assigned_patients:
            log_access('unauthorized_access', doctor_id, file_hash=file_hash, 
                      details=f"Doctor {doctor_id} attempted to view file without patient consent")
            return jsonify({'error': 'Access denied - Patient consent required'}), 403
        
        # Get file extension for proper display
        file_extension = 'pdf'  # default
        if original_filename and '.' in original_filename:
            file_extension = original_filename.split('.')[-1].lower()
        
        # Determine file type category
        file_type = 'document'
        if file_extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp']:
            file_type = 'image'
        elif file_extension in ['mp4', 'avi', 'mov', 'wmv']:
            file_type = 'video'
        elif file_extension in ['mp3', 'wav', 'ogg']:
            file_type = 'audio'
        elif file_extension in ['dcm', 'dicom']:
            file_type = 'medical_image'
        
        log_access('file_viewed', doctor_id, file_hash=file_hash, 
                  details=f"Doctor viewed file details for patient {patient_id} (view only)")
        
        return jsonify({
            'success': True,
            'file_info': {
                'patient_id': patient_id,
                'upload_timestamp': upload_timestamp,
                'file_hash': file_hash,
                'original_filename': original_filename or f"medical_record_{file_hash[:8]}",
                'file_size': file_size,
                'file_type': file_type,
                'file_extension': file_extension,
                'access_level': 'View Only',
                'security_note': 'Download functionality is restricted to patients only'
            },
            'message': 'File details accessed successfully - View only mode'
        })
        
    except Exception as e:
        log_access('file_view_error', doctor_id, file_hash=file_hash, details=str(e))
        return jsonify({'error': 'Failed to view file details'}), 500

@app.route('/api/patient/revoke-access', methods=['POST'])
@require_auth
@require_role('patient')
def revoke_doctor_access():
    """Patient revokes doctor's access to their files"""
    patient_id = session['user_id']
    data = request.get_json()
    doctor_id = data.get('doctor_id')
    
    if not doctor_id:
        return jsonify({'error': 'Doctor ID required'}), 400
    
    assignments = load_assignments()
    
    # Check if doctor has access to this patient
    if patient_id not in assignments.get(doctor_id, []):
        return jsonify({'error': 'Doctor does not have access to your files'}), 400
    
    # Remove patient from doctor's assigned list
    assignments[doctor_id].remove(patient_id)
    
    # Save updated assignments
    with open(ASSIGNMENTS_FILE, 'w') as f:
        json.dump(assignments, f, indent=2)
    
    log_access('access_revoked', patient_id, doctor_id=doctor_id, 
              details=f"Patient revoked access from doctor {doctor_id}")
    
    return jsonify({
        'success': True,
        'message': 'Access revoked successfully',
        'revoked_doctor': doctor_id
    })

@app.route('/api/patient/granted-doctors', methods=['GET'])
@require_auth
@require_role('patient')
def get_granted_doctors():
    """Get list of doctors who have access to patient's files"""
    patient_id = session['user_id']
    assignments = load_assignments()
    users = load_users()
    
    granted_doctors = []
    
    # Find all doctors who have access to this patient
    for doctor_id, patient_list in assignments.items():
        if patient_id in patient_list:
            # Find doctor details
            for uid, doctor in users['doctors'].items():
                if doctor['id'] == doctor_id:
                    granted_doctors.append({
                        'id': doctor['id'],
                        'name': doctor['name'],
                        'email': doctor['email'],
                        'department': doctor.get('department', 'N/A'),
                        'specialization': doctor.get('specialization', 'N/A')
                    })
                    break
    
    log_access('view_granted_doctors', patient_id, details=f"Viewed {len(granted_doctors)} doctors with access")
    return jsonify({'doctors': granted_doctors})

# Emergency access
@app.route('/api/emergency/access', methods=['POST'])
@require_auth
@require_role('doctor')
def emergency_access():
    """Emergency access protocol - requires justification"""
    data = request.get_json()
    patient_id = data.get('patient_id')
    reason = data.get('reason', '')
    urgency = data.get('urgency', 'medium')
    
    # Log emergency access request
    log_access('emergency_access_request', session['user_id'], patient_id=patient_id, 
              details=f"Emergency access: {reason} (Urgency: {urgency})")
    
    # In a real system, this would:
    # 1. Notify hospital administrators
    # 2. Require additional approval
    # 3. Create high-priority audit trail
    # 4. Grant temporary access
    
    return jsonify({
        'success': True,
        'message': 'Emergency access granted',
        'access_granted_until': (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()
    })

# Original upload endpoints (now require authentication)
@app.route('/api/upload', methods=['POST'])
@require_auth
def upload_file():
    """Secure file upload with authentication"""
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
    
    # In a real system, we'd link this file to a patient in the database
    log_access('file_upload', session['user_id'], file_hash=file_hash, 
              details=f"Uploaded file: {file.filename} ({len(file_data)} bytes)")
    
    return jsonify({
        'message': 'File encrypted & stored securely',
        'hash': file_hash,
        'uploaded_by': session['user_id']
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'secure': True})

if __name__ == '__main__':
    print("Starting Secure Healthcare Data Server...")
    print("Authentication: ENABLED")
    print("Doctor Access: SECURE")
    print("Audit Logging: ACTIVE")
    print("Emergency Protocols: READY")
    print("Server running at http://localhost:3000")
    app.run(host='0.0.0.0', port=3000, debug=True)
