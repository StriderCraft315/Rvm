#!/usr/bin/env python3
"""
Rvm - VPS Control Panel
Optimized with separate HTML files and KVM focus
"""

import os
import sys
import json
import psutil
import subprocess
import secrets
import base64
import hashlib
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import contextmanager

app = Flask(__name__, template_folder='sites')
app.secret_key = 'rvm_optimized_secure_2024'
app.config['DATABASE'] = 'rvm.db'

# Database setup
def init_db():
    """Initialize the SQLite database"""
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                expiry_date DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        db.execute('''
            CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT NOT NULL
            )
        ''')
        
        db.execute('''
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                expiry_date DATETIME NOT NULL,
                license_key TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert default admin user if not exists
        cursor = db.execute('SELECT * FROM users WHERE username = ?', ('admin',))
        if not cursor.fetchone():
            db.execute(
                'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                ('admin', generate_password_hash('admin123'), True)
            )
        
        # Insert default config
        default_config = {
            'maintenance_mode': 'false',
            'ssh_welcome': 'Welcome to Rvm VPS Control Panel!',
            'web_welcome': 'Rvm Control Panel',
            'ssh_port': '22',
            'background': '#1a1a1a',
            'footer': 'Rvm VPS Control Panel v1.0',
            'allow_registration': 'true',
            'max_users': '10'
        }
        
        for key, value in default_config.items():
            db.execute(
                'INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)',
                (key, value)
            )
        
        db.commit()

@contextmanager
def get_db():
    """Get database connection with context manager"""
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()

def query_db(query, args=(), one=False):
    """Execute a query and return results"""
    with get_db() as db:
        cursor = db.execute(query, args)
        result = cursor.fetchall()
        return (result[0] if result else None) if one else result

def execute_db(query, args=()):
    """Execute a write query"""
    with get_db() as db:
        db.execute(query, args)
        db.commit()

def get_config(key, default=None):
    """Get configuration value"""
    result = query_db('SELECT value FROM config WHERE key = ?', [key], one=True)
    return result[0] if result else default

def set_config(key, value):
    """Set configuration value"""
    execute_db('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', [key, str(value)])

def get_all_config():
    """Get all configuration as dict"""
    results = query_db('SELECT key, value FROM config')
    return {row['key']: row['value'] for row in results}

# Helper functions
def run_command(cmd):
    """Execute shell command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_system_info():
    """Get system information"""
    try:
        return {
            "hostname": run_command("hostname")["output"].strip(),
            "os": run_command("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'").get("output", "").strip(),
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "uptime": run_command("uptime -p").get("output", "").replace("up ", "").strip(),
            "load_avg": os.getloadavg(),
            "processes": len(psutil.pids())
        }
    except:
        return {"error": "Unable to get system info"}

def get_services():
    """Get system services"""
    result = run_command("systemctl list-units --type=service --state=running --no-legend | head -20")
    services = []
    if result["success"]:
        for line in result["output"].split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    services.append({
                        "name": parts[0],
                        "status": "active"
                    })
    return services

def get_ufw_status():
    """Get UFW firewall status"""
    result = run_command("ufw status verbose")
    ports = []
    if result["success"]:
        for line in result["output"].split('\n'):
            if "ALLOW" in line and "anywhere" in line:
                import re
                port_match = re.search(r'(\d+)(\/\w+)?', line)
                if port_match:
                    ports.append(port_match.group(1))
    
    status = "active" if "Status: active" in result["output"] else "inactive"
    return {"status": status, "ports": ports}

def get_kvm_vms():
    """Get KVM virtual machines"""
    try:
        result = run_command("virsh list --all")
        vms = []
        for line in result["output"].split('\n')[2:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    vms.append({
                        "id": parts[0],
                        "name": parts[1],
                        "status": parts[2] if parts[2] != "-" else "shut off"
                    })
        return vms
    except:
        return []

def get_os_images():
    """Get available OS images for KVM"""
    images_dir = "/var/lib/libvirt/images"
    images = []
    if os.path.exists(images_dir):
        for file in os.listdir(images_dir):
            if file.endswith(('.qcow2', '.img')):
                file_path = os.path.join(images_dir, file)
                size = os.path.getsize(file_path)
                images.append({
                    "name": file,
                    "size": size,
                    "path": file_path
                })
    return images

def get_file_list(path="/"):
    """Get file list for file manager"""
    try:
        files = []
        for item in os.listdir(path):
            if item.startswith('.'):
                continue
            item_path = os.path.join(path, item)
            try:
                stat = os.stat(item_path)
                files.append({
                    "name": item,
                    "size": stat.st_size,
                    "is_dir": os.path.isdir(item_path),
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "path": item_path
                })
            except:
                continue
        return sorted(files, key=lambda x: (not x['is_dir'], x['name'].lower()))
    except:
        return []

def generate_tmate():
    """Generate tmate session"""
    result = run_command("tmate -S /tmp/tmate.sock new-session -d && sleep 2 && tmate -S /tmp/tmate.sock display -p '#{tmate_ssh}'")
    if result["success"]:
        web_result = run_command("tmate -S /tmp/tmate.sock display -p '#{tmate_web}'")
        return {
            "ssh": result["output"].strip(),
            "web": web_result["output"].strip() if web_result["success"] else "N/A",
            "status": "active"
        }
    return {"error": "Failed to generate tmate session"}

# Authentication decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('Admin access required!', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# License System
class LicenseSystem:
    def __init__(self):
        self.secret = "rvm_domain_secret_2024"
    
    def generate_license(self, domain, expiry_days):
        """Generate license key for domain and expiry only"""
        expiry_date = datetime.now() + timedelta(days=expiry_days)
        license_data = f"{domain}:{expiry_date.isoformat()}"
        signature = hashlib.sha256(f"{license_data}{self.secret}".encode()).hexdigest()
        license_key = base64.b64encode(f"{license_data}:{signature}".encode()).decode()
        
        # Store in database
        execute_db(
            'INSERT INTO licenses (domain, expiry_date, license_key) VALUES (?, ?, ?)',
            [domain, expiry_date.isoformat(), license_key]
        )
        
        return license_key
    
    def validate_license(self, license_key, current_domain):
        """Validate license key for current domain"""
        try:
            decoded = base64.b64decode(license_key).decode()
            parts = decoded.split(":")
            if len(parts) < 3:
                return False, "Invalid license format"
            
            domain = parts[0]
            expiry_str = parts[1]
            signature = parts[-1]
            
            # Check domain
            if domain != current_domain:
                return False, "Domain mismatch"
            
            # Check expiry
            expiry_date = datetime.fromisoformat(expiry_str)
            if datetime.now() > expiry_date:
                return False, "License expired"
            
            # Verify signature
            license_data = ":".join(parts[:-1])
            expected_signature = hashlib.sha256(f"{license_data}{self.secret}".encode()).hexdigest()
            
            if signature != expected_signature:
                return False, "Invalid license signature"
            
            # Check if license exists in database
            result = query_db('SELECT * FROM licenses WHERE license_key = ?', [license_key], one=True)
            if not result:
                return False, "License not found in database"
            
            return True, "Valid license"
        except Exception as e:
            return False, f"License validation error: {str(e)}"

# Routes
@app.route('/')
@login_required
def index():
    if get_config('maintenance_mode') == 'true' and not session.get('is_admin'):
        return render_template('maintenance.html')
    
    config = get_all_config()
    system_info = get_system_info()
    services = get_services()
    firewall = get_ufw_status()
    kvm_vms = get_kvm_vms()
    
    return render_template('dashboard.html',
                         config=config,
                         system_info=system_info,
                         services=services,
                         firewall=firewall,
                         kvm_vms=kvm_vms,
                         username=session['username'],
                         is_admin=session.get('is_admin', False))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_config('maintenance_mode') == 'true':
        return render_template('maintenance.html')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        
        if user and check_password_hash(user['password_hash'], password):
            # Check if user is expired
            if user['expiry_date'] and datetime.fromisoformat(user['expiry_date']) < datetime.now():
                flash('Account has expired!', 'error')
                return render_template('login.html', allow_registration=get_config('allow_registration'))
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html', allow_registration=get_config('allow_registration'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if get_config('maintenance_mode') == 'true':
        return render_template('maintenance.html')
    
    if get_config('allow_registration') != 'true':
        flash('Registration is disabled!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username exists
        existing_user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        if existing_user:
            flash('Username already exists!', 'error')
            return render_template('register.html')
        
        # Check user limit
        user_count = query_db('SELECT COUNT(*) as count FROM users')[0]['count']
        max_users = int(get_config('max_users', 10))
        if user_count >= max_users:
            flash('Maximum user limit reached!', 'error')
            return render_template('register.html')
        
        # Create user
        execute_db(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
            [username, generate_password_hash(password), False]
        )
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# File Manager
@app.route('/files')
@login_required
def file_manager():
    path = request.args.get('path', '/')
    files = get_file_list(path)
    parent_path = os.path.dirname(path) if path != '/' else '/'
    return render_template('files.html', 
                         files=files, 
                         current_path=path,
                         parent_path=parent_path,
                         username=session['username'])

@app.route('/api/files/upload', methods=['POST'])
@login_required
def api_file_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['file']
    path = request.form.get('path', '/')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    file_path = os.path.join(path, file.filename)
    file.save(file_path)
    
    return jsonify({'status': 'success', 'message': f'File {file.filename} uploaded'})

@app.route('/api/files/create-folder', methods=['POST'])
@login_required
def api_create_folder():
    name = request.form.get('name')
    path = request.form.get('path', '/')
    
    if name:
        folder_path = os.path.join(path, name)
        os.makedirs(folder_path, exist_ok=True)
        return jsonify({'status': 'success', 'message': 'Folder created'})
    
    return jsonify({'error': 'No folder name provided'})

@app.route('/api/files/delete', methods=['POST'])
@login_required
def api_delete_file():
    path = request.form.get('path')
    
    if path and os.path.exists(path):
        if os.path.isdir(path):
            import shutil
            shutil.rmtree(path)
        else:
            os.remove(path)
        return jsonify({'status': 'success', 'message': 'Deleted successfully'})
    
    return jsonify({'error': 'File not found'})

@app.route('/api/files/download')
@login_required
def api_download_file():
    path = request.args.get('path')
    if path and os.path.exists(path) and not os.path.isdir(path):
        return send_file(path, as_attachment=True)
    return jsonify({'error': 'File not found'})

# Services Manager
@app.route('/services')
@login_required
def services_manager():
    services = get_services()
    return render_template('services.html', services=services, username=session['username'])

@app.route('/api/services/<action>/<service_name>', methods=['POST'])
@login_required
def api_service_control(action, service_name):
    if action in ['start', 'stop', 'restart']:
        result = run_command(f'systemctl {action} {service_name}')
        return jsonify(result)
    return jsonify({'error': 'Invalid action'})

# Firewall Manager
@app.route('/firewall')
@login_required
def firewall_manager():
    firewall = get_ufw_status()
    return render_template('firewall.html', firewall=firewall, username=session['username'])

@app.route('/api/firewall/ports/<action>', methods=['POST'])
@login_required
def api_firewall_control(action):
    port = request.form.get('port')
    if action in ['allow', 'deny'] and port:
        result = run_command(f'ufw {action} {port}')
        return jsonify(result)
    return jsonify({'error': 'Invalid action or port'})

# Virtualization (KVM Only)
@app.route('/virtualization')
@login_required
def virtualization():
    kvm_vms = get_kvm_vms()
    os_images = get_os_images()
    return render_template('virtualization.html', 
                         kvm_vms=kvm_vms,
                         os_images=os_images,
                         username=session['username'])

@app.route('/api/kvm/vms/<vm_name>/<action>', methods=['POST'])
@login_required
def api_kvm_control(vm_name, action):
    if action in ['start', 'shutdown', 'reboot', 'destroy']:
        result = run_command(f'virsh {action} {vm_name}')
        return jsonify(result)
    return jsonify({'error': 'Invalid action'})

@app.route('/api/kvm/vms/create', methods=['POST'])
@login_required
def api_create_vm():
    name = request.form.get('name')
    memory = request.form.get('memory', '1024')
    disk_size = request.form.get('disk_size', '10')
    os_image = request.form.get('os_image')
    
    if name and os_image:
        # Create VM using virt-install
        cmd = f"virt-install --name {name} --memory {memory} --disk size={disk_size} --import --os-variant generic --graphics vnc --noautoconsole"
        result = run_command(cmd)
        return jsonify(result)
    
    return jsonify({'error': 'Missing VM name or OS image'})

# Tmate
@app.route('/tmate')
@login_required
def tmate_generator():
    tmate_session = generate_tmate()
    return render_template('tmate.html', tmate=tmate_session, username=session['username'])

@app.route('/api/tmate/generate')
@login_required
def api_tmate_generate():
    return jsonify(generate_tmate())

# System Tools
@app.route('/system')
@login_required
def system_tools():
    return render_template('system.html', username=session['username'])

@app.route('/api/system/power/<action>', methods=['POST'])
@login_required
def api_power_control(action):
    if action in ['shutdown', 'reboot']:
        run_command(f'systemctl {action}')
        return jsonify({'status': 'success'})
    return jsonify({'error': 'Invalid action'})

@app.route('/api/ssh/change-port', methods=['POST'])
@login_required
def api_change_ssh_port():
    new_port = request.form.get('new_port')
    if new_port:
        run_command(f"sed -i 's/^#Port.*/Port {new_port}/' /etc/ssh/sshd_config")
        run_command("systemctl restart ssh")
        return jsonify({'status': 'success', 'message': f'SSH port changed to {new_port}'})
    return jsonify({'error': 'No port specified'})

# User Management
@app.route('/users')
@admin_required
def user_management():
    users = query_db('SELECT * FROM users')
    return render_template('users.html', users=users, username=session['username'])

@app.route('/api/users/create', methods=['POST'])
@admin_required
def api_create_user():
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = request.form.get('is_admin') == 'true'
    
    if username and password:
        execute_db(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
            [username, generate_password_hash(password), is_admin]
        )
        return jsonify({'status': 'success', 'message': f'User {username} created'})
    
    return jsonify({'error': 'Missing username or password'})

@app.route('/api/users/expiry', methods=['POST'])
@admin_required
def api_set_expiry():
    username = request.form.get('username')
    days = request.form.get('days')
    
    if username and days:
        expiry_date = datetime.now() + timedelta(days=int(days))
        execute_db(
            'UPDATE users SET expiry_date = ? WHERE username = ?',
            [expiry_date.isoformat(), username]
        )
        return jsonify({'status': 'success', 'message': f'Expiry set for {username}'})
    
    return jsonify({'error': 'Missing username or days'})

@app.route('/api/users/delete', methods=['POST'])
@admin_required
def api_delete_user():
    username = request.form.get('username')
    
    if username and username != 'admin':
        execute_db('DELETE FROM users WHERE username = ?', [username])
        return jsonify({'status': 'success', 'message': f'User {username} deleted'})
    
    return jsonify({'error': 'Cannot delete admin user'})

# License Management
@app.route('/license')
@admin_required
def license_manager():
    licenses = query_db('SELECT * FROM licenses')
    return render_template('license.html', licenses=licenses, username=session['username'])

@app.route('/api/license/generate', methods=['POST'])
@admin_required
def api_generate_license():
    domain = request.form.get('domain')
    expiry_days = request.form.get('expiry_days')
    
    if domain and expiry_days:
        license_system = LicenseSystem()
        license_key = license_system.generate_license(domain, int(expiry_days))
        return jsonify({'license_key': license_key})
    
    return jsonify({'error': 'Missing domain or expiry days'})

@app.route('/api/license/validate', methods=['POST'])
@login_required
def api_validate_license():
    license_key = request.form.get('license_key')
    current_domain = request.host.split(':')[0]  # Get current domain
    
    if license_key:
        license_system = LicenseSystem()
        valid, message = license_system.validate_license(license_key, current_domain)
        return jsonify({'valid': valid, 'message': message})
    
    return jsonify({'error': 'No license key provided'})

# Settings
@app.route('/settings')
@login_required
def settings():
    config = get_all_config()
    return render_template('settings.html', config=config, username=session['username'])

@app.route('/api/config/update', methods=['POST'])
@login_required
def api_update_config():
    for key in ['ssh_welcome', 'web_welcome', 'footer', 'background', 'allow_registration', 'max_users', 'maintenance_mode']:
        value = request.form.get(key)
        if value is not None:
            set_config(key, value)
    
    # Update SSH welcome message
    ssh_welcome = request.form.get('ssh_welcome')
    if ssh_welcome:
        with open('/etc/motd', 'w') as f:
            f.write(ssh_welcome + '\n')
    
    return jsonify({'status': 'success', 'message': 'Settings updated'})

# API Routes
@app.route('/api/system/info')
@login_required
def api_system_info():
    return jsonify(get_system_info())

@app.route('/api/services')
@login_required
def api_services():
    return jsonify(get_services())

@app.route('/api/firewall/status')
@login_required
def api_firewall_status():
    return jsonify(get_ufw_status())

@app.route('/api/kvm/vms')
@login_required
def api_kvm_vms():
    return jsonify(get_kvm_vms())

@app.route('/api/kvm/images')
@login_required
def api_kvm_images():
    return jsonify(get_os_images())

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    print("🚀 Starting Rvm VPS Control Panel on http://0.0.0.0:3000")
    print("📊 Optimized with separate HTML files")
    print("🔐 Default: admin / admin123")
    print("💾 Database: rvm.db")
    print("🖥️  KVM Focused Virtualization")
    
    app.run(host='0.0.0.0', port=3000, debug=False)
