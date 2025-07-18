import string

from flask_sqlalchemy import SQLAlchemy

import os
from flask_bcrypt import Bcrypt
import bcrypt as real_bcrypt
import smtplib
from email.message import EmailMessage
  # light transparency

from flask import Flask, render_template, request, redirect, url_for, session, flash
import random
from flask import session
import mimetypes
from flask import send_file
from io import BytesIO
from flask import send_from_directory
import uuid  # Add at the top
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO

def create_watermark(access_text: str, owner_text: str):
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.colors import gray
    from io import BytesIO

    packet = BytesIO()
    can = canvas.Canvas(packet, pagesize=letter)
    width, height = map(int, letter)  # Ensure width and height are integers

    # ✅ Single diagonal watermark (centered across the page)
    can.saveState()
    can.setFillColorRGB(0.75, 0.75, 0.75)  # Light gray
    can.setFont("Helvetica-Bold", 34)
    can.translate(width / 2, height / 2)
    can.rotate(45)
    can.drawCentredString(0, 0, access_text)
    can.restoreState()

    # ✅ Footer: Owned by
    can.setFont("Helvetica", 10)
    can.setFillColor(gray)
    can.drawRightString(width - 20, 20, owner_text)

    can.save()
    packet.seek(0)
    return PdfReader(packet)


import smtplib
from email.message import EmailMessage

def send_otp_email(to_email, otp):
    msg = EmailMessage()
    msg['Subject'] = 'Your OTP for Secure File Access'
    msg['From'] = 'gurrambhavya0708@gmail.com89'
    msg['To'] = to_email
    msg.set_content(f'Your OTP is: {otp}\n\nThis OTP is valid for a short time.')

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.ehlo()
            smtp.starttls()  # Start TLS encryption
            smtp.login('gurrambhavya0708@gmail.com', 'rgihbpfsnovctahj')  # ✅ Use App Password
            smtp.send_message(msg)
        print(f"✅ OTP sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")

import random

def generate_otp():
    return str(random.randint(100000, 999999))


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'zip', 'docx', 'xlsx', 'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
app.secret_key = "super_secure_key_12345"  # Your secret key

# Database config for MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:MySql%402013@localhost:3306/secure_messaging'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class SecureContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    encryption_key = db.Column(db.String(200), nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)
    read_limit = db.Column(db.Integer, nullable=False)
    read_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    secure_id = db.Column(db.String(100), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    password_hash = db.Column(db.String(200), nullable=True)   # <-- ADD THIS
    wrong_attempts = db.Column(db.Integer, default=0)           # <-- ADD THIS
    signature_filename = db.Column(db.String(300), nullable=True)
    allowed_users = db.Column(db.Text, nullable=True)  # comma-separated email addresses

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content_id = db.Column(db.Integer, db.ForeignKey('secure_content.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    access_time = db.Column(db.DateTime, default=datetime.utcnow)
    wrong_attempts = db.Column(db.Integer, default=0)  # ✅ new field
    access_outcome = db.Column(db.String(50), nullable=False, default="Pending")  # e.g., "Success", "Wrong Password"
    user = db.relationship('User')


# Home Route
@app.route('/')
def home():
     return render_template('lock_page.html')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        import re

        # Validate password strength
        password = request.form.get('password', '')
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            return render_template('register.html', error="Password must be at least 8 characters, include 1 uppercase, 1 lowercase, 1 digit, and 1 special character.")

        # 🚫 Check for empty fields
        if not email or not password:
            return render_template('register.html', error="Email and password are required.")

        # ✅ Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template('register.html', error="Email is already registered. Please log in.")

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        next_page = session.pop('next', None)
        return redirect(next_page or url_for('dashboard'))

    return render_template('register.html')

def uploaded_file_is_text(filename):
    text_extensions = ['.txt', '.md', '.html', '.csv']
    for ext in text_extensions:
        if filename.lower().endswith(ext):
            return True
    return False





















# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            next_page = session.pop('next', None)
            return redirect(next_page or url_for('dashboard'))
        else:
            return "Invalid credentials"

    return render_template('login.html')


# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('otp_verified_users', None)
    # optionally clear all captcha keys
    session.clear()
    return redirect(url_for('login'))




@app.route('/my_files')
def my_files():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    contents = SecureContent.query.filter_by(sender_id=user_id).all()

    now = datetime.now()

    for content in contents:
        # Set Active / Expired status
        if now > content.expiry_time or content.read_count >= content.read_limit:
            content.status = "Expired"
        else:
            content.status = "Active"

        # Attach Access Logs for each file
        content.access_logs = AccessLog.query.filter_by(content_id=content.id).all()

    return render_template('my_files.html', contents=contents, now=now)

@app.route('/delete_my_file/<content_id>', methods=['POST'])
def delete_my_file(content_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    content = db.session.get(SecureContent, content_id)

    if content and content.sender_id == session['user_id']:
        destroy_content(content)
    
    return redirect(url_for('my_files'))

@app.route('/view_access_logs/<int:file_id>')
def view_access_logs(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Verify owner
    content = SecureContent.query.get(file_id)
    if not content or content.sender_id != session['user_id']:
        return "Unauthorized access."

    logs = AccessLog.query.filter_by(content_id=file_id).all()

    return render_template('view_access_logs.html', logs=logs, filename=content.filename)





@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        uploaded_file = request.files['file']
        if not allowed_file(uploaded_file.filename):
            return "File type not allowed. Allowed types: txt, pdf, zip, docx, xlsx, csv."

        expiry_hours = request.form.get('expiry_hours')
        expiry_datetime = request.form.get('expiry_datetime')
        read_limit = request.form.get('read_limit')
        password = request.form.get('password')

        # Validate expiry fields
        if (expiry_hours and expiry_datetime) or (not expiry_hours and not expiry_datetime):
            flash("Please provide either Expiry Time (in hours) or Exact Expiry Date & Time, but not both.")
            return redirect(url_for('upload'))

        # Calculate expiry time
        try:
            if expiry_hours:
                expiry_time = datetime.now() + timedelta(hours=int(expiry_hours))
            else:
                expiry_time = datetime.strptime(expiry_datetime, "%Y-%m-%dT%H:%M")
        except Exception:
            flash("Invalid expiry time provided.")
            return redirect(url_for('upload'))

        # Validate read limit
        try:
            read_limit = int(read_limit)
            if read_limit <= 0:
                flash("Read Limit must be positive.")
                return redirect(url_for('upload'))
        except Exception:
            flash("Invalid read limit.")
            return redirect(url_for('upload'))

        # Generate encryption key
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # Encrypt uploaded file
        encrypted_data = fernet.encrypt(uploaded_file.read())

        # Save encrypted file
        encrypted_filename = f"{datetime.now().timestamp()}_{uploaded_file.filename}"
        file_path = os.path.join('uploads', encrypted_filename)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        # ----- Digital Signature Part -----
        # Load Private Key
        private_key = RSA.import_key(open('private.pem').read())

        # Sign the encrypted file
        h = SHA256.new(encrypted_data)
        signature = pkcs1_15.new(private_key).sign(h)

        # Save signature file
        signature_filename = f"{encrypted_filename}.sig"
        signature_path = os.path.join('uploads', signature_filename)
        with open(signature_path, 'wb') as f:
            f.write(signature)
        # -----------------------------------

        # Handle password hashing
        if password:
            password_hash = real_bcrypt.hashpw(password.encode(), real_bcrypt.gensalt()).decode('utf-8')

        else:
            password_hash = None

        allowed_users = request.form.get('allowed_users')
        if allowed_users:
            allowed_users = ",".join([email.strip().lower() for email in allowed_users.split(",")])
        else:
            allowed_users = None

        # Save metadata to DB
        new_content = SecureContent(
        sender_id=session['user_id'],
        filename=encrypted_filename,
        encryption_key=key.decode(),
        expiry_time=expiry_time,
        read_limit=read_limit,
        password_hash=password_hash,
        signature_filename=signature_filename,
        allowed_users=allowed_users
    )

        db.session.add(new_content)
        db.session.commit()

        # Generate secure link
        link = url_for('access_content', secure_id=new_content.secure_id, _external=True)
        return render_template('upload_success.html', link=link)

    return render_template('upload.html')
    
@app.route('/access/<secure_id>', methods=['GET', 'POST'])
def access_content(secure_id):
    if 'user_id' not in session:
        session['next'] = url_for('access_content', secure_id=secure_id)
        return redirect(url_for('login'))

    current_user = db.session.get(User, session['user_id'])
    content = SecureContent.query.filter_by(secure_id=secure_id).first()
    if not content:
        return "Invalid or deleted link."

    if content.allowed_users:
        allowed = [email.strip().lower() for email in content.allowed_users.split(',')]
        if current_user.email.lower() not in allowed:
            return "🚫 You are not authorized to access this file."

    now = datetime.now()
    if now > content.expiry_time:
        destroy_content(content)
        return "This message has expired and was destroyed."
    if content.read_count >= content.read_limit:
        destroy_content(content)
        return "This message has reached max reads and was destroyed."

    # Log access attempt
    log = AccessLog.query.filter_by(content_id=content.id, user_id=current_user.id).first()
    if not log:
        log = AccessLog(content_id=content.id, user_id=current_user.id,
                        ip_address=request.remote_addr, wrong_attempts=0, access_outcome="Pending")
        db.session.add(log)
        db.session.commit()


    if log.wrong_attempts >= 3:
        return render_template('honey_file.html')

    if log.access_outcome == "Wrong OTP":
        return render_template('honey_file.html')

    # OTP Handling
    # OTP Handling
    otp_k = f'otp_{secure_id}_{current_user.email}'
    otp_time_k = f'otp_time_{secure_id}_{current_user.email}'
    otp_verified_k = f'otp_verified_{secure_id}_{current_user.email}'
    attempt_key = f'otp_attempts_{secure_id}_{current_user.email}'

    if not session.get(otp_verified_k):
        if request.method == 'POST' and 'otp_input' in request.form:
            user_input = request.form['otp_input']
            correct_otp = session.get(otp_k)
            otp_time = session.get(otp_time_k)
            if not correct_otp or not otp_time or datetime.now().timestamp() - otp_time > 300:
                log.access_outcome = "Expired OTP"
                db.session.commit()
                session.pop(otp_k, None)
                session.pop(otp_time_k, None)
                session[attempt_key] = 0
                return render_template('otp_entry.html', secure_id=secure_id, error="OTP expired. Refresh.")
            
            if user_input == correct_otp:
                session[otp_verified_k] = True
                session.pop(otp_k, None)
                session.pop(otp_time_k, None)
                session.pop(attempt_key, None)
                log.access_outcome = "Success"  # Update outcome on successful OTP
                db.session.commit()
                return redirect(url_for('access_content', secure_id=secure_id))
            else:
                session[attempt_key] = session.get(attempt_key, 0) + 1
                if session[attempt_key] > 3:
                    log.access_outcome = "Wrong OTP"
                    db.session.commit()
                    return render_template('honey_file.html')
                log.access_outcome = "Wrong OTP"
                db.session.commit()
                return render_template('otp_entry.html', secure_id=secure_id, error="Invalid OTP.")
        else:
            otp = generate_otp()
            session[otp_k] = otp
            session[otp_time_k] = datetime.now().timestamp()
            session[attempt_key] = 0
            send_otp_email(current_user.email, otp)
            return render_template('otp_entry.html', secure_id=secure_id)

    # CAPTCHA
    captcha_key = f'captcha_verified_{secure_id}_{current_user.email}'
    if not session.get(captcha_key):
        if request.method == 'POST' and 'captcha_answer' in request.form:
            try:
                ans = int(request.form['captcha_answer'])
                if ans == session.get('captcha_num1', 0) + session.get('captcha_num2', 0):
                    session[captcha_key] = True
                    return redirect(url_for('access_content', secure_id=secure_id))
                raise ValueError()
            except:
                session['captcha_num1'] = random.randint(1, 10)
                session['captcha_num2'] = random.randint(1, 10)
                return render_template('captcha_entry.html',
                                       num1=session['captcha_num1'],
                                       num2=session['captcha_num2'],
                                       error="Incorrect.")
        else:
            session['captcha_num1'] = random.randint(1, 10)
            session['captcha_num2'] = random.randint(1, 10)
            return render_template('captcha_entry.html',
                                   num1=session['captcha_num1'],
                                   num2=session['captcha_num2'])

    # Password check
    if content.password_hash:
        if request.method == 'POST' and 'password' in request.form:
            entered = request.form['password']
            if real_bcrypt.checkpw(entered.encode(), content.password_hash.encode('utf-8')):
                log.wrong_attempts = 0
                log.access_outcome = "Success"  # ✅ Update on successful password entry
                db.session.commit()
            else:
                log.wrong_attempts += 1
                log.access_outcome = "Wrong Password"  # ✅ Failed attempt
                db.session.commit()
                if log.wrong_attempts >= 3:
                    log.access_outcome = "Wrong Password"
                    db.session.commit()
                    return render_template('honey_file.html')
                return render_template('password_entry.html', error="Wrong password.", secure_id=secure_id)
        else:
            return render_template('password_entry.html', secure_id=secure_id)

    # Final Access Grant
    file_path = os.path.join('uploads', content.filename)
    signature_path = os.path.join('uploads', content.signature_filename or "")
    if not os.path.exists(file_path) or not os.path.exists(signature_path):
        destroy_content(content)
        return "File missing or already destroyed."

    def decrypt_watermark():
        with open(file_path, 'rb') as f: encrypted_data = f.read()
        with open(signature_path, 'rb') as f: signature = f.read()
        h = SHA256.new(encrypted_data)
        pkcs1_15.new(RSA.import_key(open('public.pem').read())).verify(h, signature)
        decrypted = Fernet(content.encryption_key.encode()).decrypt(encrypted_data)
        watermark = f"\n\n--- Accessed by {current_user.email} (IP: {request.remote_addr}) at {datetime.now()} ---\n"
        return decrypted + watermark.encode()

    decrypted_data = decrypt_watermark()
    content.read_count += 1
    log.access_outcome = "Success"
    db.session.commit()

    seconds_remaining = int((content.expiry_time - now).total_seconds())

    if uploaded_file_is_text(content.filename):
        decrypted_data = decrypt_and_watermark()
        log.access_outcome = "Success"  # ✅ Record successful access
        db.session.commit()
        return render_template('access_with_countdown.html',
                               message=decrypted_data.decode(),
                               seconds_remaining=seconds_remaining,
                               read_count=content.read_count,
                               read_limit=content.read_limit,
                               secure_id=secure_id)
    else:
        return render_template('download_with_countdown.html',
                               file_name=content.filename,
                               seconds_remaining=seconds_remaining,
                               read_count=content.read_count,
                               read_limit=content.read_limit,
                               secure_id=secure_id)

@app.route('/otp_continue/<secure_id>')
def otp_continue(secure_id):
    return redirect(url_for('access_content', secure_id=secure_id))


from io import BytesIO
import mimetypes
from PyPDF2 import PdfReader, PdfWriter
import zipfile
import os
from flask import send_file
from docx import Document
import openpyxl

# Adjusting ALLOWED_EXTENSIONS if needed
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'zip', 'docx', 'xlsx', 'csv'}

@app.route('/download/<secure_id>')
def download_file(secure_id):
    content = SecureContent.query.filter_by(secure_id=secure_id).first()
    if not content:
        return "Invalid or deleted secure link."

    file_path = os.path.join('uploads', content.filename)
    if not os.path.exists(file_path):
        return "Encrypted file missing."

    # Read and decrypt the file
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    fernet = Fernet(content.encryption_key.encode())
    decrypted_data = fernet.decrypt(encrypted_data)

    current_user = db.session.get(User, session['user_id'])

    # ✅ PDF Handling with Watermark
    if content.filename.lower().endswith(".pdf"):
        return handle_pdf_watermark(decrypted_data, content, current_user)

    # ✅ Text Files Handling (txt, csv)
    elif content.filename.lower().endswith(('.txt', '.csv')):
        return handle_text_watermark(decrypted_data, content, current_user)

    # ✅ Word Document Handling (.docx)
    elif content.filename.lower().endswith('.docx'):
        return handle_docx_watermark(decrypted_data, content, current_user)

    # ✅ Excel Files Handling (.xlsx)
    elif content.filename.lower().endswith('.xlsx'):
        return handle_xlsx_watermark(decrypted_data, content, current_user)

    # ✅ Zip File Handling (.zip)
    elif content.filename.lower().endswith('.zip'):
        return handle_zip_watermark(decrypted_data, content, current_user)

    # For unsupported file types, return it directly
    # After successfully verifying OTP, password, or any other access criteria
    log = AccessLog.query.filter_by(content_id=content.id, user_id=current_user.id).first()
    if log:
        log.access_outcome = "Success"  # Ensure this is updated after successful access
        db.session.commit()  # Commit the changes to the database

    # Now proceed with sending the file to the user
    decrypted_file = BytesIO(decrypted_data)
    mime_type, _ = mimetypes.guess_type(content.filename)
    if mime_type is None:
        mime_type = 'application/octet-stream'

    return send_file(
        decrypted_file,
        mimetype=mime_type,
        as_attachment=True,
        download_name=content.filename
)



def handle_pdf_watermark(decrypted_data, content, current_user):
    temp_pdf = BytesIO(decrypted_data)
    temp_pdf.seek(0)
    reader = PdfReader(temp_pdf)

    # Generate watermark
    access_email = current_user.email
    access_ip = request.remote_addr
    access_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    uploader = db.session.get(User, content.sender_id)
    access_text = f"Accessed by {access_email} | {access_time} | IP: {access_ip}"
    owner_text = f"Owned by {uploader.email} (Uploader IP Unknown)"

    watermark_reader = create_watermark(access_text, owner_text)

    # Apply watermark to all pages
    writer = PdfWriter()
    for page in reader.pages:
        page.merge_page(watermark_reader.pages[0])
        writer.add_page(page)

    output_pdf = BytesIO()
    writer.write(output_pdf)
    output_pdf.seek(0)

    return send_file(
        output_pdf,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=content.filename.split("_", 1)[1]
    )


def handle_text_watermark(decrypted_data, content, current_user):
    watermark = f"\n\n--- Accessed by {current_user.email} (IP: {request.remote_addr}) at {datetime.now()} ---\n"
    decrypted_data += watermark.encode()

    decrypted_file = BytesIO(decrypted_data)
    return send_file(
        decrypted_file,
        mimetype='text/plain',
        as_attachment=True,
        download_name=content.filename.split("_", 1)[1]
    )


def handle_docx_watermark(decrypted_data, content, current_user):
    doc = Document(BytesIO(decrypted_data))
    access_email = current_user.email
    access_ip = request.remote_addr
    access_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    watermark = f"Accessed by {access_email} | {access_time} | IP: {access_ip}"
    doc.add_paragraph(watermark, style='Normal')

    # Save the modified document to a buffer
    new_doc = BytesIO()
    doc.save(new_doc)
    new_doc.seek(0)

    return send_file(
        new_doc,
        mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        as_attachment=True,
        download_name=content.filename.split("_", 1)[1]
    )


def handle_xlsx_watermark(decrypted_data, content, current_user):
    wb = openpyxl.load_workbook(BytesIO(decrypted_data))
    sheet = wb.active
    access_email = current_user.email
    access_ip = request.remote_addr
    access_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    watermark = f"Accessed by {access_email} | {access_time} | IP: {access_ip}"
    sheet['A1'] = watermark  # Add watermark to cell A1 (you can place it wherever needed)

    # Save the modified Excel to a buffer
    new_xlsx = BytesIO()
    wb.save(new_xlsx)
    new_xlsx.seek(0)

    return send_file(
        new_xlsx,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=content.filename.split("_", 1)[1]
    )


def handle_zip_watermark(decrypted_data, content, current_user):
    # Create a temporary zip file and add watermark information
    zip_buffer = BytesIO(decrypted_data)
    zip_file = zipfile.ZipFile(zip_buffer, mode='a')  # Open in append mode
    watermark = f"Accessed by {current_user.email} | {datetime.now()} | IP: {request.remote_addr}"

    # Add a new text file to the zip with watermark details
    zip_file.writestr('watermark.txt', watermark)
    zip_file.close()

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=content.filename.split("_", 1)[1]
    )







def destroy_content(content):
    try:
        # Delete all related access logs first
        AccessLog.query.filter_by(content_id=content.id).delete()

        # Delete the encrypted file
        file_path = os.path.join('uploads', content.filename)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete the signature file
        if content.signature_filename:
            signature_path = os.path.join('uploads', content.signature_filename)
            if os.path.exists(signature_path):
                os.remove(signature_path)

        # Now delete the secure content entry
        db.session.delete(content)
        db.session.commit()
    except Exception as e:
        print(f"Error destroying content: {str(e)}")

if __name__ == "__main__":
    app.run(debug=True)
