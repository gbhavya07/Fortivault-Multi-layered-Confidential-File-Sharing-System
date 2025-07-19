# 🛡️ Fortivault – Multi-layered Confidential File Sharing System

**Fortivault** is a security-centric file sharing system built for confidentiality, integrity, and controlled access. It combines advanced encryption algorithms (AES-256, RSA), authentication protocols, CAPTCHA, OTP, and watermarking to ensure safe document transmission and receipt.

---

## 🔐 Key Features

- 🔒 **End-to-End Encryption**  
  - AES-256 symmetric encryption for file content  
  - RSA asymmetric encryption for key sharing

- 🧩 **Multi-Factor Authentication (MFA)**  
  - Email OTP verification  
  - CAPTCHA before access

- 🧼 **Digital Watermarking**  
  - Adds unique traceable mark to documents before transmission

- 🔄 **Rate Limiting & Access Control**  
  - Prevents brute-force login attempts and download abuse

- 🧾 **Audit Logs**  
  - Logs IP, time, and action for every sensitive operation

---

## 🧰 Tech Stack

| Component            | Technology         |
|----------------------|--------------------|
| Backend              | Python (Flask)     |
| Frontend             | HTML, CSS, JS      |
| Cryptography         | AES (PyCryptodome), RSA (Cryptography) |
| MFA / CAPTCHA        | Python, Email OTP, PIL, CAPTCHA Module |
| File Processing      | Python File IO, Hashing |
| Watermarking         | Python Imaging Library (PIL) |
| Logging              | Custom Python Logger |
| Optional Storage     | Local / S3 / Database (extensible) |

---

## 🛠️ Security Layers Summary

| Layer                  | Description                                       |
|------------------------|---------------------------------------------------|
| AES Encryption         | Encrypts the uploaded file                       |
| RSA Key Exchange       | Secures AES key during transmission              |
| MFA (OTP + CAPTCHA)    | Ensures authorized access                        |
| Watermarking           | Tracks user identity in distributed documents    |
| Rate Limiting          | Limits suspicious repetitive actions             |
| IP Logging             | Maintains traceability and investigation trail   |

---

## 🔢 System Flow

1. **User Uploads File**  
   → CAPTCHA verified → OTP sent → AES Encryption → Watermark added → RSA-encrypted key generated  
2. **File Shared via Link**  
   → Receiver enters OTP → RSA Decryption → File Decryption → Download with embedded watermark  
3. **Admin Dashboard (Optional)**  
   → Monitor logs, active transfers, download history

---

## 🧠 DSA & Algorithms Used

- AES (CBC mode), RSA (PKCS1)
- CAPTCHA: Random String Generation + Image Rendering
- OTP: Secure random base32 + Email
- Hashing: SHA-256 for integrity check
- Queues (Optional): For asynchronous sharing logic
- Sets: To track expired or used OTPs

---

## 💻 How to Run

```bash
git clone https://github.com/yourusername/Fortivault-Confidential-File-Sharing-System.git
cd Fortivault
pip install -r requirements.txt
python app.py
