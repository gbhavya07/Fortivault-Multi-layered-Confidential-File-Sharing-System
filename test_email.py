# test_email.py
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg['Subject'] = 'Test OTP from Flask App'
msg['From'] = 'gurrambhavya0708@gmail.com'
msg['To'] = 'vijayalaxmig1234@gmail.com'  # change to your email
msg.set_content('This is a test email to confirm OTP delivery.')

try:
    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login('gurrambhavya0708@gmail.com', 'rgihbpfsnovctahj')
        smtp.send_message(msg)

    print("✅ Test email sent successfully.")
except Exception as e:
    print(f"❌ Email send failed: {e}")
