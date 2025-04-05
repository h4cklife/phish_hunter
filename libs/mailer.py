import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from os.path import basename


class Mailer:
    """
    Mailer Class

    Used to create emails for reporting Phishing URLs
    
    """
    def __init__(self):
        self.sender_email = os.getenv("smtp_sender")
        self.smtp_server = os.getenv("smtp_host")
        self.smtp_port = int(os.getenv("smtp_port"))
        self.smtp_password = os.getenv("smtp_password")

    def send_mail(self, recipient=None, custom_message=None, target_domain=None, attachments=None):
        """
        Send email to a recipient with a default and custom additive message about a
        target domain with attachments for proof and validation purposes of
        a reported phish takedown.

        :param str recipient:
        :param str custom_message:
        :param str target_domain:
        :param list attachments:

        :return:

        """
        # Email configuration
        sender_email = self.sender_email
        password = self.smtp_password
        smtp_server = self.smtp_server
        smtp_port = self.smtp_port

        recipient = recipient
        custom_message = custom_message
        target_domain = target_domain
        attachment = attachments

        message = {}

        # Create the email message
        message["From"] = self.sender_email
        message["To"] = recipient
        message["Subject"] = "Phishing Domain Report"

        default_message = f"""This email is in regards to a reported registrar that 
        is using a purchased domain for Phishing purposes. Please see the outlined details below
        and any screenshot attachments included as proof and for your verification purposes.
        We are requesting a Takedown of said domain immediately to protect the users of the internet.
        
        DOMAIN: {target_domain}
        
        """

        message = MIMEText(f"{default_message}\n\n{custom_message}")

        for f in attachments or []:
            with open(f, "rb") as fil:
                ext = f.split('.')[-1:]
                attached_file = MIMEApplication(fil.read(), _subtype=ext)
                attached_file.add_header(
                    'content-disposition', 'attachment', filename=basename(f))
                msg.attach(attached_file)

        # Send the email
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()  # Upgrade connection to secure TLS
            server.login(sender_email, password)
            server.sendmail(sender_email, recipient, message.as_string())
            print("Domain provider notified successfully!")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            server.quit()
