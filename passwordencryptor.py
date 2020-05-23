import base64
import os
import string
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class PasswordEncryptor:
    
    def __init__(self, salt_file='salt'):
        self.salt_file = salt_file

        
    def _getsalt(self):
        if os.path.exists(self.salt_file):
            file = open(self.salt_file, 'rb')
            salt = file.read()
            file.close()
            return salt
        else:
            file = open(self.salt_file, 'wb')
            salt = os.urandom(16)
            file.write(salt)
            file.close()
            return salt


    def _generatekey(self, masterpassword):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._getsalt(),
            iterations=100000,
            backend=default_backend()
        )

        return base64.urlsafe_b64encode(
            kdf.derive(masterpassword.encode())
        )


    def encrypt(self, masterpassword, password):
        f = Fernet(self._generatekey(masterpassword))
        encryptedpass = f.encrypt(password.encode())
        return encryptedpass


    def decrypt(self, masterpassword, password):
        f = Fernet(self._generatekey(masterpassword))
        decryptedpass = f.decrypt(password)
        return str(decryptedpass, 'utf-8')


    def generate_password(self, length=16):
        alphabet = string.ascii_letters + string.digits + string.punctuation 
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        return password    