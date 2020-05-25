import base64
import os
import string
import secrets

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class PasswordEncrypter:

    def __getsalt(self, salt_file):
        if os.path.exists(salt_file):
            file = open(salt_file, 'rb')
            salt = file.read()
            file.close()
            return salt
        else:
            file = open(salt_file, 'wb')
            salt = os.urandom(32)
            file.write(salt)
            file.close()
            return salt


    def hashpass(self, password, salt_file):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.__getsalt(salt_file),
            iterations=100000,
            backend=default_backend()
        )

        return base64.urlsafe_b64encode(
            kdf.derive(password.encode())
        )


    def encrypt(self, masterpassword, password, salt_file):
        f = Fernet(self.hashpass(masterpassword, salt_file))
        encryptedpass = f.encrypt(password.encode())
        return encryptedpass


    def decrypt(self, masterpassword, password, salt_file):
        f = Fernet(self.hashpass(masterpassword, salt_file))
        decryptedpass = f.decrypt(password)
        return str(decryptedpass, 'utf-8')


    def genpass(self, length=16):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        return password