import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Encryptor(object):
    def __init__(self, password):
        self.fernet = Fernet(pbkd(password))

    def encrypt(self, value):
        return '0$' + self.fernet.encrypt(value)

    def decrypt(self, value):
        version, value = value.split('$', 1)
        return self.fernet.decrypt(value)


class NullEncryptor(object):

    def encrypt(self, value):
        return value

    def decrypt(self, value):
        return value


def pbkd(value, length=32, salt=''):
    ''' password based key derivation '''
    k = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    ).derive(value)
    return base64.urlsafe_b64encode(k)
