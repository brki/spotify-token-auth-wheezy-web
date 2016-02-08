from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto import Random
from simplecrypt import encrypt as secure_encrypt, decrypt as secure_decrypt, DecryptionException


QUICK_ENCRYPTION = 1
SECURE_ENCRYPTION = 2


class Encryption(object):
    """
    A Python3-only encryption helper.

    The encrypted value is returned as a unicode string containing hex digits.

    QUICK_ENCRYPTION style uses a 32 byte encryption key and basic AES CBC encryption.

    SECURE_ENCRYPTION uses the simplecrypt library, which also uses AES encryption, but
    adds some protection against things like timing attacks.  It can take several
    seconds to encrypt or decrypt a value.

    Note that a string encrypted with QUICK_ENCRYPTION or SECURE_ENCRYPTION encryption_style
    can only be decrypted with an Encryption object that has the same encryption_style.
    """

    def __init__(self, encryption_key, salt='', encryption_style=SECURE_ENCRYPTION):
        self.key = encryption_key
        if isinstance(salt, str):
            salt = salt.encode('utf-8')
        self.salt = salt
        self.salt_length = len(self.salt)
        if encryption_style == QUICK_ENCRYPTION:
            self.encrypt_value = self.encrypt_quickly
            self.decrypt_value = self.decrypt_quickly
        elif encryption_style == SECURE_ENCRYPTION:
            self.encrypt_value = secure_encrypt
            self.decrypt_value = secure_decrypt
        else:
            raise ValueError('Unexpected encryption_style parameter value')

    def encrypt(self, value):
        """
        Transforms the value into a hex-string representation after encrypting it.

        :param value: str or bytes
        :return: str of hex digits
        """
        if isinstance(value, str):
            value = value.encode('utf-8')

        value = self.salt + value

        encrypted_value = self.encrypt_value(self.key, value)

        return hexlify(encrypted_value).decode('ascii')

    def decrypt(self, value):
        """
        Decrypts the hex-string representation of an encrypted value.

        :param value: str or bytes of hex digits
        :return: str with decrypted text
        """
        if isinstance(value, str):
            value = value.encode('utf-8')

        byte_value = unhexlify(value)
        decrypted_value = self.decrypt_value(self.key, byte_value)

        if self.salt_length > 0:
            decrypted_value = decrypted_value[self.salt_length:]

        return decrypted_value.decode('utf8')

    @staticmethod
    def blocks_of_size(block_size, bytes):
        for i in range(0, len(bytes), block_size):
            yield bytes[i:i+block_size]

    def encrypt_quickly(self, encryption_key, byte_value):
        """
        Return bytes: first 16 bytes are the IV value, the rest is the encrypted value.

        If the passed byte_value is not a multiple of the block size, the first block
        will have padding inserted at position 0.

        :param byte_value:
        :return:
        """
        iv = Random.get_random_bytes(AES.block_size)
        encryptor = AES.new(encryption_key, AES.MODE_CBC, iv)

        padding_count = -len(byte_value) % AES.block_size
        padded = b'\x00' * padding_count + byte_value

        encrypted = iv
        for block in self.blocks_of_size(AES.block_size, padded):
            encrypted += encryptor.encrypt(block)

        return encrypted

    def decrypt_quickly(self, encryption_key, byte_value):
        iv = byte_value[:AES.block_size]
        value = byte_value[AES.block_size:]
        value_length = len(value)
        if value_length == 0 or value_length % AES.block_size > 0:
            raise DecryptionException("This doesn't seem to be encrypted in the expected format")

        decryptor = AES.new(encryption_key, AES.MODE_CBC, iv)

        decrypted_bytes = b''
        is_first_block = True
        for block in self.blocks_of_size(AES.block_size, value):
            decrypted_bytes += decryptor.decrypt(block)
            if is_first_block:
                # Strip off any padding that was added to the first block.
                decrypted_bytes = decrypted_bytes.lstrip(b'\x00')
                is_first_block = False

        return decrypted_bytes
