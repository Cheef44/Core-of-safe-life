from src.crypto import encryption
from Crypto.Cipher import AES
import chardet
import hashlib

#Класс для дешифровки данных
class Decryption(encryption.EncryptionText):
    def __init__(self, data:str, password:str, dir_name:str, sync_key_name:str, async_private_key_name:str, async_public_key_name:str, vectore_name:str):
        super().__init__(
            data,
            password,
            dir_name,
            sync_key_name,
            async_private_key_name,
            async_public_key_name,
            vectore_name
        )
        self.data = data
        self.password = password
    
    #Функция для дешифровки данных 
    def decryption(self):
        try:
            decrypt = AES.new(self.decrypt_sync_key(self.password), AES.MODE_CFB, self.vectore())
            enc_file = self.data
            decrypt_data = decrypt.decrypt(enc_file)
            if decrypt_data != b'':
                decrypt_data = decrypt_data.decode(chardet.detect(decrypt_data)['encoding'])
            else:
                decrypt_data = ''
            return decrypt_data
        except ValueError:
            raise ValueError('Encryption keys were not found')
        except TypeError:
            raise TypeError('Bytes required, string entered')