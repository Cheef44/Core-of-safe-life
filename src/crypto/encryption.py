from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import json
import hashlib
from pathlib import Path

#Подготовка ключей к шифрованию
class PreparationEncryption:
    def __init__(self, dir_name:str, sync_key_name:str, async_private_key_name:str, async_public_key_name:str, vectore_name:str) -> None:
        
        self.dir_name = Path(dir_name)
        self.sync_key_path = Path(self.dir_name / sync_key_name)
        self.async_public_key_path = Path(self.dir_name / async_public_key_name)
        self.async_private_key_path = Path(self.dir_name / async_private_key_name)
        self.vectore_path = Path(self.dir_name / vectore_name)
        
    #Метод получения вектора
    def vectore(self):
        try:
            with open(self.vectore_path, 'rb') as iv:
                iv = iv.read()
            return iv
        except FileNotFoundError:
            raise FileNotFoundError('Vectore were not found')
        
    #Метод расшифровки синхронного ключа
    def decrypt_sync_key(self, password):
        password = hashlib.sha3_512(bytes(password, encoding='utf-8')).digest()
        try:
            with open(self.async_private_key_path, 'rb') as private_key:
                private_key = private_key.read()
                private_key = RSA.import_key(private_key, passphrase=password)
                
            with open(self.sync_key_path, 'rb') as sync_key:
                sync_key = sync_key.read()
                
            decrypt = PKCS1_OAEP.new(private_key)
            decrypt = decrypt.decrypt(sync_key)
            
            return decrypt
        except FileNotFoundError:
            raise FileNotFoundError('Encryption keys were not found')
        
#Класс для шифрования текста
class EncryptionText(PreparationEncryption):
    def __init__(self, data:str, password:str, dir_name:str, sync_key_name:str, async_private_key_name:str, async_public_key_name:str, vectore_name:str):
        super().__init__(
            dir_name=dir_name,
            sync_key_name=sync_key_name,
            async_private_key_name=async_private_key_name,
            async_public_key_name=async_public_key_name,
            vectore_name=vectore_name
        )
        self.data = data
        self.password = password
        
    #Метод шифрования текста
    def encryption_text(self):
        encrypt = AES.new(self.decrypt_sync_key(self.password), AES.MODE_CFB, self.vectore())
        encrypt_text = encrypt.encrypt(bytes(self.data, encoding='utf8'))
        return encrypt_text