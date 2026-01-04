from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from pathlib import Path
import os
import hashlib

#Класс для функция связанных с ключами
class Keys:
    def __init__(self, dir_name:str, sync_key_name:str, async_private_key_name:str, async_public_key_name:str, vectore_name:str, password:str=""):
        self.password = hashlib.sha3_512(bytes(password, encoding="utf-8")).digest()
        
        self.dir_name = Path(dir_name)
        self.sync_key_path = sync_key_name
        self.async_public_key_path = async_public_key_name
        self.async_private_key_path = async_private_key_name
        self.vectore_path = vectore_name
        os.mkdir(self.dir_name) if not os.path.exists(self.dir_name) else None
    
    #Метод генерации вектора
    def vectore(self):
        if not os.path.exists(Path(self.dir_name / self.vectore_path)):
            with open(Path(self.dir_name / self.vectore_path), 'wb') as vectore:
                vectore_data = os.urandom(16)
                vectore.write(vectore_data)
    
    #Метод генерации синхронного ключа
    def gen_sync_key(self):
        with open(Path(self.dir_name / self.sync_key_path), 'wb') as key:
            key.write(get_random_bytes(32))
    
    #Метод генерации асинхронного ключа
    def gen_async_key(self):
        keys = RSA.generate(1024)
        with open(Path(self.dir_name / self.async_public_key_path), 'wb') as key_pub:
            key_pub.write(keys.public_key().export_key())
        with open(Path(self.dir_name / self.async_private_key_path), 'wb') as key_private:
            key_private.write(keys.export_key(format='PEM', passphrase=self.password, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', prot_params={'iteration_count':131072}))
    
    #Метод шифрования синхронного ключа с помощью асинхронного шифрования
    def synchronous_key_encryption(self):
        with open(Path(self.dir_name / self.sync_key_path), 'rb') as sync_key:
            sync_key = sync_key.read()
        with open(Path(self.dir_name / self.async_public_key_path), 'rb') as async_key:
            async_key = RSA.import_key(async_key.read(), self.password)
        
        encrypt = PKCS1_OAEP.new(async_key)
        encrypt = encrypt.encrypt(sync_key)
        with open(Path(self.dir_name / self.sync_key_path), 'wb') as sync_key:
            sync_key.write(encrypt)
            
    #Функция для запуска всех методов      
    def run(self):
        if not os.path.exists(Path(self.dir_name / self.sync_key_path)):
            self.vectore()
            self.gen_sync_key()
            self.gen_async_key()
            self.synchronous_key_encryption()