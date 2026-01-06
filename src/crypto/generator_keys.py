from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from pathlib import Path
import os
import hashlib

#Класс для функция связанных с ключами
class Keys:
    def __init__(self, dir_name:str="data", sync_key_name:str="", async_private_key_name:str="", async_public_key_name:str="", vectore_name:str="", password:str="password"):
        self.password = password.encode('utf-8')
        
        self.dir_name = Path(dir_name)
        self.sync_key_path = Path(self.dir_name / sync_key_name)
        self.async_public_key_path = Path(self.dir_name / async_public_key_name)
        self.async_private_key_path = Path(self.dir_name / async_private_key_name)
        self.vectore_path = Path(self.dir_name / vectore_name)
        self.dir_name.mkdir(parents=True, exist_ok=True)
    
    #Метод генерации вектора
    def vectore(self):
        if not os.path.exists(self.vectore_path):
            with open(self.vectore_path, 'wb') as vectore:
                vectore_data = os.urandom(16)
                vectore.write(vectore_data)
    
    #Метод генерации синхронного ключа
    def gen_sync_key(self):
        with open(self.sync_key_path, 'wb') as key:
            key.write(get_random_bytes(32))
    
    #Метод генерации асинхронного ключа
    def gen_async_key(self):
        keys = RSA.generate(3072)
        with open(self.async_public_key_path, 'wb') as key_pub:
            key_pub.write(keys.public_key().export_key())
        try:
            with open(self.async_private_key_path, 'wb') as key_private:
                key_private.write(keys.export_key(format='PEM', passphrase=self.password, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', prot_params={'iteration_count':131072}))
        except ValueError:
            raise ValueError("You have entered a blank password. Passwords cannot be blank. Default password: password")
    
    #Метод шифрования синхронного ключа с помощью асинхронного шифрования
    def synchronous_key_encryption(self):
        with open(self.sync_key_path, 'rb') as sync_key:
            sync_key = sync_key.read()
        with open(self.async_public_key_path, 'rb') as async_key:
            async_key = RSA.import_key(async_key.read(), self.password)
        
        encrypt = PKCS1_OAEP.new(async_key)
        encrypt = encrypt.encrypt(sync_key)
        with open(self.sync_key_path, 'wb') as sync_key:
            sync_key.write(encrypt)
            
    #Функция для запуска всех методов      
    def run(self):
        if not os.path.exists(self.sync_key_path):
            self.vectore()
            self.gen_sync_key()
            self.gen_async_key()
            self.synchronous_key_encryption()