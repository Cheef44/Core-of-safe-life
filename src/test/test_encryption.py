from pathlib import Path
from src.crypto import encryption
from src.crypto.generator_keys import Keys

#Класс тестирования модуля шифрования
class TestEncryption:
    #Метод тестирования получения вектора
    def test_vectore(self, tmp_path):
        keys = Keys(
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin",
            password=""
        )
        
        keys.run()
        vectore = encryption.PreparationEncryption(
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin"
        )
        
        assert vectore.vectore() != FileNotFoundError
    
    #Метод тестирования расшифровки ключа
    def test_decrypt_sync_key(self, tmp_path):
        keys = Keys(
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin",
            password="1"
        )
        
        keys.run()
        decrypt_sync_key = encryption.PreparationEncryption(
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin"
        )
        
        assert decrypt_sync_key.decrypt_sync_key(password="1") != FileNotFoundError
    
    #Метод тестирования шифрования текста
    def test_encryption_text(self, tmp_path):
        keys = Keys(
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin",
            password="1"
        )
        
        keys.run()
        encrypt_text = encryption.EncryptionText(
            data="test_text",
            password="1",
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin"
        )
        
        assert len(encrypt_text.encryption_text()) > 0