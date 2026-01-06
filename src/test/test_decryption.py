from src.crypto import encryption
from src.crypto.generator_keys import Keys
from src.crypto.decryption import Decryption
import pytest

#Класс тестирования модуля дешифрования
class TestDecryption:
    #Метод тестирования расшифровки строки
    def test_decryption_str(self, tmp_path):
        test_data = {
            'dir_name':str(tmp_path),
            'sync_key_name':"sync_key.pub",
            'async_private_key_name':"async.pem",
            'async_public_key_name':"async.pub",
            'vectore_name':"vectore.bin",
            'password':"1"
        }
        keys = Keys(**test_data)
        
        keys.run()
        with pytest.raises(TypeError):
            Decryption(["encrypt_text"], **test_data).decryption()
    
    #Метод тестирования расшифровки без ключей
    def test_decryption_none_keys(self, tmp_path):
        test_data = {
            'dir_name':str(tmp_path),
            'sync_key_name':"sync_key.pub",
            'async_private_key_name':"async.pem",
            'async_public_key_name':"async.pub",
            'vectore_name':"vectore.bin",
            'password':"1"
        }
        with pytest.raises(FileNotFoundError):
            Decryption("encrypt_text", **test_data).decryption()