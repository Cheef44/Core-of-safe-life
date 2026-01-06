from pathlib import Path
from src.crypto.generator_keys import Keys
import pytest

#Класс тестирования генерации ключей
class TestGeneratorKeys:
    #Метод теста на пустой пароль
    def test_blank_password(self, tmp_path):
        keys = Keys(
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin",
            password=""
        )
        with pytest.raises(ValueError):
            keys.run()
        assert (Path(tmp_path / "sync_key.pub")).exists()
        assert (Path(tmp_path / "async.pem")).exists()
        assert (Path(tmp_path / "async.pub")).exists()
        assert (Path(tmp_path / "vectore.bin")).exists()
    
    #Метод теста на заполнение файлов
    def test_file_filling(self, tmp_path):
        keys = Keys(
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin",
            password="1234"
        )
        
        keys.run()
        assert (Path(tmp_path / "sync_key.pub")).stat().st_size > 0
        assert (Path(tmp_path / "async.pem")).stat().st_size > 0
        assert (Path(tmp_path / "async.pub")).stat().st_size > 0
        assert (Path(tmp_path / "vectore.bin")).stat().st_size == 16
    
    #Метод теста на создание ключей без шифрования синхронного ключа
    def test_no_encrypt_sync_key(self, tmp_path):
        keys = Keys(
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin",
        )
        
        keys.gen_sync_key()
        keys.gen_async_key()
        keys.vectore()
        assert (Path(tmp_path / "sync_key.pub")).stat().st_size > 0
        assert (Path(tmp_path / "async.pem")).stat().st_size > 0
        assert (Path(tmp_path / "async.pub")).stat().st_size > 0
        assert (Path(tmp_path / "vectore.bin")).stat().st_size == 16