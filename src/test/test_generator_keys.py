from pathlib import Path
from src.crypto.generator_keys import Keys

#Класс тестирования генерации ключей
class TestGeneratorKeys:
    #Метод теста на создание директорий
    def test_create_dir(self, tmp_path):
        keys = Keys(
            dir_name=str(tmp_path),
            sync_key_name="sync_key.pub",
            async_private_key_name="async.pem",
            async_public_key_name="async.pub",
            vectore_name="vectore.bin",
            password=""
        )
        
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