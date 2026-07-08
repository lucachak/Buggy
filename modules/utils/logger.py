import logging
import os
from pathlib import Path

class BuggyLogger:
    def __init__(self):
        self.logger = logging.getLogger("buggy")
        self.logger.setLevel(logging.DEBUG)
        
        # Formatador para console (clean, apenas INFO/WARNING/ERROR)
        self.console_formatter = logging.Formatter('%(message)s')
        self.console_handler = logging.StreamHandler()
        self.console_handler.setLevel(logging.INFO)
        self.console_handler.setFormatter(self.console_formatter)
        
        # Evita handlers duplicados
        if not self.logger.handlers:
            self.logger.addHandler(self.console_handler)
            
        self.file_handler = None

    def setup_file_logging(self, output_dir: str):
        """Configura o log detalhado em arquivo dentro do diretório de output."""
        log_dir = Path(output_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "buggy.log"
        
        file_formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        self.file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        self.file_handler.setLevel(logging.DEBUG)
        self.file_handler.setFormatter(file_formatter)
        
        self.logger.addHandler(self.file_handler)
        self.info(f"Detailed logging initialized at {log_file}")

    def debug(self, msg: str):
        self.logger.debug(msg)
        
    def info(self, msg: str):
        self.logger.info(msg)
        
    def warning(self, msg: str):
        self.logger.warning(f"\033[93m[!] {msg}\033[0m")
        
    def error(self, msg: str):
        self.logger.error(f"\033[91m[X] {msg}\033[0m")


# Singleton instance
buggy_logger = BuggyLogger()
