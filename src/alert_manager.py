# src/alert_manager.py
import logging

class AlertManager:
    def __init__(self, log_file):
        self.logger = logging.getLogger('IDS_Logger')
        self.logger.setLevel(logging.INFO)
        
        # Evita adicionar handlers duplicados se a classe for instanciada várias vezes
        if not self.logger.handlers:
            # Handler para o arquivo de log
            file_handler = logging.FileHandler(log_file)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            
            # Handler para o console
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter('%(levelname)s: %(message)s')
            console_handler.setFormatter(console_formatter)
            
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)

    def alert(self, message):
        self.logger.warning(message)