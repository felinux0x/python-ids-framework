# main_ids.py
import yaml
from src import RuleParser, PacketAnalyzer, Sniffer, AlertManager
import sys
import os

def main():
    # Garante que o script está sendo executado com privilégios de administrador
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        import ctypes
        is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)

    if not is_admin:
        print("[ERRO] Este script precisa ser executado com privilégios de Administrador para capturar pacotes.")
        sys.exit(1)

    print("--- Iniciando o Sistema de Detecção de Intrusão Robusto ---")
    
    try:
        with open('ids_config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print("[ERRO] Arquivo de configuração 'ids_config.yaml' não encontrado.")
        return
    except Exception as e:
        print(f"[ERRO] Erro ao ler o arquivo de configuração: {e}")
        return

    alert_manager = AlertManager(config['log_file'])
    
    try:
        parser = RuleParser(config['rules_file'])
        rules = parser.parse()
        print(f"[INFO] {len(rules)} regras carregadas com sucesso de '{config['rules_file']}'.")
    except FileNotFoundError:
        alert_manager.alert(f"Arquivo de regras '{config['rules_file']}' não encontrado. O IDS iniciará sem regras.")
        rules = []
    except Exception as e:
        alert_manager.alert(f"Erro ao processar arquivo de regras: {e}")
        return

    analyzer = PacketAnalyzer(rules, alert_manager)
    interface_to_sniff = config.get('network_interface')

    if not interface_to_sniff:
        print(f"[INFO] Nenhuma interface de rede especificada. Monitorando em todas as interfaces disponíveis.")
    else:
        print(f"[INFO] Monitorando na interface: {interface_to_sniff}")
        
    sniffer = Sniffer(interface_to_sniff, analyzer)
    
    try:
        sniffer.start()
    except KeyboardInterrupt:
        print("\n[INFO] IDS parado pelo usuário. Saindo...")
    except Exception as e:
        print(f"[ERRO CRÍTICO] Ocorreu um erro inesperado: {e}")

if __name__ == "__main__":
    main()