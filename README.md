# Python IDS - Sistema de Detecção de Intrusão Baseado em Regras

Um sistema de detecção de intrusão (IDS) robusto e configurável, escrito em Python, que monitora o tráfego de rede em tempo real e dispara alertas com base em um conjunto de regras personalizáveis. Este projeto foi desenvolvido para fins educacionais e para demonstrar habilidades em cibersegurança defensiva, programação de redes com Scapy e engenharia de software em Python.

## Funcionalidades Principais

- **Motor de Regras Flexível:** Carrega regras de um arquivo externo (`.rules`) com uma sintaxe inspirada no Snort.
- **Análise de Pacotes:** Utiliza a biblioteca Scapy para capturar e analisar pacotes de rede em baixo nível.
- **Configuração Externa:** Todas as configurações principais (interface de rede, arquivos de log e regras) são gerenciadas em um arquivo `ids_config.yaml`.
- **Alertas e Logs:** Registra todos os alertas detectados em um arquivo de log formatado com data, hora e detalhes da ameaça.
- **Estrutura Modular:** O código é organizado em módulos com responsabilidades claras (Sniffer, Analisador, Parser de Regras, etc.).

## Pré-requisitos

- Python 3.8+
- `pip` (gerenciador de pacotes do Python)
- **Para Windows:** [Npcap](https://npcap.com/) deve ser instalado para permitir a captura de pacotes (durante a instalação, marque a opção "Install Npcap in WinPcap API-compatible Mode").

## Instalação e Execução

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git](https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git)
    cd SEU-REPOSITORIO
    ```

2.  **Crie e ative um ambiente virtual:**
    ```bash
    # Criar o ambiente
    python -m venv venv

    # Ativar no Windows (PowerShell)
    .\venv\Scripts\activate
    ```

3.  **Instale as dependências:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Execute o IDS (com privilégios de Administrador):**
    Abra um novo terminal **como Administrador**, ative o ambiente virtual novamente e execute o script principal.
    ```powershell
    python main_ids.py
    ```
    O IDS começará a monitorar a rede.

## Como Usar e Testar

O sistema detecta ameaças com base nas regras definidas em `rules/local.rules`. Para testar se o IDS está funcionando, você pode gerar tráfego de rede que corresponda a uma das regras.

Por exemplo, para testar a regra de detecção de `ping` (ICMP):
1.  Deixe o IDS rodando em um terminal.
2.  Abra um **novo** terminal.
3.  Execute o comando:
    ```bash
    ping google.com
    ```
4.  Observe o alerta aparecer em tempo real no terminal do IDS.

## Aviso Legal

Este projeto foi criado estritamente para fins educacionais. A utilização desta ferramenta em redes ou sistemas sem autorização prévia e explícita é ilegal. O autor não se responsabiliza pelo mau uso do código.