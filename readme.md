#  Asset Discovery Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/yourusername/asset-discovery-tool?style=social)](https://github.com/yourusername/asset-discovery-tool)
[![GitHub Forks](https://img.shields.io/github/forks/yourusername/asset-discovery-tool?style=social)](https://github.com/yourusername/asset-discovery-tool)

**Asset Discovery Tool** é uma ferramenta completa de descoberta de ativos digitais desenvolvida em Python. Ela permite mapear e analisar todos os subdomínios, tecnologias, portas abertas e vulnerabilidades associadas a um domínio alvo.

##  **Sobre o Projeto**

Esta ferramenta foi desenvolvida para profissionais de segurança, pentesters e administradores de sistemas que precisam entender a superfície de ataque de seus domínios. Ela combina múltiplas técnicas de enumeração para fornecer uma visão completa dos ativos digitais expostos.

### ✨ **Características Principais**

| Fase | Módulo | Funcionalidade |
|------|--------|----------------|
| 1 | **Passive Enumeration** | Consulta fontes públicas como crt.sh, AlienVault OTX e Wayback Machine |
| 2 | **Active Bruteforce** | Testa milhares de subdomínios com wordlist integrada |
| 2 | **Technology Detection** | Identifica frameworks, CMS, servidores e bibliotecas |
| 3 | **Port Scanning** | Verifica portas abertas e serviços em execução |
| 3 | **Screenshots** | Captura imagens dos sites encontrados (opcional) |
| 4 | **Takeover Detection** | Identifica subdomínios vulneráveis a takeover |

##  **Instalação**

###  **Pré-requisitos**

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)
- Git (opcional, para clonar)

###  **Passos de Instalação**

```bash
# 1. Clonar o repositório
git clone https://github.com/yourusername/asset-discovery-tool.git
cd asset-discovery-tool

# 2. Criar ambiente virtual (recomendado)
python -m venv venv

# Ativar no Windows
venv\Scripts\activate
# Ativar no Linux/Mac
source venv/bin/activate

# 3. Instalar dependências
pip install -r requirements.txt

# 4. Verificar instalação
python Main.py --help