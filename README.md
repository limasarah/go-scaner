# 🚀 Scaner de portas abertas 

## 📝 Descrição do Projeto
Este projeto é um **Scanner de Vulnerabilidades e Portas** desenvolvido em linguagem **Go**. Ele foi criado como parte dos meus estudos em redes e segurança cibernética, com foco em entender como a comunicação de baixo nível acontece entre dispositivos.

O diferencial deste scanner é o uso de **Goroutines** para velocidade extrema e a biblioteca **Gopacket** para realizar scans do tipo "Stealth" (SYN Scan), que são mais discretos que conexões comuns.

---

## 🧐 Glossário e Conceitos Estudados
Para desenvolver este projeto, estudei e implementei os seguintes conceitos técnicos:

*   **TCP SYN Scan (Half-Open):** Diferente do `net.Dial` comum, aqui enviamos apenas o primeiro pacote do aperto de mão TCP. Se o alvo responde, sabemos que está aberto sem precisar completar a conexão.
*   **Worker Pool Pattern:** Técnica em Go para gerenciar centenas de tarefas (scans de portas) simultaneamente sem travar o processador.
*   **Banner Grabbing:** Técnica para ler a mensagem de boas-vindas de um serviço (ex: descobrir que um servidor é um "Apache 2.4.5") após a conexão ser estabelecida.
*   **Raw Sockets:** Manipulação de pacotes diretamente na placa de rede, pulando as proteções padrão do sistema operacional.

---

## 🛠️ Tecnologias e Dependências
*   **Linguagem:** [Go 1.2x]
*   **Principais Pacotes:**
    *   `github.com/google/gopacket`: Manipulação de pacotes brutos.
    *   `net`: Funções base de rede.
    *   `flag`: Para criação da interface de linha de comando (CLI).

---

## 💻 Manual de Instalação e Uso

### 1. Pré-requisitos
O projeto depende da biblioteca `pcap` (usada pelo Wireshark) para capturar pacotes:
*   **Linux:** `sudo apt install libpcap-dev`
*   **Windows:** Instale o [Npcap](https://nmap.org/npcap/) em modo de compatibilidade WinPcap.
*   **macOS:** `brew install libpcap`

### 2. Configuração do Ambiente
```bash
# Clone o repositório
git clone [https://github.com/](https://github.com/)[seu-usuario]/[nome-do-repositorio].git

# Instale as dependências de Go
go mod tidy
