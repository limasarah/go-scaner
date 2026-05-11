
# 🚀 GoScan-Pro: High-Speed Network Vulnerability Scanner

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Focus-Cybersecurity-red?style=for-the-badge)

O **GoScan-Pro** é uma ferramenta de reconhecimento de rede de alta performance desenvolvida em Go. O diferencial deste projeto é o uso de **Raw Sockets** e manipulação de pacotes na camada 4 (Transporte), permitindo técnicas avançadas de escaneamento que ferramentas de alto nível não alcançam.

---

## 🛠️ Diferenciais Técnicos

*   **⚡ Arquitetura Worker Pool:** Gerenciamento inteligente de concorrência com **Goroutines** e **Channels**, permitindo escanear milhares de portas em segundos sem exaurir os recursos do sistema ou travar a execução.
*   **🕵️ Stealth SYN Scan (Half-Open):** Implementação via `google/gopacket`. O scanner identifica portas abertas sem completar o *three-way handshake*, tornando o processo mais rápido e evitando que a conexão seja registrada por logs de aplicação padrão.
*   **🔍 Banner Grabbing & Fingerprinting:** Após detectar uma porta aberta, a ferramenta realiza a captura do banner do serviço para identificar versões de softwares e sistemas operacionais.
*   **🛡️ Alerta de Portas Críticas:** Base de conhecimento integrada que sinaliza automaticamente portas associadas a serviços vulneráveis (ex: Telnet, SMB, RDP antigo).
*   **📊 Saída Estruturada:** Suporte nativo para exportação em **JSON**, facilitando o pipeline com outras ferramentas de segurança ou análise de dados.

---

└── pkg/
    └── utils/          # Helpers de rede e tratamento de IPs
