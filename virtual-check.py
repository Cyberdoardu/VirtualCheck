import os
import socket
import struct
from datetime import datetime, timezone
import time
import subprocess
import re
import sys

# Lista de prefixos MAC comuns para máquinas virtuais e containers
VIRTUAL_MAC_PREFIXES = {
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5D": "Hyper-V",
    "02:42": "Docker",
    "00:1C:42": "Parallels"
}

# Verifica se o parâmetro "-v" foi passado (modo verbose)
verbose = "-v" in sys.argv

def log_verbose(message):
    """Imprime mensagens no modo verbose"""
    if verbose:
        print(message)

# Função para obter a hora do NTP
def get_ntp_time():
    NTP_SERVER = 'pool.ntp.org'
    NTP_PORT = 123
    NTP_EPOCH = 2208988800
    try:
        log_verbose("Executando consulta ao servidor NTP...")
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5)
        data = b'\x1b' + 47 * b'\0'
        client.sendto(data, (NTP_SERVER, NTP_PORT))
        response, _ = client.recvfrom(1024)
        t = struct.unpack('!12I', response)[10]
        t -= NTP_EPOCH
        return datetime.fromtimestamp(t, tz=timezone.utc)
    except socket.timeout:
        return None

# Primeira requisição NTP
start_time = get_ntp_time()

# Inicializa `out_of_sync` como False
out_of_sync = False

# Função para detectar a frequência da CPU
def get_cpu_clock():
    try:
        log_verbose("Verificando clock da CPU...")
        with open('/proc/cpuinfo') as f:
            for line in f:
                if "cpu MHz" in line:
                    return float(line.split(":")[1].strip())
    except Exception as e:
        return f"Erro ao detectar o clock da CPU: {e}"

# Função para obter informações de memória
def get_memory_info():
    try:
        log_verbose("Obtendo informações de memória...")
        with open('/proc/meminfo') as f:
            meminfo = f.readlines()
        mem_total = int([line for line in meminfo if "MemTotal" in line][0].split(":")[1].strip().split()[0]) // 1024
        mem_free = int([line for line in meminfo if "MemFree" in line][0].split(":")[1].strip().split()[0]) // 1024
        return mem_total, mem_free
    except Exception as e:
        return f"Erro ao detectar a memória RAM: {e}"

# Função para verificar hypervisor no /proc/cpuinfo
def check_hypervisor():
    try:
        log_verbose("Verificando hypervisor...")
        with open('/proc/cpuinfo') as f:
            return any("hypervisor" in line.lower() for line in f)
    except Exception as e:
        return f"Erro ao verificar hypervisor: {e}"

# Função para verificar o ambiente virtual usando systemd e dmesg
def is_virtual_environment():
    try:
        log_verbose("Verificando ambiente virtual com systemd-detect-virt e dmesg...")
        result = subprocess.run(['systemd-detect-virt'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stdout.decode().strip() != 'none':
            return True, result.stdout.decode().strip()  # Retorna o tipo de VM/container detectado
        dmesg_result = subprocess.run(['dmesg'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if b'hypervisor' in dmesg_result.stdout.lower() or b'virtual' in dmesg_result.stdout.lower():
            return True, 'Hypervisor'
        return False, None
    except Exception as e:
        print(f"Erro ao verificar ambiente virtual: {e}")
        return False, None

# Função para verificar prefixo de MAC associado a VMs/containers
def is_virtual_mac():
    try:
        log_verbose("Verificando MAC para identificar VMs ou containers...")
        result = subprocess.run(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        mac_addresses = re.findall(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        for mac in mac_addresses:
            mac_prefix = mac[0][:8]
            if mac_prefix.lower() in VIRTUAL_MAC_PREFIXES:
                return True, VIRTUAL_MAC_PREFIXES[mac_prefix.lower()]  # Retorna a fonte da VM/container
        return False, None
    except Exception as e:
        print(f"Erro ao verificar endereços MAC: {e}")
        return False, None

# Função para verificar se a tabela ARP está vazia
def is_empty_arp_table():
    try:
        log_verbose("Verificando se a tabela ARP está vazia...")
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp") as f:
                arp_table = f.readlines()
            return len(arp_table) <= 1  # Se houver apenas o cabeçalho
        return False
    except Exception as e:
        print(f"Erro ao verificar a tabela ARP: {e}")
        return False

# Função para verificar se é um ambiente Docker
def is_docker_environment():
    log_verbose("Verificando se é um ambiente Docker...")
    return os.path.exists("/.dockerenv")

# Função para verificar se o comando sudo está disponível
def is_sudo_available():
    try:
        log_verbose("Verificando se o comando sudo está disponível...")
        result = subprocess.run(['sudo', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except FileNotFoundError:
        return False

# Função para verificar se há usuários logados
def has_logged_in_users():
    try:
        log_verbose("Verificando se há usuários logados...")
        result = subprocess.run(['w'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode().strip()
        lines = output.splitlines()
        return len(lines) > 2  # Mais de duas linhas indica que há usuários logados
    except Exception as e:
        print(f"Erro ao verificar usuários logados: {e}")
        return False

# Função principal para gerar o relatório
def generate_report():
    report = {}
    reasons = []  # Lista para armazenar os motivos que indicam VM/container
    vm_type = None  # Armazena o tipo de VM ou container

    # Verificação de ambiente virtual
    is_virtual, vm_detected = is_virtual_environment()
    report['Ambiente Virtual'] = is_virtual
    if is_virtual:
        reasons.append('Ambiente Virtual Detectado')
        vm_type = vm_detected

    # Verificação de MAC virtual
    mac_virtual, mac_source = is_virtual_mac()
    report['MAC Virtual'] = mac_virtual
    if mac_virtual:
        reasons.append('MAC Virtual Detectado')
        vm_type = mac_source

    # Verificação da tabela ARP
    arp_empty = is_empty_arp_table()
    report['Tabela ARP Vazia'] = arp_empty
    if arp_empty:
        reasons.append('Tabela ARP Vazia')

    # Verificação de Docker
    is_docker = is_docker_environment()
    report['Docker'] = is_docker
    if is_docker:
        reasons.append('Ambiente Docker Detectado')
        vm_type = 'Docker'

    # Verificação de sudo
    sudo_available = is_sudo_available()
    report['Sudo Disponível'] = sudo_available
    if not sudo_available:
        reasons.append('Sudo Não Disponível')

    # Verificação de usuários logados
    users_logged = has_logged_in_users()
    report['Usuários Logados'] = users_logged
    if not users_logged:
        reasons.append('Nenhum Usuário Logado')

    # Detecção de hypervisor
    hypervisor_detected = check_hypervisor()
    report['Hypervisor Detectado'] = hypervisor_detected
    if hypervisor_detected:
        reasons.append('Hypervisor Detectado')

    # Número de núcleos da CPU
    num_cores = os.cpu_count()
    report['Número de Cores da CPU'] = num_cores
    if num_cores < 3:
        reasons.append('Poucos Núcleos de CPU')

    # Clock da CPU
    cpu_clock = get_cpu_clock()
    report['Clock da CPU (MHz)'] = cpu_clock
    if isinstance(cpu_clock, float) and cpu_clock < 1000:
        reasons.append('Clock da CPU Baixo')

    # Memória Total e Livre
    mem_total, mem_free = get_memory_info()
    report['Memória Total (MB)'] = mem_total
    report['Memória Livre (MB)'] = mem_free
    if mem_total is not None and mem_total < 2048:
        reasons.append('Pouca Memória RAM')

    # Segunda requisição NTP
    global tempo
    end_time = get_ntp_time()

    if start_time and end_time:
        elapsed_time = (end_time - start_time).total_seconds()
        out_of_sync = elapsed_time > (tempo + 1) or elapsed_time < (tempo - 1)
        print(f"Tempo decorrido: {elapsed_time} segundos, esperado: {tempo} segundos. (Tolerância: ±1 segundo)")
        print(f"Tempo fora de sincronização: {out_of_sync}")
        if out_of_sync:
            print("Indício de ambiente virtualizado: Tempo fora de sincronização (modo debug).")
            reasons.append('Tempo Fora de Sincronização')

    return report, reasons, vm_type

# Função para exibir o relatório
def print_report(report, reasons, vm_type):
    print("\n--- Relatório de Ambiente ---")
    for key, value in report.items():
        print(f"{key}: {value}")
    print("\n--- Resultados ---")
    if reasons:
        print("Motivos para considerar o sistema como VM/Container:")
        for reason in reasons:
            print(f"- {reason}")
        if vm_type:
            print(f"Tipo de Máquina Virtual/Container: {vm_type}")
    else:
        print("Nenhum indício de ambiente virtual ou container foi encontrado.")
    print("----------------------------")

# Configura o tempo de espera entre as requisições NTP
tempo = 15
time.sleep(tempo)


# Gera e exibe o relatório
report, reasons, vm_type = generate_report()
print_report(report, reasons, vm_type)

# Verifica se o sistema está rodando em VM ou container
if reasons or out_of_sync:
    print("\nO sistema está rodando em uma máquina virtual ou container.")
else:
    print("\nO sistema está rodando em um host físico.")
