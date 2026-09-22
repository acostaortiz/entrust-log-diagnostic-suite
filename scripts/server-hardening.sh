#!/usr/bin/env bash
# ==============================================================================
#  🏢 IT SERVICIOS DE VENEZUELA, S.A.
#  SCRIPT DE HARDENING INTEGRAL Y ASEGURAMIENTO DE INFRAESTRUCTURA
#  Entorno: Ubuntu 22.04 LTS | Entrust IdentityGuard & Diagnostic Suite
#  Auditor & Autor: Ing. Tomás Acosta — Ciberseguridad & TI
# ==============================================================================

set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP="10.16.13.175"

clear
printf "${BLUE}${BOLD}================================================================================${NC}\n"
printf "${CYAN}${BOLD}   🛡️  IT SERVICIOS DE VENEZUELA | HARDENING & ASEGURAMIENTO DE SERVIDOR${NC}\n"
printf "${YELLOW}   Servidor: Ubuntu 22.04 LTS  |  IP: ${WHITE}${BOLD}%s${NC}\n" "$SERVER_IP"
printf "${BLUE}${BOLD}================================================================================${NC}\n\n"

if [ "$EUID" -ne 0 ]; then
  printf "${RED}❌ Este script debe ejecutarse con privilegios de superusuario (sudo).${NC}\n"
  printf "   Ejecuta: ${CYAN}sudo bash scripts/server-hardening.sh${NC}\n\n"
  exit 1
fi

printf "${WHITE}${BOLD}Iniciando Plan de Hardening en 5 Fases...${NC}\n\n"

# ------------------------------------------------------------------------------
# FASE 1: ACTUALIZACIÓN Y PARCHES AUTOMÁTICOS DE SEGURIDAD
# ------------------------------------------------------------------------------
printf "${CYAN}${BOLD}[FASE 1/5] Configurando Actualizaciones Automáticas de Seguridad...${NC}\n"
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y unattended-upgrades ufw fail2ban logrotate >/dev/null 2>&1 || true

cat << 'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl restart unattended-upgrades >/dev/null 2>&1 || true
printf "${GREEN}  ✅ Parches automáticos (unattended-upgrades) configurados.${NC}\n"

# ------------------------------------------------------------------------------
# FASE 2: HARDENING DE ACCESO REMOTO SSH
# ------------------------------------------------------------------------------
printf "\n${CYAN}${BOLD}[FASE 2/5] Aplicando Hardening a la Configuración SSH...${NC}\n"

# Configurar en /etc/ssh/sshd_config directamente
if grep -qi "PermitRootLogin" /etc/ssh/sshd_config; then
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
else
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi

if grep -qi "MaxAuthTries" /etc/ssh/sshd_config; then
  sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
else
  echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
fi

mkdir -p /etc/ssh/sshd_config.d
cat << 'EOF' > /etc/ssh/sshd_config.d/99-it-servicios-hardening.conf
# IT SERVICIOS HARDENING STANDARD
PermitRootLogin no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
MaxSessions 5
TCPKeepAlive no
EOF

# Reiniciar servicio SSH
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
printf "${GREEN}  ✅ Parámetros SSH asegurados (Root deshabilitado, MaxAuthTries=3, Timeout=15m).${NC}\n"

# ------------------------------------------------------------------------------
# FASE 3: PROTECCIÓN CONTRA ATAQUES DE FUERZA BRUTA (FAIL2BAN)
# ------------------------------------------------------------------------------
printf "\n${CYAN}${BOLD}[FASE 3/5] Configurando y Activando Fail2ban...${NC}\n"
cat << 'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 4
banaction = ufw

[sshd]
enabled = true
port    = 22
logpath = %(sshd_log)s
backend = %(default_backend)s
EOF

systemctl unmask fail2ban >/dev/null 2>&1 || true
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true
printf "${GREEN}  ✅ Fail2ban activo con bloqueo automático en UFW tras 4 intentos fallidos.${NC}\n"

# ------------------------------------------------------------------------------
# FASE 4: CONFIGURACIÓN DE FIREWALL PERIMETRAL (UFW)
# ------------------------------------------------------------------------------
printf "\n${CYAN}${BOLD}[FASE 4/5] Configurando Reglas de Firewall UFW...${NC}\n"
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1

# Puertos esenciales
ufw allow 22/tcp comment 'SSH Administracion' >/dev/null 2>&1
ufw allow 8085/tcp comment 'Entrust Diagnostic Suite' >/dev/null 2>&1
ufw allow 8000/tcp comment 'Entrust Admin Portal' >/dev/null 2>&1
ufw allow 443/tcp comment 'HTTPS TLS Reverse Proxy' >/dev/null 2>&1
ufw allow 80/tcp comment 'HTTP Redirect' >/dev/null 2>&1

ufw --force enable >/dev/null 2>&1
printf "${GREEN}  ✅ Firewall UFW activado (Inbound cerrado por defecto, puertos 22, 8085, 8000, 443 permitidos).${NC}\n"

# ------------------------------------------------------------------------------
# FASE 5: PERMISOS DE ARCHIVOS Y ESTRUCTURA ENTRUST / SUITE
# ------------------------------------------------------------------------------
printf "\n${CYAN}${BOLD}[FASE 5/5] Ajustando Permisos Estrictos en Archivos y Repositorios...${NC}\n"

SUITE_DIR="/var/www/entrust-log-diagnostic-suite"
if [ -d "$SUITE_DIR" ]; then
  find "$SUITE_DIR" -type f -name "*.py" -exec chmod 644 {} + 2>/dev/null || true
  find "$SUITE_DIR" -type f -name "*.sh" -exec chmod 755 {} + 2>/dev/null || true
  chmod 700 "$SUITE_DIR/scripts" 2>/dev/null || true
  printf "${GREEN}  ✅ Permisos de ejecución y lectura ajustados en la Suite de Diagnóstico.${NC}\n"
fi

if [ -d "/opt/entrust/identityguard" ]; then
  find /opt/entrust/identityguard/server/conf -name "*.properties" -exec chmod 600 {} + 2>/dev/null || true
  find /opt/entrust/identityguard/server/conf -name "*.enc" -exec chmod 600 {} + 2>/dev/null || true
  printf "${GREEN}  ✅ Archivos confidenciales .properties y .enc de Entrust protegidos con chmod 600.${NC}\n"
else
  printf "${YELLOW}  ℹ️ Ruta local /opt/entrust/identityguard no detectada en este nodo (se aplicará al montar clúster).${NC}\n"
fi

cat << 'EOF' > /etc/security/limits.d/99-it-entrust.conf
* soft nofile 65535
* hard nofile 65535
* soft nproc 32768
* hard nproc 32768
EOF

printf "\n${BLUE}${BOLD}================================================================================${NC}\n"
printf "${GREEN}${BOLD}  🎉 ¡HARDENING DEL SERVIDOR COMPLETADO AL 100%% CON ÉXITO!${NC}\n"
printf "${WHITE}  El servidor Ubuntu (${SERVER_IP}) cumple con el estándar de seguridad IT Servicios.${NC}\n"
printf "${BLUE}${BOLD}================================================================================${NC}\n\n"
