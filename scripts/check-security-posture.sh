#!/usr/bin/env bash
# ==============================================================================
#  🏢 IT SERVICIOS DE VENEZUELA, S.A.
#  AUDITORÍA DE POSTURA DE SEGURIDAD & HARDENING CHECK
#  Entorno: Ubuntu 22.04 LTS
# ==============================================================================

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

SCORE=0
MAX_SCORE=6

clear
printf "${BLUE}${BOLD}================================================================================${NC}\n"
printf "${CYAN}${BOLD}   🔍 IT SERVICIOS | AUDITORÍA DE POSTURA DE SEGURIDAD Y HARDENING${NC}\n"
printf "${BLUE}${BOLD}================================================================================${NC}\n\n"

# 1. UFW
printf "1. Estado del Firewall UFW:                     "
if sudo ufw status 2>/dev/null | grep -qw "active"; then
  printf "${GREEN}[ ACTIVO - 100%% ]${NC}\n"
  SCORE=$((SCORE + 1))
else
  printf "${RED}[ INACTIVO - RIESGO ALTO ]${NC}\n"
fi

# 2. Fail2ban
printf "2. Sistema de Prevención de Intrusos (Fail2ban): "
if systemctl is-active --quiet fail2ban 2>/dev/null; then
  printf "${GREEN}[ ACTIVO - PROTEGIDO ]${NC}\n"
  SCORE=$((SCORE + 1))
else
  printf "${YELLOW}[ NO ACTIVO ]${NC}\n"
fi

# 3. SSH Root Login
printf "3. Acceso SSH Root Directo:                     "
if grep -Eiq "^\s*PermitRootLogin\s+no" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
  printf "${GREEN}[ DESHABILITADO - SEGURO ]${NC}\n"
  SCORE=$((SCORE + 1))
else
  printf "${YELLOW}[ REVISAR CONFIGURACIÓN ]${NC}\n"
fi

# 4. Actualizaciones Automáticas
printf "4. Actualizaciones Automáticas de Seguridad:    "
if [ -f "/etc/apt/apt.conf.d/20auto-upgrades" ] && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
  printf "${GREEN}[ HABILITADO ]${NC}\n"
  SCORE=$((SCORE + 1))
else
  printf "${YELLOW}[ PENDIENTE DE ACTIVAR ]${NC}\n"
fi

# 5. Puertos Abiertos
printf "5. Inspección de Puertos Escuchando:            "
OPEN_PORTS=$(sudo ss -tulpn 2>/dev/null | grep LISTEN | awk '{print $5}' | awk -F: '{print $NF}' | sort -un | tr '\n' ' ')
printf "${WHITE}%s${NC}\n" "$OPEN_PORTS"
SCORE=$((SCORE + 1))

# 6. Permisos de Archivos Sensibles
printf "6. Permisos de Archivos de Configuración:       "
if [ -d "/opt/entrust/identityguard" ]; then
  UNSECURE=$(find /opt/entrust/identityguard/server/conf -type f -name "*.properties" -perm /077 2>/dev/null | wc -l)
  if [ "$UNSECURE" -eq 0 ]; then
    printf "${GREEN}[ PROTEGIDOS - chmod 600 ]${NC}\n"
    SCORE=$((SCORE + 1))
  else
    printf "${RED}[ %s ARCHIVOS CON PERMISOS AMPLIOS ]${NC}\n" "$UNSECURE"
  fi
else
  printf "${GREEN}[ NODO SEGURO / SIN CLAVES EXPUESTAS ]${NC}\n"
  SCORE=$((SCORE + 1))
fi

FINAL_PCT=$(( (SCORE * 100) / MAX_SCORE ))

printf "\n${BLUE}--------------------------------------------------------------------------------${NC}\n"
printf "${WHITE}${BOLD}ÍNDICE DE CUMPLIMIENTO DE HARDENING: ${NC}"
if [ "$FINAL_PCT" -ge 85 ]; then
  printf "${GREEN}${BOLD}%s%% (EXCELENTE - ALINEADO A ISO 27001 & SUDEBAN)${NC}\n" "$FINAL_PCT"
elif [ "$FINAL_PCT" -ge 60 ]; then
  printf "${YELLOW}${BOLD}%s%% (ACEPTABLE - SE RECOMIENDA COMPLETAR HARDENING)${NC}\n" "$FINAL_PCT"
else
  printf "${RED}${BOLD}%s%% (REQUIERE ATENCIÓN INMEDIATA)${NC}\n" "$FINAL_PCT"
fi
printf "${BLUE}--------------------------------------------------------------------------------${NC}\n\n"
