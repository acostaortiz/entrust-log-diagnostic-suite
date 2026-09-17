#!/usr/bin/env bash
# ==============================================================================
#  IT SERVICIOS DE VENEZUELA, S.A.
#  GESTOR Y SINCRONIZADOR ENTERPRISE DE PROYECTOS GITHUB
#  Desarrollado por: Ing. TomÃ¡s Acosta â€” Ciberseguridad & TI
#  Plataforma: Ubuntu 22.04 LTS
# ==============================================================================

NC='\033[0m'
BOLD='\033[1m'
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'

DIR_PORTAL="/var/www/entrust-admin-portal"
DIR_DIAGNOSTIC="/var/www/entrust-log-diagnostic-suite"
LOG_FILE="$HOME/.it_servicios_sync.log"

SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="10.16.13.175"
fi

git config --global --add safe.directory '*' 2>/dev/null || true

log_event() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" >> "$LOG_FILE"
}

check_git_status() {
    local dir="$1"
    if [ ! -d "$dir/.git" ] && [ ! -d "$dir" ]; then
        printf "${RED}?? (Directorio no encontrado)${NC}\n"
        return
    fi

    cd "$dir" 2>/dev/null || return
    git fetch origin >/dev/null 2>&1

    local branch="master"
    if ! git rev-parse --verify origin/master >/dev/null 2>&1; then
        branch="main"
    fi

    local behind=$(git rev-list --count HEAD..origin/$branch 2>/dev/null || echo 0)
    if [ "$behind" -gt 0 ]; then
        printf "${RED}${BOLD}?? Â¡%s nuevo(s) cambio(s) en GitHub!${NC}\n" "$behind"
    else
        printf "${GREEN}?? Al dÃ­a con GitHub${NC}\n"
    fi
}

print_header() {
    clear
    printf "${BLUE}${BOLD}================================================================================${NC}\n"
    printf "${CYAN}${BOLD}   ?? IT SERVICIOS DE VENEZUELA, S.A. | GESTOR ENTERPRISE DE PROYECTOS GITHUB${NC}\n"
    printf "${YELLOW}   Servidor: Ubuntu 22.04 LTS  |  IP Oficial: ${WHITE}${BOLD}%s${NC}\n" "$SERVER_IP"
    printf "${BLUE}${BOLD}================================================================================${NC}\n"
}

print_line() {
    printf "${BLUE}--------------------------------------------------------------------------------${NC}\n"
}

sync_portal() {
    printf "\n${CYAN}${BOLD}?? Sincronizando: entrust-admin-portal...${NC}\n"
    print_line
    if [ -d "$DIR_PORTAL" ]; then
        cd "$DIR_PORTAL" || return
        git fetch origin

        local branch="master"
        if ! git rev-parse --verify origin/master >/dev/null 2>&1; then branch="main"; fi

        git checkout "$branch" >/dev/null 2>&1 || true
        git reset --hard "origin/$branch"

        if [ $? -eq 0 ]; then
            php artisan optimize:clear >/dev/null 2>&1 || true
            sudo chown -R www-data:www-data "$DIR_PORTAL" >/dev/null 2>&1 || true
            sudo chmod -R 775 storage bootstrap/cache >/dev/null 2>&1 || true

            local commit_msg=$(git log -1 --pretty=format:"%h - %s (%cr)")
            printf "${GREEN}${BOLD}? entrust-admin-portal actualizado con Ã©xito.${NC}\n"
            printf "${WHITE}   Commit Desplegado: %s${NC}\n" "$commit_msg"
            printf "${YELLOW}   ?? Apache: http://%s/entrust-admin-portal/public/banking-simulator${NC}\n" "$SERVER_IP"
            log_event "SUCCESS: Portal actualizado -> $commit_msg"
        fi
    else
        printf "${RED}? No se encontrÃ³ $DIR_PORTAL${NC}\n"
    fi
}

sync_diagnostic() {
    printf "\n${CYAN}${BOLD}??? Sincronizando: entrust-log-diagnostic-suite...${NC}\n"
    print_line
    if [ -d "$DIR_DIAGNOSTIC" ]; then
        cd "$DIR_DIAGNOSTIC" || return
        git fetch origin

        local branch="master"
        if ! git rev-parse --verify origin/master >/dev/null 2>&1; then branch="main"; fi

        git checkout "$branch" >/dev/null 2>&1 || true
        git reset --hard "origin/$branch"

        if [ $? -eq 0 ]; then
            sudo chmod -R 777 "$DIR_DIAGNOSTIC" >/dev/null 2>&1 || true

            local commit_msg=$(git log -1 --pretty=format:"%h - %s (%cr)")
            printf "${GREEN}${BOLD}? entrust-log-diagnostic-suite actualizado con Ã©xito.${NC}\n"
            printf "${WHITE}   Commit Desplegado: %s${NC}\n" "$commit_msg"
            log_event "SUCCESS: Suite de Diagnostico actualizada -> $commit_msg"
        fi
    else
        printf "${RED}? No se encontrÃ³ $DIR_DIAGNOSTIC${NC}\n"
    fi
}

start_portal_8000() {
    printf "\n${CYAN}${BOLD}? Levantando Portal Laravel en Puerto 8000...${NC}\n"
    print_line
    sudo ufw allow 8000/tcp >/dev/null 2>&1 || true
    sudo fuser -k 8000/tcp >/dev/null 2>&1 || true

    if [ -d "$DIR_PORTAL" ]; then
        cd "$DIR_PORTAL" || return
        nohup php artisan serve --host=0.0.0.0 --port=8000 >/dev/null 2>&1 &
        sleep 1
        printf "${GREEN}${BOLD}? Portal Laravel ACTIVO en el puerto 8000.${NC}\n\n"
        printf "${WHITE}   ?? Simulador Bancario: ${CYAN}http://%s:8000/banking-simulator${NC}\n" "$SERVER_IP"
        printf "${WHITE}   ?? GestiÃ³n de Usuarios: ${CYAN}http://%s:8000/users${NC}\n" "$SERVER_IP"
        printf "${WHITE}   ?? Laboratorio Accesos: ${CYAN}http://%s:8000/login-test${NC}\n" "$SERVER_IP"
    else
        printf "${RED}? No se encontrÃ³ la carpeta $DIR_PORTAL.${NC}\n"
    fi
}

start_server_8085() {
    printf "\n${CYAN}${BOLD}? Levantando Suite de DiagnÃ³stico en Puerto 8085...${NC}\n"
    print_line
    sudo ufw allow 8085/tcp >/dev/null 2>&1 || true
    sudo fuser -k 8085/tcp >/dev/null 2>&1 || true

    if [ -d "$DIR_DIAGNOSTIC" ]; then
        cd "$DIR_DIAGNOSTIC" || return
        sudo kill -9 $(sudo lsof -t -i:8085 2>/dev/null) 2>/dev/null || true
        sudo fuser -k 8085/tcp >/dev/null 2>&1 || true
        sleep 1
        if [ -f "server.py" ]; then
            nohup python3 server.py > server_8085.log 2>&1 &
        else
            nohup python3 -m http.server 8085 --bind 0.0.0.0 >/dev/null 2>&1 &
        fi
        sleep 1
        printf "${GREEN}${BOLD}? Suite de DiagnÃ³stico activa en el puerto 8085.${NC}\n"
        printf "${YELLOW}   ?? Abre: http://%s:8085/${NC}\n" "$SERVER_IP"
    else
        printf "${RED}? No se encontrÃ³ $DIR_DIAGNOSTIC.${NC}\n"
    fi
}

while true; do
    print_header
    printf "${WHITE}${BOLD}Estado de SincronizaciÃ³n en Tiempo Real con GitHub:${NC}\n"
    print_line

    printf "  â€¢ ${BOLD}entrust-admin-portal${NC}:        "
    check_git_status "$DIR_PORTAL"

    printf "  â€¢ ${BOLD}entrust-log-diagnostic-suite${NC}: "
    check_git_status "$DIR_DIAGNOSTIC"

    print_line
    printf "${WHITE}${BOLD}Opciones Disponibles:${NC}\n\n"
    printf "  ${CYAN}[1]${NC} ?? Sincronizar: ${BOLD}entrust-admin-portal${NC}\n"
    printf "  ${CYAN}[2]${NC} ??? Sincronizar: ${BOLD}entrust-log-diagnostic-suite${NC}\n"
    printf "  ${CYAN}[3]${NC} ?? Sincronizar AMBOS Proyectos\n"
    printf "  ${CYAN}[4]${NC} ?? Activar Portal Laravel en ${BOLD}Puerto 8000${NC}\n"
    printf "  ${CYAN}[5]${NC} ? Activar Suite DiagnÃ³stico en ${BOLD}Puerto 8085${NC}\n"
    printf "  ${CYAN}[6]${NC} ?? Ver Historial de Sincronizaciones\n"
    printf "  ${CYAN}[7]${NC} ?? Salir\n"
    print_line

    read -rp "Ingresa tu opciÃ³n [1-7]: " opt

    case $opt in
        1) sync_portal; read -rp $'\nPresiona [Enter] para continuar...' ;;
        2) sync_diagnostic; read -rp $'\nPresiona [Enter] para continuar...' ;;
        3) sync_portal; sync_diagnostic; read -rp $'\nPresiona [Enter] para continuar...' ;;
        4) start_portal_8000; read -rp $'\nPresiona [Enter] para continuar...' ;;
        5) start_server_8085; read -rp $'\nPresiona [Enter] para continuar...' ;;
        6)
            print_header
            printf "${CYAN}${BOLD}?? HISTORIAL AUDITADO DE SINCRONIZACIONES${NC}\n"
            print_line
            if [ -f "$LOG_FILE" ]; then tail -n 15 "$LOG_FILE"; else printf "${YELLOW}Sin registros aÃºn.${NC}\n"; fi
            print_line
            read -rp $'\nPresiona [Enter] para continuar...'
            ;;
        7) printf "\n${GREEN}${BOLD}Â¡Hasta luego, TomÃ¡s! OperaciÃ³n finalizada.${NC}\n\n"; exit 0 ;;
        *) printf "\n${RED}OpciÃ³n invÃ¡lida.${NC}\n"; sleep 1.5 ;;
    esac
done
