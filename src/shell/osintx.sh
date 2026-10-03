#!/usr/bin/env bash
#
# OSINT-X :: menu principal (shell)
# 01 DOMAIN | 02 PORTSCAN | 03 SUBDOMAIN | 04 PHONE | 05 USERNAME |
# 06 IPINFO | 07 EMAIL | 08 URL | 09 REPORT | 00 EXIT
#
# Compatible Git Bash (Windows) y Linux. Solo info publica, con timeouts.
#
# Uso:
#   ./osintx.sh                 (menu interactivo)
#   ./osintx.sh 01 example.com  (atajo: modulo + objetivo)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/lib/common.sh"

MOD_DIR="${SCRIPT_DIR}/modules"
LAST_OUTPUT=""   # ultima salida capturada (para 09 REPORT)
LAST_MODULE="GENERAL"
LAST_TARGET=""

load_modules() {
  local m
  for m in domain portscan subdomain phone username ipinfo email url report; do
    if [[ -f "${MOD_DIR}/${m}.sh" ]]; then
      # shellcheck source=/dev/null
      source "${MOD_DIR}/${m}.sh"
    else
      log_error "modulo no encontrado: ${MOD_DIR}/${m}.sh"
    fi
  done
}

show_banner() {
  cat <<'BANNER'
  ____   _____ _____ _   _ _______  __  __
 / __ \ / ____|_   _| \ | |__   __| \ \/ /
| |  | | (___   | | |  \| |  | |     \  /
| |  | |\___ \  | | | . ` |  | |     /  \
| |__| |____) |_| |_| |\  |  | |    / /\ \
 \____/|_____/|_____|_| \_|  |_|   /_/  \_\
  Passive-intelligence console (shell) v1.0.0
  Solo informacion publica. Uso autorizado unicamente.
BANNER
}

show_menu() {
  cat <<'MENU'

  ============ OSINT-X ============
  01 DOMAIN     (DNS + RDAP + DoH)
  02 PORTSCAN   (TCP, solo autorizados)
  03 SUBDOMAIN  (CT via crt.sh)
  04 PHONE      (formato + pais)
  05 USERNAME   (presencia publica)
  06 IPINFO     (ASN/ISP/geoloc aprox)
  07 EMAIL      (MX/SPF/RDAP)
  08 URL        (headers + cert TLS)
  09 REPORT     (guarda JSON/TXT/HTML)
  00 EXIT
  =================================
MENU
}

pause() {
  read -r -p "Pulse ENTER para continuar..." _ </dev/tty 2>/dev/null || read -r -p "Pulse ENTER para continuar..." _ || true
}

ask_target() {
  local prompt="${1:-Objetivo: }"
  local val=""
  read -r -p "$prompt" val || val=""
  printf '%s' "$val"
}

# Ejecuta un modulo capturando su salida para poder enviarla a 09 REPORT.
run_and_capture() {
  local module="$1" target="$2"
  local out rc
  case "$module" in
    DOMAIN)    out="$(run_domain "$target" 2>&1)"; rc=$? ;;
    PORTSCAN)  out="$(run_portscan "$target" 2>&1)"; rc=$? ;;
    SUBDOMAIN) out="$(run_subdomain "$target" 2>&1)"; rc=$? ;;
    PHONE)     out="$(run_phone "$target" 2>&1)"; rc=$? ;;
    USERNAME)  out="$(run_username "$target" 2>&1)"; rc=$? ;;
    IPINFO)    out="$(run_ipinfo "$target" 2>&1)"; rc=$? ;;
    EMAIL)     out="$(run_email "$target" 2>&1)"; rc=$? ;;
    URL)       out="$(run_url "$target" 2>&1)"; rc=$? ;;
    *) log_error "modulo desconocido: $module"; return 2 ;;
  esac
  printf '%s\n' "$out"
  LAST_OUTPUT="$out"
  LAST_MODULE="$module"
  LAST_TARGET="$target"
  if (( rc != 0 )); then
    log_error "$module termino con codigo $rc (ver mensajes arriba)"
  else
    log_info "puede usar 09 REPORT para guardar este resultado"
  fi
  return "$rc"
}

do_domain() {
  local t
  t="$(ask_target "Dominio (ej: example.com): ")"
  [[ -z "$t" ]] && { log_error "objetivo vacio"; return 2; }
  run_and_capture "DOMAIN" "$t" || true
}

do_portscan() {
  local h p
  h="$(ask_target "Host (dominio o IP, solo autorizados): ")"
  [[ -z "$h" ]] && { log_error "objetivo vacio"; return 2; }
  read -r -p "Puertos [21,22,23,25,53,80,110,143,443,445,3306,8080]: " p || p=""
  run_and_capture "PORTSCAN" "$h" 2>/dev/null || true
  # run_portscan acepta spec de puertos: re-ejecutar con spec si se dio
  if [[ -n "${p:-}" ]]; then
    local out
    out="$(run_portscan "$h" "$p" 2>&1)"; local rc=$?
    printf '%s\n' "$out"
    LAST_OUTPUT="$out"; LAST_MODULE="PORTSCAN"; LAST_TARGET="$h"
    (( rc != 0 )) && log_error "PORTSCAN termino con codigo $rc"
  fi
  return 0
}

do_subdomain() {
  local t
  t="$(ask_target "Dominio (ej: example.com): ")"
  [[ -z "$t" ]] && { log_error "objetivo vacio"; return 2; }
  run_and_capture "SUBDOMAIN" "$t" || true
}

do_phone() {
  local t
  t="$(ask_target "Telefono (ej: +34123456789): ")"
  [[ -z "$t" ]] && { log_error "objetivo vacio"; return 2; }
  run_and_capture "PHONE" "$t" || true
}

do_username() {
  local t
  t="$(ask_target "Username: ")"
  [[ -z "$t" ]] && { log_error "objetivo vacio"; return 2; }
  run_and_capture "USERNAME" "$t" || true
}

do_ipinfo() {
  local t
  t="$(ask_target "IP (ej: 8.8.8.8): ")"
  [[ -z "$t" ]] && { log_error "objetivo vacio"; return 2; }
  run_and_capture "IPINFO" "$t" || true
}

do_email() {
  local t
  t="$(ask_target "Email: ")"
  [[ -z "$t" ]] && { log_error "objetivo vacio"; return 2; }
  run_and_capture "EMAIL" "$t" || true
}

do_url() {
  local t
  t="$(ask_target "URL (https://...): ")"
  [[ -z "$t" ]] && { log_error "objetivo vacio"; return 2; }
  run_and_capture "URL" "$t" || true
}

do_report() {
  if [[ -z "$LAST_OUTPUT" ]]; then
    log_info "sin resultado previo en esta sesion; se pediran datos manualmente."
    local m t
    m="$(ask_target "Modulo (ej: DOMAIN): ")"
    t="$(ask_target "Objetivo: ")"
    log_info "la salida del ultimo modulo esta vacia; se guardara un informe basico."
    run_report "${m:-GENERAL}" "${t:-unknown}" "(informe manual desde menu OSINT-X)" || true
  else
    run_report "$LAST_MODULE" "$LAST_TARGET" "$LAST_OUTPUT" || true
  fi
}

main_loop() {
  local opt
  while true; do
    show_menu
    read -r -p "OSINT-X> opcion (01-09, 00 salir): " opt || { echo; break; }
    # Normalizar: "1" -> "01", mayusculas, espacios
    opt="$(printf '%s' "$opt" | tr -d ' \t' | tr '[:lower:]' '[:upper:]')"
    case "$opt" in
      1) opt="01" ;; 2) opt="02" ;; 3) opt="03" ;; 4) opt="04" ;;
      5) opt="05" ;; 6) opt="06" ;; 7) opt="07" ;; 8) opt="08" ;; 9) opt="09" ;;
    esac
    case "$opt" in
      01|DOMAIN)      do_domain ;;
      02|PORTSCAN)    do_portscan ;;
      03|SUBDOMAIN)   do_subdomain ;;
      04|PHONE)       do_phone ;;
      05|USERNAME)    do_username ;;
      06|IPINFO)      do_ipinfo ;;
      07|EMAIL)       do_email ;;
      08|URL)        do_url ;;
      09|REPORT)      do_report ;;
      00|EXIT|Q|QUIT) log_info "saliendo de OSINT-X. Adios."; break ;;
      *) log_error "opcion invalida: '$opt' (use 01-09 o 00)" ;;
    esac
    echo
    pause
  done
}

# Atajo no interactivo: ./osintx.sh 01 example.com
shortcut() {
  local mod="${1:-}" tgt="${2:-}"
  mod="$(printf '%s' "$mod" | tr -d ' \t' | tr '[:lower:]' '[:upper:]')"
  case "$mod" in
    1) mod="01" ;; 2) mod="02" ;; 3) mod="03" ;; 4) mod="04" ;;
    5) mod="05" ;; 6) mod="06" ;; 7) mod="07" ;; 8) mod="08" ;; 9) mod="09" ;;
  esac
  case "$mod" in
    01|DOMAIN)      run_domain "$tgt" ;;
    02|PORTSCAN)    run_portscan "$tgt" "${3:-}" ;;
    03|SUBDOMAIN)   run_subdomain "$tgt" ;;
    04|PHONE)       run_phone "$tgt" ;;
    05|USERNAME)    run_username "$tgt" ;;
    06|IPINFO)      run_ipinfo "$tgt" ;;
    07|EMAIL)       run_email "$tgt" ;;
    08|URL)        run_url "$tgt" ;;
    09|REPORT)      run_report "GENERAL" "${tgt:-manual}" ;;
    *) log_error "atajo invalido. Uso: $0 <01-09> <objetivo>"; return 2 ;;
  esac
}

load_modules
if [[ $# -ge 2 ]]; then
  shortcut "$@"
  exit $?
elif [[ $# -eq 1 && ( "$1" == "00" || "$1" == "--help" || "$1" == "-h" ) ]]; then
  show_banner
  show_menu
  echo "Uso: $0 [01-09 objetivo]   (sin args = menu interactivo)"
  exit 0
else
  show_banner
  main_loop
fi
