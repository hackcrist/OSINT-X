#!/usr/bin/env bash
#
# OSINT-X :: 02 PORTSCAN (pasivo/autorizado)
# Metodo: timeout + bash /dev/tcp, o nc si existe, fallback curl (puertos 80/443).
# ADVERTENCIA: escanear solo objetivos propios o con autorizacion escrita.
#
# Uso:
#   ./modules/portscan.sh <host> [puertos] [timeout_s]
#   run_portscan <host> [puertos] [timeout_s]
#   puertos: "80,443,22" o "1-1024" (max 1024 puertos por ejecucion)

set -u

_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${_MOD_DIR}/../lib/common.sh"

_DEFAULT_PORTS="21,22,23,25,53,80,110,143,443,445,3306,8080"

service_name() {
  case "$1" in
    21) printf 'ftp' ;; 22) printf 'ssh' ;; 23) printf 'telnet' ;;
    25) printf 'smtp' ;; 53) printf 'dns' ;; 80) printf 'http' ;;
    110) printf 'pop3' ;; 143) printf 'imap' ;; 443) printf 'https' ;;
    445) printf 'smb' ;; 3306) printf 'mysql' ;; 3389) printf 'rdp' ;;
    5900) printf 'vnc' ;; 8080|8000) printf 'http-alt' ;;
    *) printf 'unknown' ;;
  esac
}

# Expande "80,443,8000-8002" -> lista separada por espacios. Max 1024.
expand_ports() {
  local spec="${1:-}" out="" part a b p n=0
  spec="${spec// /}"
  [[ -z "$spec" ]] && spec="$_DEFAULT_PORTS"
  local IFS=','
  for part in $spec; do
    if [[ "$part" =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
      a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
      (( a > b )) && { local t=$a; a=$b; b=$t; }
      (( a < 1 )) && a=1; (( b > 65535 )) && b=65535
      for (( p=a; p<=b; p++ )); do
        out+="$p "; (( n++ ))
        (( n > 1024 )) && { log_error "demasiados puertos (max 1024 por ejecucion)"; return 2; }
      done
    elif [[ "$part" =~ ^[0-9]{1,5}$ ]]; then
      (( part >= 1 && part <= 65535 )) || { log_error "puerto fuera de rango: $part"; return 2; }
      out+="$part "; (( n++ ))
      (( n > 1024 )) && { log_error "demasiados puertos (max 1024 por ejecucion)"; return 2; }
    else
      log_error "especificacion de puertos invalida: '$part'"
      return 2
    fi
  done
  printf '%s' "$out"
}

# Intenta TCP connect con timeout. Retorna: 0 abierto, 1 cerrado, 2 indeterminado.
tcp_probe() {
  local host="$1" port="$2" to="${3:-3}"
  if has_cmd timeout && has_cmd bash; then
    # timeout envuelve a bash para abrir /dev/tcp
    if timeout "$to" bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
      return 0
    else
      local rc=$?
      if (( rc == 124 )); then return 2; fi  # timeout => filtrado/indeterminado
      return 1
    fi
  elif has_cmd nc; then
    if nc -z -w "$to" "$host" "$port" 2>/dev/null; then
      return 0
    else
      return 1
    fi
  else
    return 2
  fi
}

# Banner pasivo: GET HTTP minimo por /dev/tcp (solo informativo).
grab_banner() {
  local host="$1" port="$2" to="${3:-3}"
  if ! has_cmd timeout; then return 0; fi
  timeout "$to" bash -c "
    exec 3<>/dev/tcp/${host}/${port} 2>/dev/null || exit 1
    printf 'HEAD / HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: ${OSINTX_UA}\r\n\r\n' >&3
    head -c 512 <&3 2>/dev/null
    exec 3<&-; exec 3>&-
  " 2>/dev/null | tr -d '\0' | head -c 512
  return 0
}

run_portscan() {
  local host="${1:-}" spec="${2:-$_DEFAULT_PORTS}" ptimeout="${3:-3}"
  if [[ -z "$host" ]]; then
    log_error "02 PORTSCAN: host vacio"
    return 2
  fi
  # host puede ser dominio o IPv4
  if ! printf '%s' "$host" | grep -Eq '^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$|^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    log_error "02 PORTSCAN: host invalido: '$host'"
    return 2
  fi
  [[ "$ptimeout" =~ ^[1-9][0-9]*$ ]] || ptimeout=3
  (( ptimeout > 10 )) && ptimeout=10

  local ports
  ports="$(expand_ports "$spec")" || return 2

  print_header "02" "PORTSCAN" "$host"
  log_info "ADVERTENCIA: escanear unicamente objetivos propios o con autorizacion."
  log_info "metodo: /dev/tcp+timeout preferred, nc alternativo, curl fallback (80/443)"
  log_info "puertos: $ports (timeout ${ptimeout}s c/u)"

  local port svc rc banner code
  for port in $ports; do
    svc="$(service_name "$port")"
    # set +e local: tcp_probe retorna 1/2 a proposito
    set +u
    tcp_probe "$host" "$port" "$ptimeout"
    rc=$?
    set -u
    if (( rc == 0 )); then
      banner="$(grab_banner "$host" "$port" "$ptimeout" 2>/dev/null)"
      banner="$(printf '%s' "$banner" | tr '\r\n' ' ' | head -c 120)"
      if [[ -n "$banner" ]]; then
        log_ok "portscan: ${host}:${port} OPEN (servicio probable: ${svc}) banner: ${banner}"
      else
        log_ok "portscan: ${host}:${port} OPEN (servicio probable: ${svc})"
      fi
    elif (( rc == 1 )); then
      printf '[INFO] portscan: %s:%s CLOSED (%s)\n' "$host" "$port" "$svc"
    else
      # indeterminado: fallback curl solo para web
      if [[ "$port" == "80" || "$port" == "443" || "$port" == "8080" || "$port" == "8000" ]]; then
        local scheme="http"; [[ "$port" == "443" ]] && scheme="https"
        if has_cmd curl; then
          code="$(http_code "${scheme}://${host}:${port}/" 2>/dev/null)" || code="000"
          if [[ "$code" != "000" ]]; then
            log_ok "portscan: ${host}:${port} OPEN (fallback curl HTTP ${code}, servicio: ${svc})"
          else
            printf '[INFO] portscan: %s:%s FILTERED/INDETERMINADO (%s, curl sin respuesta)\n' "$host" "$port" "$svc"
          fi
        else
          printf '[INFO] portscan: %s:%s FILTERED/INDETERMINADO (%s)\n' "$host" "$port" "$svc"
        fi
      else
        printf '[INFO] portscan: %s:%s CLOSED/FILTERED (%s, sin /dev/tcp ni nc concluyente)\n' "$host" "$port" "$svc"
      fi
    fi
  done
  log_ok "02 PORTSCAN completado para $host"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -lt 1 ]]; then
    read -r -p "Host (dominio o IP): " _h || exit 2
    read -r -p "Puertos [${_DEFAULT_PORTS}]: " _p || exit 2
    run_portscan "${_h:-}" "${_p:-$_DEFAULT_PORTS}"
  else
    run_portscan "$1" "${2:-$_DEFAULT_PORTS}" "${3:-3}"
  fi
fi
