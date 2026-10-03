#!/usr/bin/env bash
#
# OSINT-X :: 06 IPINFO
# Fuentes publicas: ip-api.com (geoloc aproximada) + reverse DNS
# (getent/host/nslookup segun disponibilidad).
#
# Uso:
#   ./modules/ipinfo.sh 8.8.8.8
#   run_ipinfo "8.8.8.8"

set -u

_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${_MOD_DIR}/../lib/common.sh"

reverse_dns() {
  local ip="$1" out=""
  if has_cmd getent; then
    out="$(getent hosts "$ip" 2>&1)"
    [[ -n "$out" ]] && { printf '%s\n' "$out"; return 0; }
  fi
  if has_cmd host; then
    out="$(host "$ip" 2>&1)"
    [[ -n "$out" ]] && { printf '%s\n' "$out"; return 0; }
  fi
  if has_cmd nslookup; then
    out="$(nslookup "$ip" 2>&1)"
    [[ -n "$out" ]] && { printf '%s\n' "$out"; return 0; }
  fi
  if has_cmd dig; then
    out="$(dig +short +time=5 +tries=1 -x "$ip" 2>&1)"
    [[ -n "$out" ]] && { printf '%s\n' "$out"; return 0; }
  fi
  return 1
}

run_ipinfo() {
  local raw="${1:-}"
  local ip
  ip="$(validate_ipv4 "$raw")" || return 2
  require_cmd curl || return 1

  print_header "06" "IPINFO" "$ip"
  log_info "consultando ip-api.com (fuente publica, geolocalizacion aproximada)..."

  local body
  if ! body="$(http_get "http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query" 2>&1)"; then
    log_error "06 IPINFO: ip-api.com sin respuesta (${body:0:160})"
    return 1
  fi
  printf '%s\n' "$body"

  # Chequeo minimo sin jq: buscar "status":"success"
  if printf '%s' "$body" | grep -q '"status":"success"'; then
    log_ok "ipinfo: datos publicos obtenidos para $ip (geoloc aproximada, no exacta)"
  else
    log_error "ipinfo: la fuente devolvio fallo (ver cuerpo arriba; puede ser IP privada/reservada o limite de la API)"
  fi

  log_info "--- Reverse DNS (getent -> host -> nslookup -> dig) ---"
  local rev
  if rev="$(reverse_dns "$ip" 2>&1)" && [[ -n "$rev" ]]; then
    printf '%s\n' "$rev"
    log_ok "ipinfo.reverse: respuesta obtenida"
  else
    log_info "ipinfo.reverse: sin registro PTR o herramienta no disponible"
  fi

  log_ok "06 IPINFO completado para $ip"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -lt 1 ]]; then
    read -r -p "IP (ej: 8.8.8.8): " _i || exit 2
    run_ipinfo "${_i:-}"
  else
    run_ipinfo "$1"
  fi
fi
