#!/usr/bin/env bash
#
# OSINT-X :: 03 SUBDOMAIN (enumeracion pasiva)
# Fuente publica: crt.sh (Certificate Transparency).
# Sin fuerza bruta, sin bypass, con timeout.
#
# Uso:
#   ./modules/subdomain.sh example.com
#   run_subdomain "example.com"

set -u

_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${_MOD_DIR}/../lib/common.sh"

run_subdomain() {
  local raw="${1:-}"
  local domain
  domain="$(validate_domain "$raw")" || return 2
  require_cmd curl || return 1

  print_header "03" "SUBDOMAIN" "$domain"
  log_info "consultando crt.sh (Certificate Transparency, fuente publica)..."

  local body
  if ! body="$(http_get "https://crt.sh/?q=%25.${domain}&output=json" 2>&1)"; then
    log_error "03 SUBDOMAIN: crt.sh sin respuesta (${body:0:160})"
    return 1
  fi
  if [[ -z "$body" ]]; then
    log_error "03 SUBDOMAIN: crt.sh devolvio respuesta vacia"
    return 1
  fi

  # Extraer "name_value" sin depender de jq (portable Git Bash/Linux).
  local subs tmp
  tmp="$(printf '%s' "$body" | grep -o '"name_value":"[^"]*"' | sed 's/"name_value":"//;s/"$//' | tr -d '\r' | tr ',' '\n' | sed 's/^[*][.]//;s/^[[:space:]]*//;s/[[:space:]]*$//' | grep -i "\.${domain//./\\.}\$" | sort -u)"
  # Nota: el patron anterior falla si el dominio tiene caracteres especiales;
  # fallback simple: filtrar lineas que terminen en el dominio.
  if [[ -z "$tmp" ]]; then
    tmp="$(printf '%s' "$body" | grep -o '"name_value":"[^"]*"' | sed 's/"name_value":"//;s/"$//' | tr -d '\r' | tr ',' '\n' | sed 's/^[*][.]//;s/^[[:space:]]*//;s/[[:space:]]*$//' | grep -F ".${domain}" | sort -u)"
  fi

  if [[ -z "$tmp" ]]; then
    log_info "subdomain: sin subdominios encontrados en CT para $domain"
    log_ok "03 SUBDOMAIN completado (0 resultados)"
    return 0
  fi

  local count total
  total="$(printf '%s\n' "$tmp" | wc -l | tr -d ' ')"
  log_ok "subdomain: $total subdominio(s) unicos en CT (mostrando max 50)"
  count=0
  while IFS= read -r subs; do
    [[ -z "$subs" ]] && continue
    (( count++ ))
    (( count > 50 )) && { log_info "... y $(( total - 50 )) mas (informe completo via 09 REPORT)"; break; }
    printf '[OK] subdomain: %s\n' "$subs"
  done <<< "$tmp"

  log_ok "03 SUBDOMAIN completado para $domain"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -lt 1 ]]; then
    read -r -p "Dominio (ej: example.com): " _d || exit 2
    run_subdomain "${_d:-}"
  else
    run_subdomain "$1"
  fi
fi
