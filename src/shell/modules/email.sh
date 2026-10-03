#!/usr/bin/env bash
#
# OSINT-X :: 07 EMAIL
# Solo comprobaciones OSINT permitidas: formato, dominio, MX, SPF/TXT, RDAP.
# NO consulta brechas (HaveIBeenPwned exige API key) ni verifica inbox.
#
# Uso:
#   ./modules/email.sh usuario@example.com
#   run_email "usuario@example.com"

set -u

_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${_MOD_DIR}/../lib/common.sh"

run_email() {
  local raw="${1:-}"
  local email
  email="$(validate_email "$raw")" || return 2

  local domain="${email##*@}"
  domain="$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')"

  print_header "07" "EMAIL" "$email"
  log_ok "email.formato: valido"
  log_ok "email.dominio: $domain"

  if ! has_cmd dig && ! has_cmd nslookup; then
    log_error "07 EMAIL: se requiere 'dig' o 'nslookup' para MX/TXT"
    return 1
  fi

  log_info "--- MX de $domain ---"
  local mx
  if mx="$(dns_lookup "$domain" "MX" 2>&1)" && [[ -n "$mx" ]]; then
    printf '%s\n' "$mx"
    log_ok "email.mx: dominio con MX (acepta correo probablemente)"
  else
    log_error "email.mx: sin registros MX o consulta fallida (${mx:0:160})"
  fi

  log_info "--- TXT/SPF de $domain ---"
  local txt
  if txt="$(dns_lookup "$domain" "TXT" 2>&1)" && [[ -n "$txt" ]]; then
    printf '%s\n' "$txt"
    if printf '%s' "$txt" | grep -qi 'v=spf1'; then
      log_ok "email.spf: politica SPF publicada"
    else
      log_info "email.spf: sin politica SPF visible en TXT"
    fi
  else
    log_info "email.txt: sin registros TXT o consulta fallida"
  fi

  log_info "--- RDAP del dominio ($domain) ---"
  local rdap
  if has_cmd curl; then
    if rdap="$(http_get "https://rdap.org/domain/${domain}" 2>&1)"; then
      printf '%s\n' "$rdap" | head -c 2000
      printf '\n'
      log_ok "email.rdap: respuesta obtenida (recortada a 2000 chars en pantalla)"
    else
      log_error "email.rdap: sin respuesta (${rdap:0:160})"
    fi
  fi

  log_info "email.brechas: no consultado (las fuentes fiables exigen API key; no intentarlo sin ella)"
  log_ok "07 EMAIL completado para $email"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -lt 1 ]]; then
    read -r -p "Email: " _e || exit 2
    run_email "${_e:-}"
  else
    run_email "$1"
  fi
fi
