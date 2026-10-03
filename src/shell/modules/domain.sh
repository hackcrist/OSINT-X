#!/usr/bin/env bash
#
# OSINT-X :: 01 DOMAIN
# Fuentes 100% publicas: DNS (dig/nslookup), RDAP, DoH Cloudflare.
# Sin bypass, con timeouts y errores explicitos.
#
# Uso:
#   ./modules/domain.sh example.com
#   run_domain "example.com"   (tras source)

set -u

_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${_MOD_DIR}/../lib/common.sh"

run_domain() {
  local raw="${1:-}"
  local domain
  domain="$(validate_domain "$raw")" || return 2

  require_cmd curl || return 1
  if ! has_cmd dig && ! has_cmd nslookup; then
    log_error "01 DOMAIN: se requiere 'dig' o 'nslookup' (ninguno encontrado)"
    return 1
  fi

  print_header "01" "DOMAIN" "$domain"
  log_info "resolviendo DNS (dig preferred, nslookup fallback)..."

  local rtype out
  for rtype in A AAAA MX TXT NS; do
    log_info "--- $rtype ---"
    if out="$(dns_lookup "$domain" "$rtype" 2>&1)"; then
      if [[ -n "$out" ]]; then
        printf '%s\n' "$out"
        log_ok "domain.$rtype: registros mostrados arriba"
      else
        log_info "domain.$rtype: sin registros (respuesta vacia)"
      fi
    else
      log_error "domain.$rtype: fallo la consulta (${out:0:160})"
    fi
  done

  log_info "--- DoH Cloudflare (fuente publica adicional, tipo A) ---"
  if out="$(doh_lookup "$domain" "A" 2>&1)"; then
    printf '%s\n' "$out"
    log_ok "domain.doh: respuesta DoH obtenida"
  else
    log_error "domain.doh: sin respuesta (${out:0:160})"
  fi

  log_info "--- RDAP (https://rdap.org/domain/$domain) ---"
  if out="$(http_get "https://rdap.org/domain/${domain}" 2>&1)"; then
    printf '%s\n' "$out"
    log_ok "domain.rdap: respuesta RDAP obtenida"
  else
    log_error "domain.rdap: no se pudo obtener RDAP (${out:0:160})"
  fi

  log_info "--- IPs asociadas (derivadas de registros A/AAAA y DoH, sin escaneo) ---"
  log_info "ver seccion A/AAAA + DoH de arriba; resolucion inversa disponible en modulo 06 IPINFO"
  log_ok "01 DOMAIN completado para $domain"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -lt 1 ]]; then
    read -r -p "Dominio (ej: example.com): " _d || exit 2
    run_domain "${_d:-}"
  else
    run_domain "$1"
  fi
fi
