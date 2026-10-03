#!/usr/bin/env bash
#
# OSINT-X :: 08 URL
# Fuentes publicas: headers (curl -sSI), redirects, heuristica de tecnologias,
# certificado TLS (openssl s_client). Sin bypass, con timeouts.
#
# Uso:
#   ./modules/url.sh https://example.com/
#   run_url "https://example.com/"

set -u

_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${_MOD_DIR}/../lib/common.sh"

run_url() {
  local raw="${1:-}"
  local url
  url="$(validate_url "$raw")" || return 2
  require_cmd curl || return 1

  print_header "08" "URL" "$url"

  log_info "--- Headers + redirects (curl -sSI, max 5 saltos) ---"
  local hdrs
  if hdrs="$(http_headers "$url" 2>&1)"; then
    printf '%s\n' "$hdrs"
    log_ok "url.headers: cabeceras obtenidas"
    # Resumen de redirects
    local locs
    locs="$(printf '%s' "$hdrs" | grep -i '^location:' || true)"
    if [[ -n "$locs" ]]; then
      log_ok "url.redirects: se detectaron redirecciones (ver Location arriba)"
    else
      log_info "url.redirects: sin redirecciones visibles"
    fi
    # Heuristica de servidor/tecnologia desde headers
    local srv xpbn
    srv="$(printf '%s' "$hdrs" | grep -i '^server:' | head -n1 || true)"
    xpbn="$(printf '%s' "$hdrs" | grep -i '^x-powered-by:' | head -n1 || true)"
    [[ -n "$srv" ]] && log_ok "url.server: $srv" || log_info "url.server: cabecera Server no expuesta"
    [[ -n "$xpbn" ]] && log_ok "url.tecnologia(headers): $xpbn" || log_info "url.tecnologia(headers): X-Powered-By no expuesto"
  else
    log_error "url.headers: fallo la peticion (${hdrs:0:200})"
    return 1
  fi

  log_info "--- Heuristica de tecnologias (cuerpo HTML, primeros 64KB) ---"
  local body
  if body="$(http_get "$url" 2>&1 | head -c 65536)"; then
    local tech=""
    printf '%s' "$body" | grep -qi 'wp-content\|wp-includes' && tech+="WordPress "
    printf '%s' "$body" | grep -qi 'drupal' && tech+="Drupal "
    printf '%s' "$body" | grep -qi 'joomla' && tech+="Joomla "
    printf '%s' "$body" | grep -qi 'next/static\|__NEXT_DATA__' && tech+="Next.js "
    printf '%s' "$body" | grep -qi 'nuxt' && tech+="Nuxt "
    printf '%s' "$body" | grep -qi 'django\|csrfmiddlewaretoken' && tech+="Django "
    printf '%s' "$body" | grep -qi 'laravel' && tech+="Laravel "
    if [[ -n "$tech" ]]; then
      log_ok "url.tecnologia(cuerpo): $tech (heuristica, no concluyente)"
    else
      log_info "url.tecnologia(cuerpo): sin firmas conocidas (heuristica limitada)"
    fi
    local title
    title="$(printf '%s' "$body" | grep -oi '<title>[^<]*</title>' | head -n1 || true)"
    [[ -n "$title" ]] && log_ok "url.titulo: $title" || log_info "url.titulo: no extraido"
  else
    log_error "url.cuerpo: no se pudo descargar el cuerpo (${body:0:160})"
  fi

  log_info "--- Certificado TLS (openssl s_client, solo https) ---"
  if [[ "$url" =~ ^https:// ]]; then
    if ! has_cmd openssl; then
      log_error "url.cert: 'openssl' no disponible"
    else
      local hostport host port
      hostport="$(printf '%s' "$url" | sed -E 's#^https://##;s#/.*$##')"
      host="${hostport%%:*}"
      port="${hostport##*:}"
      [[ "$hostport" == *:* ]] || port="443"
      [[ "$port" == "$host" ]] && port="443"
      log_info "conectando a ${host}:${port} (timeout ${OSINTX_TIMEOUT}s)..."
      local cert
      if has_cmd timeout; then
        cert="$(printf '' | timeout "${OSINTX_TIMEOUT}" openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>&1)"
      else
        cert="$(printf '' | openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>&1)"
      fi
      if [[ -n "$cert" ]]; then
        printf '%s\n' "$cert"
        log_ok "url.cert: certificado obtenido"
      else
        log_error "url.cert: no se pudo obtener el certificado (host inaccesible o sin TLS)"
      fi
    fi
  else
    log_info "url.cert: omitido (la URL no es https)"
  fi

  log_ok "08 URL completado para $url"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -lt 1 ]]; then
    read -r -p "URL (https://...): " _u || exit 2
    run_url "${_u:-}"
  else
    run_url "$1"
  fi
fi
