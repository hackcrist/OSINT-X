#!/usr/bin/env bash
#
# OSINT-X :: lib/common.sh
# Utilidades compartidas (Git Bash Windows + Linux).
# Solo usa: curl, dig/nslookup, openssl, nc/timeout, getent/host.
# Todo el trafico es publico, con timeouts y sin tecnicas de bypass.
#
# Contrato de salida (stdout humano + stderr errores):
#   "[OK] <modulo>: <dato>"  -> lineas de resultado
#   "[INFO] ..."             -> progreso
#   "[ERROR] ..." >&2        -> error explicito, retorno != 0
#
# Uso:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=/dev/null
#   source "$SCRIPT_DIR/../lib/common.sh"

set -u
export LC_ALL=C

OSINTX_VERSION="1.0.0"
OSINTX_UA="OSINT-X/${OSINTX_VERSION}"
OSINTX_TIMEOUT="${OSINTX_TIMEOUT:-10}"

# ---------------------------------------------------------------- helpers ---
log_info()  { printf '[INFO] %s\n' "$*"; }
log_ok()    { printf '[OK] %s\n' "$*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }

# 0 si el comando existe, 1 si no.
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Aborta con mensaje si falta un comando obligatorio.
# Uso: require_cmd curl || return 1
require_cmd() {
  if ! has_cmd "$1"; then
    log_error "comando requerido no encontrado: $1"
    return 1
  fi
  return 0
}

# Timestamp UTC ISO-8601. Ej: 2026-10-02T19:00:00Z
timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Escapa una cadena para incrustarla en JSON entre comillas dobles.
# Uso: esc="$(json_escape "$valor")"; printf '{"k":"%s"}\n' "$esc"
json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"          # backslash
  s="${s//\"/\\\"}"          # comillas dobles
  s="${s//$'\t'/\\t}"        # tab
  s="${s//$'\r'/\\r}"        # CR
  # NL -> \n (hacerlo al final en dos pasos)
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

# Escapa texto para HTML.
html_escape() {
  local s="${1:-}"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  s="${s//\"/&quot;}"
  printf '%s' "$s"
}

# GET HTTP publico con contrato fijo:
#   curl -sS -m <timeout> -A "OSINT-X/x.y.z"
# Imprime el cuerpo en stdout. Errores a stderr + retorno != 0.
# Uso: body="$(http_get "https://example.com")" || return 1
# Vars: OSINTX_TIMEOUT (seg, defecto 10), OSINTX_UA.
http_get() {
  local url="${1:-}"
  if [[ -z "$url" ]]; then
    log_error "http_get: URL vacia"
    return 2
  fi
  require_cmd curl || return 1
  curl -sS -m "${OSINTX_TIMEOUT}" -A "${OSINTX_UA}" --proto '=http,https' "$url"
}

# HEAD/headers HTTP publicos (sigue redirects, max 5).
# Uso: http_headers "https://example.com"
http_headers() {
  local url="${1:-}"
  if [[ -z "$url" ]]; then
    log_error "http_headers: URL vacia"
    return 2
  fi
  require_cmd curl || return 1
  curl -sSI -m "${OSINTX_TIMEOUT}" -A "${OSINTX_UA}" -L --max-redirs 5 \
    --proto '=http,https' "$url"
}

# Devuelve el codigo HTTP de una URL (solo info publica, sin bypass).
# Imprime ej: 200. Retorno != 0 si curl falla.
# Uso: code="$(http_code "https://github.com/user")"
http_code() {
  local url="${1:-}"
  if [[ -z "$url" ]]; then
    log_error "http_code: URL vacia"
    return 2
  fi
  require_cmd curl || return 1
  curl -o /dev/null -sS -m "${OSINTX_TIMEOUT}" -A "${OSINTX_UA}" \
    -L --max-redirs 3 --proto '=http,https' -w '%{http_code}' "$url"
}

# Imprime cabecera de seccion del contrato de salida.
# Uso: print_header "01" "DOMAIN" "example.com"
print_header() {
  local num="${1:-??}" mod="${2:-MODULE}" target="${3:-}"
  printf '=== [%s %s] target: %s | %s ===\n' "$num" "$mod" "$target" "$(timestamp_utc)"
}

# ------------------------------------------------------------- validacion ---
validate_domain() {
  local d="${1:-}"
  if [[ -z "$d" ]]; then
    log_error "dominio vacio"
    return 2
  fi
  # minusculas para comparar; no resolvemos nada aqui
  d="$(printf '%s' "$d" | tr '[:upper:]' '[:lower:]')"
  if [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; then
    printf '%s' "$d"
    return 0
  fi
  log_error "dominio invalido: '$1' (esperado ej: example.com)"
  return 2
}

validate_ipv4() {
  local ip="${1:-}"
  if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    local IFS=.
    local -a o=($ip)
    local n
    for n in "${o[@]}"; do
      if (( n < 0 || n > 255 )); then
        log_error "IPv4 invalida (octeto fuera de rango): '$ip'"
        return 2
      fi
    done
    printf '%s' "$ip"
    return 0
  fi
  log_error "IPv4 invalida: '$ip' (esperado ej: 8.8.8.8)"
  return 2
}

validate_email() {
  local e="${1:-}"
  if [[ "$e" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]]; then
    printf '%s' "$e"
    return 0
  fi
  log_error "email invalido: '$e'"
  return 2
}

validate_url() {
  local u="${1:-}"
  if [[ "$u" =~ ^https?://[^[:space:]/$.?#].[^[:space:]]*$ ]]; then
    printf '%s' "$u"
    return 0
  fi
  log_error "URL invalida: '$u' (debe empezar por http:// o https://)"
  return 2
}

validate_username() {
  local u="${1:-}"
  if [[ "$u" =~ ^[A-Za-z0-9._-]{1,39}$ ]]; then
    printf '%s' "$u"
    return 0
  fi
  log_error "username invalido: '$u' (permitido: letras, numeros, . _ - , 1-39 chars)"
  return 2
}

# Normaliza telefono a formato E.164 aproximado (+<digitos>).
# Acepta espacios, guiones, parentesis y un '+' inicial.
validate_phone() {
  local raw="${1:-}"
  if [[ -z "$raw" ]]; then
    log_error "telefono vacio"
    return 2
  fi
  # quitar espacios, guiones, puntos, parentesis
  local norm
  norm="$(printf '%s' "$raw" | tr -d ' \t\n\r-.()')"
  if [[ "$norm" =~ ^\+?[0-9]{7,15}$ ]]; then
    [[ "$norm" != +* ]] && norm="+${norm}"
    printf '%s' "$norm"
    return 0
  fi
  log_error "telefono invalido: '$raw' (esperado 7-15 digitos, ej: +34123456789)"
  return 2
}

# ------------------------------------------------------- resolucion DNS -----
# Resuelve registros usando dig si existe, si no nslookup.
# Uso: dns_lookup <dominio> [TYPE]  (TYPE: A, AAAA, MX, TXT, NS)
dns_lookup() {
  local domain="${1:-}" rtype="${2:-A}"
  if [[ -z "$domain" ]]; then
    log_error "dns_lookup: dominio vacio"
    return 2
  fi
  if has_cmd dig; then
    dig +short +time=5 +tries=1 "$domain" "$rtype" 2>&1
    return 0
  elif has_cmd nslookup; then
    if [[ "$rtype" == "A" ]]; then
      nslookup "$domain" 2>&1
    else
      nslookup -type="$rtype" "$domain" 2>&1
    fi
    return 0
  else
    log_error "dns_lookup: ni 'dig' ni 'nslookup' disponibles"
    return 1
  fi
}

# DNS-over-HTTPS (Cloudflare) como fuente publica adicional / fallback.
# Uso: doh_lookup <dominio> [TYPE]
doh_lookup() {
  local domain="${1:-}" rtype="${2:-A}"
  require_cmd curl || return 1
  curl -sS -m "${OSINTX_TIMEOUT}" -A "${OSINTX_UA}" \
    -H 'accept: application/dns-json' \
    --proto '=https' \
    "https://cloudflare-dns.com/dns-json?name=${domain}&type=${rtype}" 2>&1
}
