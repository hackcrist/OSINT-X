#!/usr/bin/env bash
#
# OSINT-X :: 05 USERNAME
# Busqueda de presencia publica: GET a perfiles publicos, clasifica por HTTP code.
# Contrato: curl -o /dev/null -w %{http_code} (mas -sS -m 10 -A OSINT-X).
# Sin login, sin bypass, con timeouts.
#
# Uso:
#   ./modules/username.sh johndoe
#   run_username "johndoe"

set -u

_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${_MOD_DIR}/../lib/common.sh"

# plataforma|url_template (donde %s = username)
PLATFORMS=(
  "GitHub|https://github.com/%s"
  "GitLab|https://gitlab.com/%s"
  "X|https://x.com/%s"
  "Instagram|https://www.instagram.com/%s/"
  "Reddit|https://www.reddit.com/user/%s/"
  "TikTok|https://www.tiktok.com/@%s"
  "Medium|https://medium.com/@%s"
  "Pinterest|https://www.pinterest.com/%s/"
)

run_username() {
  local raw="${1:-}"
  local user
  user="$(validate_username "$raw")" || return 2
  require_cmd curl || return 1

  print_header "05" "USERNAME" "$user"
  log_info "comprobando presencia publica en ${#PLATFORMS[@]} plataformas (timeout ${OSINTX_TIMEOUT}s)..."

  local entry name tmpl url code
  local found=0 checked=0
  for entry in "${PLATFORMS[@]}"; do
    name="${entry%%|*}"
    tmpl="${entry#*|}"
    # shellcheck disable=SC2059
    url="$(printf "$tmpl" "$user")"
    (( checked++ ))
    if code="$(http_code "$url" 2>/dev/null)"; then
      case "$code" in
        200)
          log_ok "username: [$name] EXISTE (HTTP 200) -> $url"
          (( found++ ))
          ;;
        404)
          printf '[INFO] username: [%s] no encontrado (HTTP 404)\n' "$name"
          ;;
        000)
          log_error "username: [$name] sin respuesta (timeout/red)"
          ;;
        *)
          printf '[INFO] username: [%s] indeterminado (HTTP %s) -> %s\n' "$name" "$code" "$url"
          ;;
      esac
    else
      log_error "username: [$name] error de red al consultar $url"
    fi
  done

  log_info "username.resumen: $found coincidencia(s) de $checked plataformas (HTTP 200 = perfil publico probable)"
  log_info "nota: un 200 indica pagina publica existente, no confirma identidad del titular"
  log_ok "05 USERNAME completado para $user"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -lt 1 ]]; then
    read -r -p "Username: " _u || exit 2
    run_username "${_u:-}"
  else
    run_username "$1"
  fi
fi
