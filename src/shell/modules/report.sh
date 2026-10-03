#!/usr/bin/env bash
#
# OSINT-X :: 09 REPORT
# Guarda resultados en ./reports/ como JSON / TXT / HTML.
# Sin dependencias externas: solo bash + common.sh.
#
# Uso:
#   ./modules/report.sh <modulo> <objetivo> [fichero_datos]
#   run_report <modulo> <objetivo> [texto_o_fichero]
# Ej:
#   ./modules/domain.sh example.com | ./modules/report.sh DOMAIN example.com
#   run_report "DOMAIN" "example.com" "$(cat datos.txt)"

set -u

_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${_MOD_DIR}/../lib/common.sh"

REPORT_DIR="${REPORT_DIR:-${_MOD_DIR}/../reports}"

safe_name() {
  # Sanitiza para nombre de fichero: solo [A-Za-z0-9._-], resto -> _
  printf '%s' "${1:-report}" | sed 's/[^A-Za-z0-9._-]/_/g' | head -c 80
}

run_report() {
  local module="${1:-GENERAL}"
  local target="${2:-unknown}"
  local data="${3:-}"

  # Si el 3er arg es un fichero existente, leerlo; si no, tratarlo como texto.
  if [[ -n "$data" && -f "$data" ]]; then
    data="$(cat "$data")"
  fi
  # Si no hay datos y stdin no es terminal, leer de stdin (para tuberias).
  if [[ -z "$data" && ! -t 0 ]]; then
    data="$(cat)"
  fi
  [[ -z "$data" ]] && data="(sin datos: el modulo no produjo salida)"

  mkdir -p "$REPORT_DIR" || { log_error "09 REPORT: no se pudo crear $REPORT_DIR"; return 1; }

  local ts stamp smod starget base json txt html
  ts="$(timestamp_utc)"
  stamp="$(date -u +"%Y%m%d-%H%M%S")"
  smod="$(safe_name "$module")"
  starget="$(safe_name "$target")"
  base="${REPORT_DIR}/${stamp}-${smod}-${starget}"
  json="${base}.json"
  txt="${base}.txt"
  html="${base}.html"

  local emod etarget ets edata
  emod="$(json_escape "$module")"
  etarget="$(json_escape "$target")"
  ets="$(json_escape "$ts")"
  edata="$(json_escape "$data")"

  {
    printf '{\n'
    printf '  "tool": "OSINT-X %s (shell)",\n' "$OSINTX_VERSION"
    printf '  "module": "%s",\n' "$emod"
    printf '  "target": "%s",\n' "$etarget"
    printf '  "timestamp_utc": "%s",\n' "$ets"
    printf '  "summary": "%s"\n' "$edata"
    printf '}\n'
  } > "$json" || { log_error "09 REPORT: no se pudo escribir $json"; return 1; }

  {
    printf 'OSINT-X %s :: informe\n' "$OSINTX_VERSION"
    printf 'Modulo : %s\n' "$module"
    printf 'Objetivo: %s\n' "$target"
    printf 'Fecha UTC: %s\n' "$ts"
    printf -- '----------------------------------------\n'
    printf '%s\n' "$data"
  } > "$txt" || { log_error "09 REPORT: no se pudo escribir $txt"; return 1; }

  {
    printf '<!DOCTYPE html>\n<html lang="es">\n<head>\n<meta charset="utf-8">\n'
    printf '<title>OSINT-X %s</title>\n' "$(html_escape "$module")"
    printf '<style>body{font-family:monospace;max-width:900px;margin:2em auto;padding:0 1em}pre{background:#f4f4f4;padding:1em;white-space:pre-wrap}</style>\n'
    printf '</head>\n<body>\n<h1>OSINT-X %s :: %s</h1>\n' "$(html_escape "$OSINTX_VERSION")" "$(html_escape "$module")"
    printf '<p><strong>Objetivo:</strong> %s<br><strong>Fecha UTC:</strong> %s</p>\n' "$(html_escape "$target")" "$(html_escape "$ts")"
    printf '<pre>%s</pre>\n</body>\n</html>\n' "$(html_escape "$data")"
  } > "$html" || { log_error "09 REPORT: no se pudo escribir $html"; return 1; }

  print_header "09" "REPORT" "$target"
  log_ok "report.json: $json"
  log_ok "report.txt : $txt"
  log_ok "report.html: $html"
  log_ok "09 REPORT completado"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  _m="${1:-GENERAL}"
  _t="${2:-unknown}"
  _d="${3:-}"
  if [[ $# -eq 0 && -t 0 ]]; then
    read -r -p "Modulo (ej: DOMAIN): " _m || exit 2
    read -r -p "Objetivo: " _t || exit 2
    log_info "pegue los datos y pulse Ctrl+D (o deje vacio):"
    _d="$(cat)"
    run_report "${_m:-GENERAL}" "${_t:-unknown}" "$_d"
  else
    run_report "$_m" "$_t" "$_d"
  fi
fi
