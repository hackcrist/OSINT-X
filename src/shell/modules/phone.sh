#!/usr/bin/env bash
#
# OSINT-X :: 04 PHONE
# Solo metadatos publicos: normalizacion E.164, pais por prefijo, formato.
# No identifica operador salvo coincidencia de prefijo publico; todo es aproximado.
#
# Uso:
#   ./modules/phone.sh +34123456789
#   run_phone "+34 612 34 56 78"

set -u

_MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${_MOD_DIR}/../lib/common.sh"

# Prefijo -> pais (lista publica, no exhaustiva, aproximada).
country_by_prefix() {
  case "$1" in
    1) printf 'Estados Unidos / Canada (NANP)' ;;
    7) printf 'Rusia / Kazajistan' ;;
    20) printf 'Egipto' ;; 27) printf 'Sudafrica' ;;
    30) printf 'Grecia' ;; 31) printf 'Paises Bajos' ;;
    32) printf 'Belgica' ;; 33) printf 'Francia' ;;
    34) printf 'Espana' ;; 39) printf 'Italia' ;;
    40) printf 'Rumania' ;; 41) printf 'Suiza' ;;
    43) printf 'Austria' ;; 44) printf 'Reino Unido' ;;
    49) printf 'Alemania' ;; 51) printf 'Peru' ;;
    52) printf 'Mexico' ;; 53) printf 'Cuba' ;;
    54) printf 'Argentina' ;; 55) printf 'Brasil' ;;
    56) printf 'Chile' ;; 57) printf 'Colombia' ;;
    58) printf 'Venezuela' ;; 60) printf 'Malasia' ;;
    61) printf 'Australia' ;; 62) printf 'Indonesia' ;;
    63) printf 'Filipinas' ;; 64) printf 'Nueva Zelanda' ;;
    65) printf 'Singapur' ;; 81) printf 'Japon' ;;
    82) printf 'Corea del Sur' ;; 84) printf 'Vietnam' ;;
    86) printf 'China' ;; 90) printf 'Turquia' ;;
    91) printf 'India' ;; 212) printf 'Marruecos' ;;
    213) printf 'Argelia' ;; 233) printf 'Ghana' ;;
    234) printf 'Nigeria' ;; 351) printf 'Portugal' ;;
    352) printf 'Luxemburgo' ;; 353) printf 'Irlanda' ;;
    507) printf 'Panama' ;; 509) printf 'Haiti' ;;
    591) printf 'Bolivia' ;; 593) printf 'Ecuador' ;;
    595) printf 'Paraguay' ;; 598) printf 'Uruguay' ;;
    *) printf 'Desconocido / no catalogado (aproximado)' ;;
  esac
}

run_phone() {
  local raw="${1:-}"
  local e164
  e164="$(validate_phone "$raw")" || return 2

  print_header "04" "PHONE" "$e164"

  local digits="${e164#+}"
  local len="${#digits}"
  log_ok "phone.e164: $e164"
  log_ok "phone.digitos: $len (rango E.164 valido: 7-15)"

  # Detectar prefijo: probar 3, 2 y 1 digitos (orden longest-match).
  local prefix country="Desconocido / no catalogado (aproximado)"
  if (( len >= 3 )) && [[ "$(country_by_prefix "${digits:0:3}")" != "Desconocido / no catalogado (aproximado)" ]]; then
    prefix="${digits:0:3}"
    country="$(country_by_prefix "$prefix")"
  elif (( len >= 2 )) && [[ "$(country_by_prefix "${digits:0:2}")" != "Desconocido / no catalogado (aproximado)" ]]; then
    prefix="${digits:0:2}"
    country="$(country_by_prefix "$prefix")"
  else
    prefix="${digits:0:1}"
    country="$(country_by_prefix "$prefix")"
  fi

  log_ok "phone.prefijo: +${prefix}"
  log_ok "phone.pais_probable: ${country}"
  log_info "phone.formato_internacional: ${e164}"
  log_info "phone.formato_nacional_aprox: 0${digits:${#prefix}} (solo referencia, varia por pais)"
  log_info "phone.operador: no determinable con fuentes publicas locales (se omite por diseno)"
  log_info "nota: la atribucion pais/prefijo es aproximada y no identifica al titular"
  log_ok "04 PHONE completado para $e164"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -lt 1 ]]; then
    read -r -p "Telefono (ej: +34123456789): " _p || exit 2
    run_phone "${_p:-}"
  else
    run_phone "$1"
  fi
fi
