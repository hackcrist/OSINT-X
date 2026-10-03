// Package main implementa el core Go de OSINT-X (solo stdlib).
//
// Contrato de salida común: toda la lógica de negocio devuelve un Result
// con los campos Status, Module, Target, Data, Sources, RetrievedAt y Errors.
// Status admite: "ok" (datos completos), "partial" (datos con errores
// parciales) o "error" (sin datos útiles).
//
// Reglas aplicadas: solo stdlib, timeouts cortos (5s salvo excepción
// documentada), User-Agent "OSINT-X", sin resultados fabricados y errores
// explícitos en Result.Errors.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// UserAgent se envía en todas las peticiones HTTP salientes.
const UserAgent = "OSINT-X"

// DefaultTimeout es el timeout corto estándar para red (5s).
const DefaultTimeout = 5 * time.Second

// Result es el contrato de salida común de todos los módulos.
type Result struct {
	Status      string   `json:"status"`
	Module      string   `json:"module"`
	Target      string   `json:"target"`
	Data        any      `json:"data,omitempty"`
	Sources     []string `json:"sources,omitempty"`
	RetrievedAt string   `json:"retrieved_at"`
	Errors      []string `json:"errors,omitempty"`
}

// NewResult crea un Result con RetrievedAt en UTC (RFC3339) y Status "ok".
// Cada módulo ajusta Status a "partial"/"error" según corresponda.
func NewResult(module, target string) Result {
	return Result{
		Status:      "ok",
		Module:      module,
		Target:      target,
		Sources:     []string{},
		RetrievedAt: time.Now().UTC().Format(time.RFC3339),
		Errors:      []string{},
	}
}

// AddError registra un error explícito y degrada Status a "partial".
// Si ya no hay datos útiles, el llamador debe fijar Status en "error".
func (r *Result) AddError(format string, args ...any) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
	if r.Status == "ok" {
		r.Status = "partial"
	}
}

// AddSource registra una fuente pública realmente consultada.
func (r *Result) AddSource(s string) {
	r.Sources = append(r.Sources, s)
}

// PrintJSON imprime el Result como JSON indentado en stdout.
func (r Result) PrintJSON() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

// newHTTPClient devuelve un cliente HTTP con timeout corto y sin seguir
// redirecciones de forma silenciosa (el módulo URL gestiona su propia
// política de redirects para registrar la cadena).
func newHTTPClient(timeout time.Duration, followRedirects bool) *http.Client {
	c := &http.Client{Timeout: timeout}
	if !followRedirects {
		c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

// httpGet realiza un GET con User-Agent OSINT-X y timeout dado.
func httpGet(url string, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json, text/html, */*")
	return newHTTPClient(timeout, true).Do(req)
}

// httpHead realiza un HEAD con User-Agent OSINT-X y timeout dado.
func httpHead(url string, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	return newHTTPClient(timeout, true).Do(req)
}
