// Módulo 03 SUBDOMAIN: enumeración pasiva vía Certificate Transparency.
//
// Contrato API:
//   - RunSubdomain(target string) Result con Data de tipo SubdomainData.
//   - Fuente: https://crt.sh/?q=%25.<dominio>&output=json (timeout 10s por
//     latencia conocida de esa fuente; resto del proyecto usa 5s).
//   - Cada candidato se verifica con DNS (LookupIPAddr); solo los que
//     resuelven van a Verified. Nada se inventa: sin resolución no hay
//     confirmación.
//   - Límite de 100 candidatos verificados; el exceso se indica en Errors.
package main

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// crtTimeout es la excepción documentada a DefaultTimeout (crt.sh es lento).
const crtTimeout = 10 * time.Second

// MaxSubdomainCandidates limita la verificación DNS por ejecución.
const MaxSubdomainCandidates = 100

// SubdomainData agrupa los hallazgos del módulo SUBDOMAIN.
type SubdomainData struct {
	Verified   []string `json:"verified"`
	Unresolved []string `json:"unresolved,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// crtEntry modela cada fila JSON de crt.sh (solo nos importa name_value).
type crtEntry struct {
	NameValue string `json:"name_value"`
}

// RunSubdomain enumera subdominios vía CT y los verifica por DNS.
func RunSubdomain(target string) Result {
	domain := strings.ToLower(strings.TrimSpace(target))
	domain = strings.TrimSuffix(domain, ".")
	res := NewResult("subdomain", domain)

	if domain == "" || !isValidDomain(domain) {
		res.Status = "error"
		res.AddError("dominio inválido: %q", target)
		res.Status = "error"
		return res
	}

	ctURL := "https://crt.sh/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	resp, err := httpGet(ctURL, crtTimeout)
	if err != nil {
		res.Status = "error"
		res.AddError("crt.sh %s: %v", ctURL, err)
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		res.Status = "error"
		res.AddError("crt.sh %s: HTTP %d", ctURL, resp.StatusCode)
		return res
	}
	var entries []crtEntry
	if derr := json.NewDecoder(resp.Body).Decode(&entries); derr != nil {
		res.Status = "error"
		res.AddError("crt.sh: respuesta no JSON: %v", derr)
		return res
	}
	res.AddSource(ctURL)

	// Deduplicar candidatos (minúsculas, sin comodines ni saltos).
	seen := map[string]bool{}
	var candidates []string
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(line))
			name = strings.TrimPrefix(name, "*.")
			name = strings.TrimSuffix(name, ".")
			if name == "" || seen[name] {
				continue
			}
			// Solo subdominios del dominio objetivo.
			if name != domain && !strings.HasSuffix(name, "."+domain) {
				continue
			}
			seen[name] = true
			candidates = append(candidates, name)
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		res.Status = "error"
		res.AddError("crt.sh no devolvió subdominios para %s", domain)
		return res
	}

	if len(candidates) > MaxSubdomainCandidates {
		res.AddError("candidatos truncados a %d de %d (límite por ejecución)",
			MaxSubdomainCandidates, len(candidates))
		candidates = candidates[:MaxSubdomainCandidates]
	}

	var data SubdomainData
	for _, c := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		addrs, lerr := net.DefaultResolver.LookupIPAddr(ctx, c)
		cancel()
		if lerr != nil || len(addrs) == 0 {
			data.Unresolved = append(data.Unresolved, c)
			continue
		}
		data.Verified = append(data.Verified, c)
	}
	if len(data.Verified) == 0 {
		res.Status = "error"
		res.AddError("ningún candidato resolvió por DNS")
	} else {
		res.AddSource("verificación DNS A/AAAA del sistema")
	}
	data.Notes = []string{"fuente pasiva: Certificate Transparency (crt.sh); wordlists no incluidas (sin red activa adicional)"}
	res.Data = data
	return res
}
