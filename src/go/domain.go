// Módulo 01 DOMAIN: DNS (A/AAAA, NS, MX, TXT) + RDAP.
//
// Contrato API:
//   - RunDomain(target string) Result con Data de tipo DomainData.
//   - Fuentes: resolución DNS del sistema, https://rdap.org/domain/<dominio>.
//   - Errores explícitos por cada lookup fallido; Status "error" solo si no
//     se obtuvo ningún dato.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// DomainData agrupa los hallazgos del módulo DOMAIN.
type DomainData struct {
	IPs         []string       `json:"ips"`
	NameServers []string       `json:"name_servers"`
	MX          []string       `json:"mx"`
	TXT         []string       `json:"txt"`
	RDAP        map[string]any `json:"rdap,omitempty"`
}

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$`)

// isValidDomain valida sintaxis de dominio (sin IDN: solo ASCII).
// RE2 no admite lookahead, por eso la longitud total se comprueba en código.
func isValidDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	return domainRe.MatchString(d)
}

// RunDomain resuelve DNS y consulta RDAP para el dominio dado.
func RunDomain(target string) Result {
	domain := strings.ToLower(strings.TrimSpace(target))
	domain = strings.TrimSuffix(domain, ".")
	res := NewResult("domain", domain)

	if domain == "" || !isValidDomain(domain) {
		res.Status = "error"
		res.AddError("dominio inválido: %q (se espera p. ej. example.com)", target)
		res.Status = "error"
		return res
	}

	// Contexto con timeout corto compartido por los lookups DNS.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	r := net.DefaultResolver

	var data DomainData

	// A/AAAA.
	ips, err := r.LookupIPAddr(ctx, domain)
	if err != nil {
		res.AddError("LookupIP %s: %v", domain, err)
	} else {
		for _, ip := range ips {
			data.IPs = append(data.IPs, ip.IP.String())
		}
		res.AddSource("DNS A/AAAA")
	}

	// NS. Requiere contexto fresco: el anterior puede haberse consumido.
	if ns, err := lookupWithTimeout(func(c context.Context) (any, error) {
		return r.LookupNS(c, domain)
	}); err != nil {
		res.AddError("LookupNS %s: %v", domain, err)
	} else {
		for _, n := range ns.([]*net.NS) {
			data.NameServers = append(data.NameServers, strings.TrimSuffix(n.Host, "."))
		}
		res.AddSource("DNS NS")
	}

	// MX.
	if mx, err := lookupWithTimeout(func(c context.Context) (any, error) {
		return r.LookupMX(c, domain)
	}); err != nil {
		res.AddError("LookupMX %s: %v", domain, err)
	} else {
		for _, m := range mx.([]*net.MX) {
			data.MX = append(data.MX, fmt.Sprintf("%s (pref %d)", strings.TrimSuffix(m.Host, "."), m.Pref))
		}
		res.AddSource("DNS MX")
	}

	// TXT.
	if txt, err := lookupWithTimeout(func(c context.Context) (any, error) {
		return r.LookupTXT(c, domain)
	}); err != nil {
		res.AddError("LookupTXT %s: %v", domain, err)
	} else {
		data.TXT = append(data.TXT, txt.([]string)...)
		res.AddSource("DNS TXT")
	}

	// RDAP vía proxy público rdap.org (GET JSON, 5s).
	rdapURL := "https://rdap.org/domain/" + domain
	resp, err := httpGet(rdapURL, DefaultTimeout)
	if err != nil {
		res.AddError("RDAP %s: %v", rdapURL, err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			res.AddError("RDAP %s: HTTP %d", rdapURL, resp.StatusCode)
		} else {
			var raw map[string]any
			if derr := json.NewDecoder(resp.Body).Decode(&raw); derr != nil {
				res.AddError("RDAP %s: respuesta no JSON: %v", rdapURL, derr)
			} else {
				data.RDAP = raw
				res.AddSource(rdapURL)
			}
		}
	}

	if len(data.IPs) == 0 && len(data.NameServers) == 0 && len(data.MX) == 0 &&
		len(data.TXT) == 0 && len(data.RDAP) == 0 {
		res.Status = "error"
	} else {
		res.Data = data
	}
	return res
}

// lookupWithTimeout ejecuta un lookup DNS con contexto propio de 5s.
func lookupWithTimeout(fn func(context.Context) (any, error)) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	done := make(chan struct{})
	var (
		v   any
		err error
	)
	go func() {
		v, err = fn(ctx)
		close(done)
	}()
	select {
	case <-done:
		return v, err
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout tras %s", DefaultTimeout)
	case <-time.After(DefaultTimeout + 2*time.Second):
		return nil, fmt.Errorf("timeout tras %s", DefaultTimeout)
	}
}
