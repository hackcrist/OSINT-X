// Módulo 07 EMAIL: análisis OSINT permitido de una dirección.
//
// Contrato API:
//   - RunEmail(target string) Result con Data de tipo EmailData.
//   - Valida sintaxis, extrae dominio y consulta registros públicos MX/TXT
//     (pistas SPF/DKIM/DMARC) e IPs del dominio. Reutiliza la lógica DNS con
//     timeout corto.
//   - NO realiza comprobaciones de brechas/filtraciones (requieren API key o
//     implican tratamiento de datos de terceros): se declara en Notes.
package main

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"
)

var emailRe = regexp.MustCompile(`^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,}$`)

// EmailData agrupa los hallazgos del módulo EMAIL.
type EmailData struct {
	Address string   `json:"address"`
	Local   string   `json:"local_part,omitempty"`
	Domain  string   `json:"domain,omitempty"`
	MX      []string `json:"mx,omitempty"`
	TXT     []string `json:"txt,omitempty"`
	DomIPs  []string `json:"domain_ips,omitempty"`
	Notes   []string `json:"notes"`
}

// RunEmail analiza la dirección con fuentes públicas (DNS del dominio).
func RunEmail(target string) Result {
	addr := strings.TrimSpace(target)
	res := NewResult("email", addr)

	if !emailRe.MatchString(addr) {
		res.Status = "error"
		res.AddError("email inválido: %q", target)
		res.Status = "error"
		return res
	}
	parts := strings.SplitN(addr, "@", 2)
	local, domain := parts[0], strings.ToLower(parts[1])
	data := EmailData{
		Address: addr,
		Local:   local,
		Domain:  domain,
		Notes: []string{
			"breach check (filtraciones) no realizado: requiere API key o implica datos de terceros",
			"existencia del buzón no verificada: solo registros públicos del dominio",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()
	r := net.DefaultResolver

	// MX del dominio.
	mxDone := make(chan struct{})
	go func() {
		defer close(mxDone)
		mctx, mc := context.WithTimeout(context.Background(), DefaultTimeout)
		defer mc()
		mxs, merr := r.LookupMX(mctx, domain)
		if merr != nil {
			res.AddError("LookupMX %s: %v", domain, merr)
			return
		}
		for _, m := range mxs {
			data.MX = append(data.MX, strings.TrimSuffix(m.Host, "."))
		}
		res.AddSource("DNS MX de " + domain)
	}()

	// TXT del dominio (SPF/DKIM/DMARC a simple vista).
	txtDone := make(chan struct{})
	go func() {
		defer close(txtDone)
		tctx, tc := context.WithTimeout(context.Background(), DefaultTimeout)
		defer tc()
		txts, terr := r.LookupTXT(tctx, domain)
		if terr != nil {
			res.AddError("LookupTXT %s: %v", domain, terr)
			return
		}
		data.TXT = append(data.TXT, txts...)
		res.AddSource("DNS TXT de " + domain)
	}()

	// IPs del dominio (pista de infraestructura).
	ipDone := make(chan struct{})
	go func() {
		defer close(ipDone)
		ictx, ic := context.WithTimeout(context.Background(), DefaultTimeout)
		defer ic()
		ips, ierr := r.LookupIPAddr(ictx, domain)
		if ierr != nil {
			res.AddError("LookupIP %s: %v", domain, ierr)
			return
		}
		for _, ip := range ips {
			data.DomIPs = append(data.DomIPs, ip.IP.String())
		}
		res.AddSource("DNS A/AAAA de " + domain)
	}()

	timeout := time.After(DefaultTimeout + 2*time.Second)
	for _, ch := range []chan struct{}{mxDone, txtDone, ipDone} {
		select {
		case <-ch:
		case <-timeout:
			res.AddError("timeout esperando DNS de %s", domain)
		case <-ctx.Done():
			res.AddError("timeout esperando DNS de %s", domain)
		}
	}

	if len(data.MX) == 0 && len(data.TXT) == 0 && len(data.DomIPs) == 0 {
		res.Status = "error"
		res.AddError("dominio %s sin registros públicos útiles", domain)
	}
	res.Data = data
	return res
}
