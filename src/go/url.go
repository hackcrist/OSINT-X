// Módulo 08 URL: análisis de cabeceras, redirecciones y certificado TLS.
//
// Contrato API:
//   - RunURL(target string) Result con Data de tipo URLData.
//   - Si falta esquema se asume https:// y se anota en Notes.
//   - Registra la cadena de redirecciones (máx. 10) con un cliente que no
//     sigue redirects automáticamente; captura cabeceras de la respuesta
//     final y sugiere tecnologías SOLO desde Server/X-Powered-By (hint).
//   - Para https, obtiene el certificado presentado vía crypto/tls (dial
//     directo al host:puerto con 5s) y expone Subject/Issuer/vigencia/DNSNames
//     del primer certificado. No valida PKI más allá de lo observado.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxRedirects limita la cadena de redirecciones seguida manualmente.
const MaxRedirects = 10

// CertInfo resume el certificado TLS observado.
type CertInfo struct {
	Subject  string   `json:"subject,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	NotAfter string   `json:"not_after,omitempty"`
	DNSNames []string `json:"dns_names,omitempty"`
}

// URLData agrupa los hallazgos del módulo URL.
type URLData struct {
	RequestedURL  string            `json:"requested_url"`
	FinalURL      string            `json:"final_url,omitempty"`
	StatusCode    int               `json:"status_code,omitempty"`
	RedirectChain []string          `json:"redirect_chain,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Server        string            `json:"server,omitempty"`
	TechHints     []string          `json:"tech_hints,omitempty"`
	Cert          *CertInfo         `json:"certificate,omitempty"`
	Notes         []string          `json:"notes,omitempty"`
}

// RunURL analiza la URL dada.
func RunURL(target string) Result {
	raw := strings.TrimSpace(target)
	res := NewResult("url", raw)
	var notes []string

	if raw == "" {
		res.Status = "error"
		res.AddError("URL vacía")
		res.Status = "error"
		return res
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
		notes = append(notes, "esquema ausente: se asumió https://")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		res.Status = "error"
		res.AddError("URL inválida %q: solo http/https", target)
		res.Status = "error"
		return res
	}

	data := URLData{RequestedURL: u.String(), Headers: map[string]string{}}
	client := newHTTPClient(DefaultTimeout, false) // redirects manuales

	current := u.String()
	var chain []string
	var final *http.Response
	for i := 0; i <= MaxRedirects; i++ {
		req, rerr := http.NewRequest(http.MethodGet, current, nil)
		if rerr != nil {
			res.AddError("construir petición: %v", rerr)
			break
		}
		req.Header.Set("User-Agent", UserAgent)
		resp, derr := client.Do(req)
		if derr != nil {
			res.AddError("GET %s: %v", current, derr)
			break
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			_ = resp.Body.Close()
			if loc == "" {
				res.AddError("%s: redirect %d sin Location", current, resp.StatusCode)
				break
			}
			next, perr := url.Parse(loc)
			if perr != nil {
				res.AddError("%s: Location inválido: %v", current, perr)
				break
			}
			base, _ := url.Parse(current)
			if base != nil {
				current = base.ResolveReference(next).String()
			} else {
				current = next.String()
			}
			chain = append(chain, fmt.Sprintf("%d -> %s", resp.StatusCode, current))
			continue
		}
		final = resp
		break
	}
	if len(chain) == MaxRedirects+1 {
		res.AddError("cadena de redirects supera %d saltos; truncada", MaxRedirects)
	}
	data.RedirectChain = chain

	if final == nil {
		res.Status = "error"
		data.Notes = notes
		res.Data = data
		return res
	}
	defer final.Body.Close()
	data.FinalURL = current
	data.StatusCode = final.StatusCode
	for k := range final.Header {
		data.Headers[k] = final.Header.Get(k)
	}
	data.Server = final.Header.Get("Server")
	if xp := final.Header.Get("X-Powered-By"); xp != "" {
		data.TechHints = append(data.TechHints, "X-Powered-By: "+xp)
	}
	if data.Server != "" {
		data.TechHints = append(data.TechHints, "Server: "+data.Server)
	}
	if data.StatusCode/100 != 2 {
		res.AddError("respuesta final HTTP %d (no 2xx)", data.StatusCode)
	}
	res.AddSource("GET " + data.RequestedURL + " (cabeceras observadas)")

	// Certificado TLS si el esquema final es https.
	fu, _ := url.Parse(current)
	if fu != nil && fu.Scheme == "https" {
		if cert, cerr := fetchCert(fu.Host); cerr != nil {
			res.AddError("TLS %s: %v", fu.Host, cerr)
		} else {
			data.Cert = cert
			res.AddSource("certificado TLS presentado por " + fu.Host)
		}
	}
	data.Notes = notes
	res.Data = data
	return res
}

// fetchCert conecta por TLS al host (puerto 443 por defecto) y resume el
// primer certificado presentado. InsecureSkipVerify: solo observamos el
// certificado, no establecemos confianza PKI.
func fetchCert(host string) (*CertInfo, error) {
	h := host
	if _, _, err := net.SplitHostPort(h); err != nil {
		h = net.JoinHostPort(h, "443")
	}
	dialer := &net.Dialer{Timeout: DefaultTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", h, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // observación OSINT, no validación PKI
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("sin certificados presentados")
	}
	leaf := state.PeerCertificates[0]
	return &CertInfo{
		Subject:  leaf.Subject.String(),
		Issuer:   leaf.Issuer.String(),
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		DNSNames: leaf.DNSNames,
	}, nil
}
