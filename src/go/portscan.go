// Módulo 02 PORTSCAN: escaneo TCP con banner grabbing.
//
// Contrato API:
//   - RunPortscan(target string, ports []int) Result con Data []PortFinding.
//   - Si ports está vacío se usa DefaultScanPorts.
//   - Dial TCP con timeout corto (3s) y lectura de banner con deadline 2s.
//   - Service es solo una sugerencia por número de puerto ("unknown" si no hay
//     coincidencia); el Banner es lo realmente observado, sin fabricar.
package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// DialTimeoutTCP y BannerTimeout cumplen la regla de timeouts cortos.
const (
	DialTimeoutTCP = 3 * time.Second
	BannerTimeout  = 2 * time.Second
)

// DefaultScanPorts es la lista por defecto (puertos comunes).
var DefaultScanPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443}

// commonServices sugiere servicios habituales por puerto. Es orientativo.
var commonServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
	3306: "mysql", 3389: "rdp", 8080: "http-alt", 8443: "https-alt",
}

// PortFinding describe el hallazgo por puerto.
type PortFinding struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service_hint"`
	Banner  string `json:"banner,omitempty"`
}

// PortscanData envuelve hallazgos + notas de alcance (no son errores).
type PortscanData struct {
	Findings []PortFinding `json:"findings"`
	Notes    []string      `json:"notes"`
}

// RunPortscan escanea los puertos TCP dados en el host objetivo.
// target admite "host" o "host:puerto" (en ese caso se escanea solo ese
// puerto). Solo TCP; UDP queda fuera y se indica en Errors como límite.
func RunPortscan(target string, ports []int) Result {
	res := NewResult("portscan", strings.TrimSpace(target))
	host := strings.TrimSpace(target)
	if host == "" {
		res.Status = "error"
		res.AddError("objetivo vacío")
		return res
	}

	// Aceptar "host:puerto" como atajo.
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		var single int
		if _, serr := fmt.Sscanf(p, "%d", &single); serr == nil {
			ports = []int{single}
		}
	}
	if h := strings.Trim(host, "[]"); h != host {
		host = h
	}

	scan := ports
	if len(scan) == 0 {
		scan = DefaultScanPorts
	}
	// Validar puertos.
	valid := make([]int, 0, len(scan))
	for _, p := range scan {
		if p < 1 || p > 65535 {
			res.AddError("puerto fuera de rango ignorado: %d", p)
			continue
		}
		valid = append(valid, p)
	}
	if len(valid) == 0 {
		res.Status = "error"
		res.AddError("sin puertos válidos que escanear")
		return res
	}

	findings := make([]PortFinding, 0, len(valid))
	for _, p := range valid {
		f := PortFinding{Port: p, Service: "unknown"}
		if s, ok := commonServices[p]; ok {
			f.Service = s
		}
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", p))
		conn, err := net.DialTimeout("tcp", addr, DialTimeoutTCP)
		if err != nil {
			// Puerto cerrado/filtrado u host irresoluble: no es error del
			// módulo, se registra como cerrado.
			findings = append(findings, f)
			continue
		}
		f.Open = true
		// Banner grabbing con deadline de lectura de 2s.
		_ = conn.SetReadDeadline(time.Now().Add(BannerTimeout))
		buf := make([]byte, 1024)
		if n, rerr := conn.Read(buf); rerr == nil && n > 0 {
			f.Banner = strings.TrimSpace(sanitizeBanner(string(buf[:n])))
		}
		_ = conn.Close()
		findings = append(findings, f)
	}

	res.AddSource("TCP connect scan + banner grab (observado, no inferido)")
	res.Data = PortscanData{
		Findings: findings,
		Notes:    []string{"alcance: solo TCP; UDP no escaneado"},
	}
	return res
}

// sanitizeBanner elimina caracteres de control del banner para salida segura.
func sanitizeBanner(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		if r == 127 {
			return -1
		}
		return r
	}, s)
}
