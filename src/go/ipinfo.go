// Módulo 06 IPINFO: geolocalización aproximada, ASN/ISP y reverse DNS.
//
// Contrato API:
//   - RunIPInfo(target string) Result con Data de tipo IPInfoData.
//   - Fuente: http://ip-api.com/json/<ip>?fields=... (plan gratuito, HTTP,
//     timeout 5s) + reverse DNS local (LookupAddr).
//   - Valida que el objetivo sea una IP (v4/v6) con net.ParseIP; rechaza
//     rangos privados/reservados para la consulta remota con error explícito
//     (pero aún intenta reverse DNS local).
package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
)

// IPInfoData agrupa los hallazgos del módulo IPINFO.
type IPInfoData struct {
	IP         string   `json:"ip"`
	ReverseDNS []string `json:"reverse_dns,omitempty"`
	Country    string   `json:"country,omitempty"`
	Region     string   `json:"region,omitempty"`
	City       string   `json:"city,omitempty"`
	ISP        string   `json:"isp,omitempty"`
	Org        string   `json:"org,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	Notes      []string `json:"notes,omitempty"`
}

// ipAPIResponse modela la respuesta JSON de ip-api.com (campos solicitados).
type ipAPIResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Country string `json:"country"`
	Region  string `json:"regionName"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
	Query   string `json:"query"`
}

// RunIPInfo consulta ip-api.com y reverse DNS para la IP dada.
func RunIPInfo(target string) Result {
	ipStr := strings.TrimSpace(target)
	res := NewResult("ipinfo", ipStr)

	ip := net.ParseIP(ipStr)
	if ip == nil {
		res.Status = "error"
		res.AddError("IP inválida: %q", target)
		res.Status = "error"
		return res
	}

	var data IPInfoData
	data.IP = ip.String()

	// Reverse DNS local (no revela nada que el DNS no publique).
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	names, rerr := net.DefaultResolver.LookupAddr(ctx, ip.String())
	cancel()
	if rerr == nil {
		for _, n := range names {
			data.ReverseDNS = append(data.ReverseDNS, strings.TrimSuffix(n, "."))
		}
		if len(names) > 0 {
			res.AddSource("reverse DNS (PTR)")
		}
	} else {
		res.AddError("reverse DNS: %v", rerr)
	}

	// Las IPs privadas/reservadas no se consultan al servicio remoto.
	if !isGlobalUnicast(ip) {
		res.AddError("IP no pública (%s): consulta remota omitida; solo reverse DNS local", ip.String())
		res.Data = data
		return res
	}

	apiURL := "http://ip-api.com/json/" + ip.String() +
		"?fields=status,message,country,regionName,city,isp,org,as,query"
	resp, err := httpGet(apiURL, DefaultTimeout)
	if err != nil {
		res.AddError("ip-api.com: %v", err)
		res.Data = data
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		res.AddError("ip-api.com: HTTP %d", resp.StatusCode)
		res.Data = data
		return res
	}
	var api ipAPIResponse
	if derr := json.NewDecoder(resp.Body).Decode(&api); derr != nil {
		res.AddError("ip-api.com: respuesta no JSON: %v", derr)
		res.Data = data
		return res
	}
	if api.Status != "success" {
		res.AddError("ip-api.com: %s", api.Message)
		res.Data = data
		return res
	}
	data.Country = api.Country
	data.Region = api.Region
	data.City = api.City
	data.ISP = api.ISP
	data.Org = api.Org
	data.ASN = api.AS
	data.Notes = []string{"geolocalización aproximada a nivel ciudad/ISP, no exacta"}
	res.AddSource("http://ip-api.com (plan gratuito)")
	res.Data = data
	return res
}

// isGlobalUnicast indica si la IP es enrutable públicamente.
func isGlobalUnicast(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsMulticast() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast()
}
