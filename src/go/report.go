// Módulo 09 REPORT: persistencia de Result en JSON/TXT/HTML.
//
// Contrato API:
//   - SaveReport(r Result, format, path string) error.
//   - format admite "json", "txt" o "html" (insensible a mayúsculas, con o
//     sin punto inicial). Cualquier otro valor es error explícito.
//   - path vacío o con directorio inexistente es error explícito.
//   - RenderTXT(r Result) string y RenderHTML(r Result) string exponen las
//     representaciones para reuso (p. ej. menú consola).
package main

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

// SaveReport serializa r en el formato pedido y lo escribe en path
// (crea el fichero, no directorios: el directorio debe existir).
func SaveReport(r Result, format, path string) error {
	format = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(format), "."))
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("report: ruta vacía")
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("report: no se pudo crear directorio %s: %w", dir, err)
		}
	}
	var (
		data []byte
		err  error
	)
	switch format {
	case "json":
		data, err = json.MarshalIndent(r, "", "  ")
		if err != nil {
			return fmt.Errorf("report json: %w", err)
		}
		data = append(data, '\n')
	case "txt":
		data = []byte(RenderTXT(r))
	case "html":
		data = []byte(RenderHTML(r))
	default:
		return fmt.Errorf("report: formato %q no soportado (json|txt|html)", format)
	}
	if werr := os.WriteFile(path, data, 0o644); werr != nil {
		return fmt.Errorf("report: escribir %s: %w", path, werr)
	}
	return nil
}

// RenderTXT devuelve una representación humana legible del Result.
func RenderTXT(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "OSINT-X report\n")
	fmt.Fprintf(&b, "module:       %s\n", r.Module)
	fmt.Fprintf(&b, "target:       %s\n", r.Target)
	fmt.Fprintf(&b, "status:       %s\n", r.Status)
	fmt.Fprintf(&b, "retrieved_at: %s\n", r.RetrievedAt)
	if len(r.Sources) > 0 {
		fmt.Fprintf(&b, "sources:\n")
		for _, s := range r.Sources {
			fmt.Fprintf(&b, "  - %s\n", s)
		}
	}
	fmt.Fprintf(&b, "data:\n")
	if r.Data == nil {
		fmt.Fprintf(&b, "  (sin datos)\n")
	} else if raw, err := json.MarshalIndent(r.Data, "  ", "  "); err == nil {
		b.WriteString("  ")
		b.Write(raw)
		b.WriteString("\n")
	} else {
		fmt.Fprintf(&b, "  (no serializable: %v)\n", err)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "errors:\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "  ! %s\n", e)
		}
	}
	return b.String()
}

// RenderHTML devuelve un informe HTML autónomo con escape de contenido.
func RenderHTML(r Result) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">\n")
	fmt.Fprintf(&b, "<title>OSINT-X · %s · %s</title>\n", html.EscapeString(r.Module), html.EscapeString(r.Target))
	b.WriteString("<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;padding:0 1em}" +
		"pre{background:#f4f4f4;padding:1em;overflow:auto}" +
		".err{color:#a00}</style>\n</head>\n<body>\n")
	fmt.Fprintf(&b, "<h1>OSINT-X · %s</h1>\n", html.EscapeString(r.Module))
	fmt.Fprintf(&b, "<p><strong>Target:</strong> %s<br>\n", html.EscapeString(r.Target))
	fmt.Fprintf(&b, "<strong>Status:</strong> %s<br>\n", html.EscapeString(r.Status))
	fmt.Fprintf(&b, "<strong>Retrieved at:</strong> %s</p>\n", html.EscapeString(r.RetrievedAt))
	if len(r.Sources) > 0 {
		b.WriteString("<h2>Sources</h2>\n<ul>\n")
		for _, s := range r.Sources {
			fmt.Fprintf(&b, "<li>%s</li>\n", html.EscapeString(s))
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString("<h2>Data</h2>\n<pre>\n")
	if r.Data == nil {
		b.WriteString("(sin datos)\n")
	} else if raw, err := json.MarshalIndent(r.Data, "", "  "); err == nil {
		b.WriteString(html.EscapeString(string(raw)))
		b.WriteString("\n")
	} else {
		fmt.Fprintf(&b, "(no serializable: %s)\n", html.EscapeString(err.Error()))
	}
	b.WriteString("</pre>\n")
	if len(r.Errors) > 0 {
		b.WriteString("<h2>Errors</h2>\n<ul>\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "<li class=\"err\">%s</li>\n", html.EscapeString(e))
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString("</body>\n</html>\n")
	return b.String()
}
