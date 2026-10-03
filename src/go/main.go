// OSINT-X · core Go (solo stdlib).
//
// Menú consola 01-09 + 00 EXIT. Cada opción ejecuta su módulo y muestra el
// Result como JSON (contrato común). La opción 09 REPORT guarda el último
// resultado en JSON/TXT/HTML vía SaveReport.
//
// Uso:
//
//	go run .            # menú interactivo
//	go vet ./...        # verificación estática
//	go build -o osintx . # binario
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 1024*1024)
	var last *Result

	for {
		printMenu()
		fmt.Print("> ")
		if !in.Scan() {
			fmt.Println("\nEOF: salida.")
			return
		}
		opt := strings.TrimSpace(in.Text())
		switch opt {
		case "00", "0", "exit", "quit", "q":
			fmt.Println("OSINT-X: fin de sesión.")
			return
		case "01":
			target := ask(in, "dominio (p. ej. example.com)")
			if target == "" {
				fmt.Println("error: objetivo vacío.")
				continue
			}
			r := RunDomain(target)
			emit(&last, r)
		case "02":
			target := ask(in, "host (IP o nombre; admite host:puerto)")
			if target == "" {
				fmt.Println("error: objetivo vacío.")
				continue
			}
			ports := parsePorts(ask(in, "puertos separados por coma [vacío = comunes]"))
			r := RunPortscan(target, ports)
			emit(&last, r)
		case "03":
			target := ask(in, "dominio base (p. ej. example.com)")
			if target == "" {
				fmt.Println("error: objetivo vacío.")
				continue
			}
			r := RunSubdomain(target)
			emit(&last, r)
		case "04":
			target := ask(in, "teléfono en formato internacional (+34...)")
			if target == "" {
				fmt.Println("error: objetivo vacío.")
				continue
			}
			r := RunPhone(target)
			emit(&last, r)
		case "05":
			target := ask(in, "username (2-39 [A-Za-z0-9._-])")
			if target == "" {
				fmt.Println("error: objetivo vacío.")
				continue
			}
			r := RunUsername(target)
			emit(&last, r)
		case "06":
			target := ask(in, "IP pública (v4/v6)")
			if target == "" {
				fmt.Println("error: objetivo vacío.")
				continue
			}
			r := RunIPInfo(target)
			emit(&last, r)
		case "07":
			target := ask(in, "email (p. ej. user@example.com)")
			if target == "" {
				fmt.Println("error: objetivo vacío.")
				continue
			}
			r := RunEmail(target)
			emit(&last, r)
		case "08":
			target := ask(in, "URL (http(s)://...)")
			if target == "" {
				fmt.Println("error: objetivo vacío.")
				continue
			}
			r := RunURL(target)
			emit(&last, r)
		case "09":
			if last == nil {
				fmt.Println("error: aún no hay resultados; ejecuta un módulo 01-08 primero.")
				continue
			}
			format := strings.ToLower(strings.TrimSpace(ask(in, "formato (json/txt/html)")))
			path := strings.TrimSpace(ask(in, "ruta de salida (p. ej. report.json)"))
			if err := SaveReport(*last, format, path); err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			fmt.Printf("informe %s guardado en %s\n", format, path)
		default:
			fmt.Printf("opción %q no válida; usa 01-09 o 00.\n", opt)
		}
	}
}

// printMenu muestra el menú principal.
func printMenu() {
	fmt.Println()
	fmt.Println("=== OSINT-X (Go) ===")
	fmt.Println("01 DOMAIN     02 PORTSCAN   03 SUBDOMAIN")
	fmt.Println("04 PHONE      05 USERNAME   06 IPINFO")
	fmt.Println("07 EMAIL      08 URL        09 REPORT (guardar último)")
	fmt.Println("00 EXIT")
}

// ask pide una línea de entrada con etiqueta.
func ask(in *bufio.Scanner, label string) string {
	fmt.Printf("%s: ", label)
	if !in.Scan() {
		return ""
	}
	return strings.TrimSpace(in.Text())
}

// emit guarda el resultado como último y lo imprime en JSON.
func emit(last **Result, r Result) {
	*last = &r
	r.PrintJSON()
}

// parsePorts convierte "80,443, 8080" en []int; vacío -> nil (defecto).
func parsePorts(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		p, err := strconv.Atoi(f)
		if err != nil || p < 1 || p > 65535 {
			fmt.Printf("aviso: puerto ignorado: %q\n", f)
			continue
		}
		out = append(out, p)
	}
	return out
}
