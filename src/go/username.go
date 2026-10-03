// Módulo 05 USERNAME: comprobación de presencia pública por plataforma.
//
// Contrato API:
//   - RunUsername(target string) Result con Data de tipo UsernameData.
//   - Valida sintaxis del handle y consulta perfiles públicos vía HEAD
//     (con reintento GET si el HEAD es rechazado con 403/405).
//   - Veredicto honesto por plataforma: "found" solo con HTTP 200,
//     "not_found" con 404, "uncertain" en cualquier otro caso (bloqueos
//     anti-bot, login obligatorio, etc.). Nada se afirma sin evidencia.
//   - Peticiones concurrentes, timeout 5s por plataforma.
package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

var handleRe = regexp.MustCompile(`^[A-Za-z0-9._-]{2,39}$`)

// platform es una plataforma con plantilla de URL de perfil público.
type platform struct {
	Name string
	URL  string // %s = handle
}

// platforms usa URLs de perfil público directo (sin API keys).
var platforms = []platform{
	{"GitHub", "https://github.com/%s"},
	{"GitLab", "https://gitlab.com/%s"},
	{"Reddit", "https://www.reddit.com/user/%s"},
	{"Medium", "https://medium.com/@%s"},
	{"X", "https://x.com/%s"},
	{"Instagram", "https://www.instagram.com/%s/"},
	{"TikTok", "https://www.tiktok.com/@%s"},
	{"Twitch", "https://www.twitch.tv/%s"},
	{"Pinterest", "https://www.pinterest.com/%s/"},
	{"DockerHub", "https://hub.docker.com/u/%s"},
}

// UsernameFinding es el veredicto por plataforma.
type UsernameFinding struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
	Status   int    `json:"http_status,omitempty"`
	Verdict  string `json:"verdict"` // found | not_found | uncertain | error
	Detail   string `json:"detail,omitempty"`
}

// UsernameData agrupa los hallazgos del módulo USERNAME.
type UsernameData struct {
	Findings []UsernameFinding `json:"findings"`
	Notes    []string          `json:"notes"`
}

// RunUsername comprueba la presencia del handle en cada plataforma.
func RunUsername(target string) Result {
	handle := strings.TrimSpace(target)
	res := NewResult("username", handle)

	if !handleRe.MatchString(handle) {
		res.Status = "error"
		res.AddError("handle inválido %q: 2-39 caracteres [A-Za-z0-9._-]", target)
		res.Status = "error"
		return res
	}

	findings := make([]UsernameFinding, len(platforms))
	var wg sync.WaitGroup
	for i, p := range platforms {
		wg.Add(1)
		go func(i int, p platform) {
			defer wg.Done()
			u := fmt.Sprintf(p.URL, handle)
			findings[i] = checkProfile(p.Name, u)
		}(i, p)
	}
	wg.Wait()

	for _, f := range findings {
		res.AddSource(f.URL)
	}
	res.Data = UsernameData{
		Findings: findings,
		Notes: []string{
			"found exige HTTP 200; ciertos sitios devuelven 200 tras login/consentimiento: revisar manualmente",
			"uncertain incluye 403/429/bloqueos anti-bot: no es evidencia de existencia",
		},
	}
	return res
}

// checkProfile consulta un perfil con HEAD y reintenta con GET si el
// servidor rechaza HEAD (403/405), clasificando el veredicto sin inventar.
func checkProfile(name, url string) UsernameFinding {
	f := UsernameFinding{Platform: name, URL: url}

	code, err := headStatus(url)
	if err != nil {
		// Fallo de red con HEAD: un intento GET antes de rendirse.
		code, err = getStatus(url)
		if err != nil {
			f.Verdict = "error"
			f.Detail = fmt.Sprintf("red: %v", err)
			return f
		}
	}
	// Algunos servidores rechazan HEAD pero sirven GET.
	if (code == http.StatusForbidden || code == http.StatusMethodNotAllowed) && true {
		if gcode, gerr := getStatus(url); gerr == nil {
			code = gcode
		}
	}
	f.Status = code
	switch code {
	case http.StatusOK:
		f.Verdict = "found"
	case http.StatusNotFound:
		f.Verdict = "not_found"
	default:
		f.Verdict = "uncertain"
		f.Detail = fmt.Sprintf("HTTP %d sin evidencia concluyente", code)
	}
	return f
}

func headStatus(url string) (int, error) {
	resp, err := httpHead(url, DefaultTimeout)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func getStatus(url string) (int, error) {
	resp, err := httpGet(url, DefaultTimeout)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
