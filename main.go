package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
)

const (
	baseURL       = "https://ai.rebelscum.network"
	cookieName    = "_oauth2_proxy"
	// TODO: Verify this Client ID with Authentik configuration
	oauthAudience = "ai.rebelscum.network"
)

//go:embed templates/quickstart.html
var quickstartTemplate string

//go:embed assets/*
var assetsFS embed.FS

type pageData struct {
	BaseURL          string
	CookieValue      string
	CookieJarSnippet string
	CookiePresent    bool
	CookieName       string
	OauthAudience    string
}

type sessionResponse struct {
	BaseURL          string `json:"baseUrl"`
	CookieName       string `json:"cookieName"`
	CookieValue      string `json:"cookieValue,omitempty"`
	CookieJarSnippet string `json:"cookieJarSnippet"`
	CookiePresent    bool   `json:"cookiePresent"`
}

func main() {
	tmpl := template.Must(template.New("quickstart").Parse(quickstartTemplate))

	assetsSub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		log.Fatalf("asset mount error: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/quickstart/static/", noCache(http.StripPrefix("/quickstart/static/", http.FileServer(http.FS(assetsSub)))))
	mux.Handle("/quickstart/api/session", noCache(http.HandlerFunc(handleSession)))
	mux.Handle("/quickstart", noCache(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleQuickstart(w, r, tmpl)
	})))
	mux.Handle("/quickstart/", noCache(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleQuickstart(w, r, tmpl)
	})))

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Println("llm-quickstart listening on :8080")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func handleQuickstart(w http.ResponseWriter, r *http.Request, tmpl *template.Template) {
	data := buildPageData(r)

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

func handleSession(w http.ResponseWriter, r *http.Request) {
	data := buildPageData(r)

	response := sessionResponse{
		BaseURL:          data.BaseURL,
		CookieName:       data.CookieName,
		CookieValue:      data.CookieValue,
		CookieJarSnippet: data.CookieJarSnippet,
		CookiePresent:    data.CookiePresent,
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(response); err != nil {
		http.Error(w, "Failed to render session", http.StatusInternalServerError)
	}
}

func buildPageData(r *http.Request) pageData {
	cookieValue := ""
	currentCookieName := cookieName

	// Try to find an efficient Authentik cookie if the default one isn't present
	// or if we want to prioritize Authentik.
	found := false
	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, "authentik_proxy") {
			currentCookieName = cookie.Name
			cookieValue = cookie.Value
			found = true
			break
		}
	}

	// Fallback to strict name check if not found via prefix
	if !found {
		if cookie, err := r.Cookie(cookieName); err == nil {
			cookieValue = cookie.Value
		}
	}

	data := pageData{
		BaseURL:       baseURL,
		CookieValue:   cookieValue,
		CookiePresent: cookieValue != "",
		CookieName:    currentCookieName,
		OauthAudience: oauthAudience,
	}

	if data.CookiePresent {
		data.CookieJarSnippet = fmt.Sprintf(
			"# Netscape HTTP Cookie File\n%s\tFALSE\t/\tTRUE\t0\t%s\t%s",
			"ai.rebelscum.network",
			currentCookieName,
			cookieValue,
		)
	} else {
		data.CookieJarSnippet = "# Cookie missing. Visit /outpost.goauthentik.io/start to authenticate."
	}

	return data
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
