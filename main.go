package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
)

const (
	baseURL       = "https://ai.sras623.com"
	cookieName    = "_oauth2_proxy"
	oauthAudience = "461475759178-sbdrb9og4193f629cq44n9u3iadqtnnj.apps.googleusercontent.com"
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

	mux := http.NewServeMux()
	mux.Handle("/static/", noCache(http.StripPrefix("/static/", http.FileServer(http.FS(assetsFS)))))
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
	if cookie, err := r.Cookie(cookieName); err == nil {
		cookieValue = cookie.Value
	}

	data := pageData{
		BaseURL:       baseURL,
		CookieValue:   cookieValue,
		CookiePresent: cookieValue != "",
		CookieName:    cookieName,
		OauthAudience: oauthAudience,
	}

	if data.CookiePresent {
		data.CookieJarSnippet = fmt.Sprintf(
			"# Netscape HTTP Cookie File\n%s\tFALSE\t/\tTRUE\t0\t%s\t%s",
			"ai.sras623.com",
			cookieName,
			cookieValue,
		)
	} else {
		data.CookieJarSnippet = "# Cookie missing. Visit /oauth2/sign_in to authenticate."
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
