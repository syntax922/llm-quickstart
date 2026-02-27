package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	baseURL       = "https://ai.rebelscum.network"
	cookieName    = "_oauth2_proxy"
	// TODO: Verify this Client ID with Authentik configuration
	oauthAudience = "ai.rebelscum.network"
)

// ──────────────────────────────────────────────────────────────
// Tool registry — defines every MCP tool the backend can execute
// ──────────────────────────────────────────────────────────────

// ToolDefinition is the OpenAI-compatible tool schema sent to the LLM.
type ToolDefinition struct {
	Type     string       `json:"type"`
	Function FunctionDef  `json:"function"`
}

type FunctionDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// ToolCallRequest is what the frontend POSTs to /studio/api/tools/execute.
type ToolCallRequest struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ToolCallResponse is returned from /studio/api/tools/execute.
type ToolCallResponse struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Error   string `json:"error,omitempty"`
}

// ToolsListResponse wraps the tool definitions for the frontend.
type ToolsListResponse struct {
	Tools []ToolDefinition `json:"tools"`
}

// searxngURL is the SearXNG API base. Configurable via SEARXNG_URL env var.
var searxngURL = envOrDefault("SEARXNG_URL", "http://searxng.searxng.svc.cluster.local:8080")

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// registeredTools is the canonical list of tools the UI + LLM can use.
var registeredTools = []ToolDefinition{
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "web_search",
			Description: "Search the web using SearXNG. Returns a list of search results with titles, URLs, and content snippets. Use this when the user asks about current events, wants to look something up, or needs real-time information.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"query": {
						"type": "string",
						"description": "The search query to look up on the web"
					}
				},
				"required": ["query"]
			}`),
		},
	},
	{
		Type: "function",
		Function: FunctionDef{
			Name:        "fetch_page",
			Description: "Fetch the full text content of a web page by URL. Use this to read articles, documentation, or any publicly accessible web page after finding it via web_search.",
			Parameters: json.RawMessage(`{
				"type": "object",
				"properties": {
					"url": {
						"type": "string",
						"description": "The URL of the web page to fetch"
					}
				},
				"required": ["url"]
			}`),
		},
	},
}

// HTTP client with reasonable timeouts for tool execution.
var toolHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

// executeTool dispatches a tool call to the correct handler.
func executeTool(name string, args json.RawMessage) ToolCallResponse {
	switch name {
	case "web_search":
		return executeWebSearch(args)
	case "fetch_page":
		return executeFetchPage(args)
	default:
		return ToolCallResponse{Name: name, Error: fmt.Sprintf("unknown tool: %s", name)}
	}
}

// ── SearXNG web_search ──────────────────────────────────────

type webSearchArgs struct {
	Query string `json:"query"`
}

type searxngResponse struct {
	Results []searxngResult `json:"results"`
}

type searxngResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Content string `json:"content"`
	Engine  string `json:"engine"`
}

func executeWebSearch(args json.RawMessage) ToolCallResponse {
	var a webSearchArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return ToolCallResponse{Name: "web_search", Error: fmt.Sprintf("invalid arguments: %v", err)}
	}
	if a.Query == "" {
		return ToolCallResponse{Name: "web_search", Error: "query is required"}
	}

	req, err := http.NewRequest("GET", searxngURL+"/search", nil)
	if err != nil {
		return ToolCallResponse{Name: "web_search", Error: err.Error()}
	}
	q := req.URL.Query()
	q.Set("q", a.Query)
	q.Set("format", "json")
	q.Set("categories", "general")
	req.URL.RawQuery = q.Encode()

	log.Printf("[tool] web_search query=%q url=%s", a.Query, req.URL.String())

	resp, err := toolHTTPClient.Do(req)
	if err != nil {
		return ToolCallResponse{Name: "web_search", Error: fmt.Sprintf("searxng request failed: %v", err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return ToolCallResponse{Name: "web_search", Error: fmt.Sprintf("failed to read response: %v", err)}
	}

	if resp.StatusCode != 200 {
		return ToolCallResponse{Name: "web_search", Error: fmt.Sprintf("searxng returned %d: %s", resp.StatusCode, string(body[:min(len(body), 500)]))}
	}

	var sr searxngResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return ToolCallResponse{Name: "web_search", Error: fmt.Sprintf("failed to parse searxng response: %v", err)}
	}

	// Format results as readable text for the LLM (cap at 10 results).
	maxResults := 10
	if len(sr.Results) < maxResults {
		maxResults = len(sr.Results)
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Search results for: %s\n\n", a.Query))
	for i, r := range sr.Results[:maxResults] {
		content := r.Content
		if len(content) > 500 {
			content = content[:500] + "..."
		}
		fmt.Fprintf(&buf, "%d. **%s**\n   URL: %s\n   %s\n\n", i+1, r.Title, r.URL, content)
	}
	if len(sr.Results) > maxResults {
		fmt.Fprintf(&buf, "(%d more results omitted)\n", len(sr.Results)-maxResults)
	}

	log.Printf("[tool] web_search returned %d results for %q", len(sr.Results), a.Query)
	return ToolCallResponse{Name: "web_search", Content: buf.String()}
}

// ── fetch_page ──────────────────────────────────────────────

type fetchPageArgs struct {
	URL string `json:"url"`
}

func executeFetchPage(args json.RawMessage) ToolCallResponse {
	var a fetchPageArgs
	if err := json.Unmarshal(args, &a); err != nil {
		return ToolCallResponse{Name: "fetch_page", Error: fmt.Sprintf("invalid arguments: %v", err)}
	}
	if a.URL == "" {
		return ToolCallResponse{Name: "fetch_page", Error: "url is required"}
	}

	// Basic validation — must be http(s).
	if !strings.HasPrefix(a.URL, "http://") && !strings.HasPrefix(a.URL, "https://") {
		return ToolCallResponse{Name: "fetch_page", Error: "url must start with http:// or https://"}
	}

	log.Printf("[tool] fetch_page url=%s", a.URL)

	req, err := http.NewRequest("GET", a.URL, nil)
	if err != nil {
		return ToolCallResponse{Name: "fetch_page", Error: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LLMQuickstart/1.0)")
	req.Header.Set("Accept", "text/html,text/plain,application/json")

	resp, err := toolHTTPClient.Do(req)
	if err != nil {
		return ToolCallResponse{Name: "fetch_page", Error: fmt.Sprintf("fetch failed: %v", err)}
	}
	defer resp.Body.Close()

	// Limit to 100KB to avoid overwhelming the LLM context.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return ToolCallResponse{Name: "fetch_page", Error: fmt.Sprintf("failed to read page: %v", err)}
	}

	if resp.StatusCode != 200 {
		return ToolCallResponse{Name: "fetch_page", Error: fmt.Sprintf("page returned %d", resp.StatusCode)}
	}

	// Strip HTML tags for cleaner LLM consumption.
	text := stripHTMLTags(string(body))

	// Collapse whitespace runs
	text = collapseWhitespace(text)

	if len(text) > 50000 {
		text = text[:50000] + "\n\n[Content truncated at 50,000 characters]"
	}

	log.Printf("[tool] fetch_page returned %d chars from %s", len(text), a.URL)
	return ToolCallResponse{Name: "fetch_page", Content: text}
}

// stripHTMLTags is a simple tag remover (no dependency needed for this).
func stripHTMLTags(s string) string {
	var buf bytes.Buffer
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			buf.WriteRune(' ')
		case !inTag:
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// collapseWhitespace reduces runs of whitespace to single spaces/newlines.
func collapseWhitespace(s string) string {
	var buf bytes.Buffer
	prevSpace := false
	for _, r := range s {
		if r == '\n' || r == '\r' {
			if !prevSpace {
				buf.WriteRune('\n')
			}
			prevSpace = true
		} else if r == ' ' || r == '\t' {
			if !prevSpace {
				buf.WriteRune(' ')
			}
			prevSpace = true
		} else {
			buf.WriteRune(r)
			prevSpace = false
		}
	}
	return buf.String()
}

// ── Concurrent tool executor ────────────────────────────────

// executeToolsConcurrently runs multiple tool calls in parallel and returns
// results in the same order as the input.
func executeToolsConcurrently(calls []ToolCallRequest) []ToolCallResponse {
	results := make([]ToolCallResponse, len(calls))
	var wg sync.WaitGroup
	for i, call := range calls {
		wg.Add(1)
		go func(idx int, c ToolCallRequest) {
			defer wg.Done()
			results[idx] = executeTool(c.Name, c.Arguments)
		}(i, call)
	}
	wg.Wait()
	return results
}

//go:embed templates/quickstart.html
var quickstartTemplate string

//go:embed assets/*
var assetsFS embed.FS

//go:embed assets/studio.html
var studioTemplate string

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
	mux.Handle("/signout", noCache(http.HandlerFunc(handleSignOut)))
	mux.Handle("/quickstart", noCache(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleQuickstart(w, r, tmpl)
	})))
	mux.Handle("/quickstart/", noCache(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleQuickstart(w, r, tmpl)
	})))
	mux.Handle("/studio", noCache(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleStudio(w, r)
	})))

	// ── Tool API endpoints ──────────────────────────────────
	mux.Handle("/studio/api/tools/list", noCache(http.HandlerFunc(handleToolsList)))
	mux.Handle("/studio/api/tools/execute", noCache(http.HandlerFunc(handleToolsExecute)))

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Printf("llm-quickstart listening on :8080 (searxng=%s, tools=%d)", searxngURL, len(registeredTools))
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

func handleSignOut(w http.ResponseWriter, r *http.Request) {
	// iterate all cookies and delete any relevant ones
	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, "authentik_proxy") || cookie.Name == cookieName {
			// Clear the cookie
			http.SetCookie(w, &http.Cookie{
				Name:   cookie.Name,
				Value:  "",
				Path:   "/",
				Domain: "ai.rebelscum.network",
				MaxAge: -1,
			})
		}
	}

	// Redirect to the Authentik OIDC end-session endpoint
	// This ensures the server-side session is also terminated
	http.Redirect(w, r, "https://auth.rebelscum.network/application/o/llm-gateway/end-session/", http.StatusFound)
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

func handleStudio(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := w.Write([]byte(studioTemplate))
	if err != nil {
		http.Error(w, "Failed to render studio", http.StatusInternalServerError)
	}
}

// ── Tool API Handlers ───────────────────────────────────────

// handleToolsList returns the list of available tools as OpenAI-compatible
// tool definitions. The frontend injects these into chat completion requests.
func handleToolsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := ToolsListResponse{Tools: registeredTools}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[tools] failed to encode tools list: %v", err)
	}
}

// handleToolsExecute receives one or more tool calls from the frontend,
// executes them concurrently, and returns the results.
func handleToolsExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024))
	if err != nil {
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Accept either a single tool call or an array.
	var calls []ToolCallRequest
	if len(body) > 0 && body[0] == '[' {
		if err := json.Unmarshal(body, &calls); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON array: %v", err), http.StatusBadRequest)
			return
		}
	} else {
		var single ToolCallRequest
		if err := json.Unmarshal(body, &single); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
		calls = []ToolCallRequest{single}
	}

	if len(calls) == 0 {
		http.Error(w, "no tool calls provided", http.StatusBadRequest)
		return
	}

	log.Printf("[tools] executing %d tool call(s): %s", len(calls), toolNames(calls))

	results := executeToolsConcurrently(calls)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		log.Printf("[tools] failed to encode results: %v", err)
	}
}

// toolNames returns a comma-separated string of tool names for logging.
func toolNames(calls []ToolCallRequest) string {
	names := make([]string, len(calls))
	for i, c := range calls {
		names[i] = c.Name
	}
	return strings.Join(names, ", ")
}
