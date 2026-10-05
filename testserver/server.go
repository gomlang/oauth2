// Package testserver is an independent HTTP/TLS OAuth2 wire oracle used only by tests.
package testserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Server = *ServerState

type ServerState struct {
	server    *httptest.Server
	mu        sync.Mutex
	calls     int
	last      string
	challenge string
	arrived   chan struct{}
}

func Start(secure bool) Server {
	s := &ServerState{arrived: make(chan struct{}, 32)}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	if secure {
		s.server.StartTLS()
	} else {
		s.server.Start()
	}
	return s
}
func URL(s Server) string { return s.server.URL }
func Certificate(s Server) string {
	if s.server.Certificate() == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.server.Certificate().Raw}))
}
func Close(s Server)                   { s.server.Close() }
func Challenge(s Server, value string) { s.mu.Lock(); defer s.mu.Unlock(); s.challenge = value }
func Count(s Server) int               { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }
func Last(s Server) string             { s.mu.Lock(); defer s.mu.Unlock(); return s.last }
func Wait(s Server) bool {
	select {
	case <-s.arrived:
		return true
	case <-time.After(4 * time.Second):
		return false
	}
}
func fail(w http.ResponseWriter, why string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": why})
}
func (s Server) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()
	s.mu.Lock()
	s.calls++
	challenge := s.challenge
	snap, _ := json.Marshal(map[string]string{"method": r.Method, "body": string(raw), "authorization": r.Header.Get("Authorization"), "content_type": r.Header.Get("Content-Type"), "query": r.URL.RawQuery})
	s.last = string(snap)
	s.mu.Unlock()
	if r.URL.Path == "/wait" {
		select {
		case s.arrived <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		return
	}
	if r.URL.Path == "/redirect" {
		w.Header().Set("Location", s.server.URL+"/token")
		w.WriteHeader(307)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/minimal":
		_, _ = io.WriteString(w, `{"access_token":"minimal","token_type":"bearer"}`)
		return
	case "/uri-type":
		_, _ = io.WriteString(w, `{"access_token":"minimal","token_type":"urn:example:token","expires_in":9223372036854775807}`)
		return
	case "/spaced-uri-type":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"urn:example:bad type"}`)
		return
	case "/escaped-uri-type":
		_, _ = io.WriteString(w, `{"access_token":"minimal","token_type":"urn:example:bad%20type?x=%c3%a9"}`)
		return
	case "/unicode-uri-type":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"urn:example:é"}`)
		return
	case "/invalid-error-uri-char":
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_uri":"/details|raw"}`)
		return
	case "/invalid-error-uri":
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_uri":"https://server.example/error?bad=%GG"}`)
		return
	case "/bad-type":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"bad type"}`)
		return
	case "/duplicate-extension":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"Bearer","extra":1,"extra":2}`)
		return
	case "/wrong-scope":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"Bearer","scope":[]}`)
		return
	case "/empty-token":
		_, _ = io.WriteString(w, `{"access_token":"","token_type":"Bearer"}`)
		return
	case "/string-expires":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"Bearer","expires_in":"12"}`)
		return
	case "/duplicate-content":
		w.Header().Add("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"Bearer"}`)
		return
	case "/error":
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"server token-secret canary","error_uri":"https://server.example/error"}`)
		return
	case "/duplicate":
		_, _ = io.WriteString(w, `{"access_token":"one","access_token":"two","token_type":"Bearer"}`)
		return
	case "/invalid-expires":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"Bearer","expires_in":1.5}`)
		return
	case "/overflow-expires":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"Bearer","expires_in":9223372036854775808}`)
		return
	case "/negative-expires":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"Bearer","expires_in":-1}`)
		return
	case "/missing":
		_, _ = io.WriteString(w, `{"access_token":"one"}`)
		return
	case "/null":
		_, _ = io.WriteString(w, `{"access_token":"one","token_type":"Bearer","refresh_token":null}`)
		return
	case "/success-error":
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
		return
	case "/nonjson":
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `secret-canary`)
		return
	case "/invalid-json":
		_, _ = io.WriteString(w, `{"secret-canary":`)
		return
	case "/large":
		_, _ = io.WriteString(w, strings.Repeat("x", 8192))
		return
	case "/binary":
		_, _ = w.Write([]byte{255})
		return
	}
	if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
		fail(w, "method or headers")
		return
	}
	fields, err := url.ParseQuery(string(raw))
	if err != nil {
		fail(w, "form parse")
		return
	}
	for _, v := range fields {
		if len(v) != 1 {
			fail(w, "duplicate form")
			return
		}
	}
	switch r.URL.Path {
	case "/public":
		if r.Header.Get("Authorization") != "" || fields.Get("client_id") != "client :+é" || fields.Has("client_secret") {
			fail(w, "public auth")
			return
		}
	case "/post":
		if r.Header.Get("Authorization") != "" || fields.Get("client_id") != "client :+é" || fields.Get("client_secret") != "secret :+é" {
			fail(w, "post auth")
			return
		}
	default:
		id, password, ok := r.BasicAuth()
		id, ide := url.QueryUnescape(id)
		password, pe := url.QueryUnescape(password)
		if !ok || ide != nil || pe != nil || id != "client :+é" || password != "secret :+é" || fields.Has("client_id") || fields.Has("client_secret") {
			fail(w, "basic form credentials")
			return
		}
	}
	switch fields.Get("grant_type") {
	case "authorization_code":
		verifier := fields.Get("code_verifier")
		if len(verifier) < 43 || len(verifier) > 128 {
			fail(w, "verifier length")
			return
		}
		for _, r := range verifier {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~", r) {
				fail(w, "verifier alphabet")
				return
			}
		}
		sum := sha256.Sum256([]byte(verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || fields.Get("code") != "code :+é" || fields.Get("redirect_uri") != "https://client.example/callback?fixed=yes" {
			fail(w, "code PKCE or redirect binding")
			return
		}
	case "refresh_token":
		if fields.Get("scope") != "read" {
			fail(w, "refresh scope")
			return
		}
		if fields.Get("refresh_token") != "refresh&value" {
			fail(w, "refresh form")
			return
		}
	case "client_credentials":
		if r.URL.Path == "/public" {
			fail(w, "public credentials grant")
			return
		}
	default:
		fail(w, "grant")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, _ = io.WriteString(w, `{"access_token":"access:test+value","token_type":"Bearer","expires_in":0,"refresh_token":"refresh&value","scope":"read write","ignored":{"extension":true}}`)
}

func CheckAuthorization(s Server, raw string) bool {
	u, e := url.Parse(raw)
	if e != nil {
		return false
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return false
	}
	for _, v := range q {
		if len(v) != 1 {
			return false
		}
	}
	s.mu.Lock()
	challenge := s.challenge
	s.mu.Unlock()
	return u.Scheme == "https" && u.Host == "server.example" && u.Path == "/authorize" && q.Get("kept") == "a+b" && q.Get("client_id") == "client :+é" && q.Get("response_type") == "code" && q.Get("redirect_uri") == "https://client.example/callback?fixed=yes" && q.Get("scope") == "read write" && q.Get("code_challenge_method") == "S256" && q.Get("code_challenge") == challenge && len(q.Get("state")) == 43 && !q.Has("client_secret") && !q.Has("code_verifier")
}
