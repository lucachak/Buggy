package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testConfig() Config {
	return Config{
		Concurrency: 4,
		Timeout:     2,
		Retry:       1,
		Silent:      true,
		FilterCodes: map[int]bool{404: true},
		MaxDepth:    1,
	}
}

func TestSoft404TemplateIsFiltered(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"name":"api","ok":true}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><h1>Not found</h1><p>%s does not exist</p></html>", r.URL.Path)
	}))
	defer server.Close()

	s := New(testConfig())
	s.Run([]string{server.URL}, []string{"/missing", "/api"})
	results := s.Results()
	if len(results) != 1 || results[0].URL != server.URL+"/api" {
		t.Fatalf("expected only the real endpoint, got %#v", results)
	}
}

func TestRecursiveScanRevisitsRealDirectoryConcurrently(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api", "/api/users":
			fmt.Fprint(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.Recursive = true
	s := New(cfg)
	s.RunRecursive([]string{server.URL}, []string{"/api", "/users"})
	results := s.Results()
	seen := map[string]bool{}
	for _, result := range results {
		seen[result.URL] = true
	}
	if !seen[server.URL+"/api"] || !seen[server.URL+"/api/users"] {
		t.Fatalf("expected recursive /api/users discovery, got %#v", results)
	}
}

func TestRecursiveScanUsesDirectorySpecificSoft404Template(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			fmt.Fprint(w, `{"api":true}`)
		case "/api/users":
			fmt.Fprint(w, `{"users":[]}`)
		default:
			if len(r.URL.Path) > len("/api/") && r.URL.Path[:len("/api/")] == "/api/" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"authentication required"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "not found: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.Recursive = true
	s := New(cfg)
	s.RunRecursive([]string{server.URL}, []string{"/api", "/users", "/missing"})
	results := s.Results()
	seen := map[string]bool{}
	for _, result := range results {
		seen[result.URL] = true
	}
	if !seen[server.URL+"/api/users"] {
		t.Fatalf("expected real nested endpoint, got %#v", results)
	}
	if seen[server.URL+"/api/missing"] {
		t.Fatalf("directory-specific 401 soft 404 was retained: %#v", results)
	}
}
