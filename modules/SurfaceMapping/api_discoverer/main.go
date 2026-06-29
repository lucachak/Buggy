package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type APIResult struct {
	URL          string            `json:"url"`
	Type         string            `json:"type"`
	Status       int               `json:"status"`
	Size         int64             `json:"size"`
	Headers      map[string]string `json:"headers"`
	HasOpenAPI   bool              `json:"has_openapi"`
	HasGraphQL   bool              `json:"has_graphql"`
	Endpoints    []string          `json:"endpoints_found"`
	IsAccessible bool              `json:"is_accessible"`
}

type FinalOutput struct {
	Results    []APIResult `json:"results"`
	TotalAPIs  int         `json:"total_apis"`
	OpenAPIs   []string    `json:"openapi_specs"`
	GraphQLs    []string    `json:"graphql_endpoints"`
	Swaggers    []string    `json:"swagger_uis"`
}

var (
	client *http.Client
	
	// Paths comuns de API para descobrir
	apiPaths = []string{
		// OpenAPI/Swagger
		"/swagger.json",
		"/swagger.yaml",
		"/swagger/v1/swagger.json",
		"/swagger/v2/swagger.json",
		"/swagger-ui.html",
		"/swagger/index.html",
		"/api/swagger.json",
		"/api-docs",
		"/api-docs.json",
		"/api/docs",
		"/api/v1/swagger.json",
		"/api/v2/swagger.json",
		"/openapi.json",
		"/openapi.yaml",
		"/v2/api-docs",
		"/v3/api-docs",
		
		// GraphQL
		"/graphql",
		"/graphiql",
		"/graphql/console",
		"/api/graphql",
		"/gql",
		"/query",
		"/graphql-explorer",
		"/altair",
		
		// REST APIs comuns
		"/api",
		"/api/v1",
		"/api/v2",
		"/api/v3",
		"/rest/api",
		"/services/rest",
		
		// Específicos de frameworks
		"/api/v1/",
		"/api/v2/",
		"/.rest",
		"/rest",
		"/REST",
		
		// Headless CMS
		"/wp-json/",
		"/wp-json/wp/v2/",
		"/ghost/api/v3/content/",
		"/content/api/",
		
		// WebServices
		"/ws",
		"/webservice",
		"/services/",
		"/service/",
		"/soap/",
	}
)

func init() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 30 * time.Second,
	}
	client = &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func discoverAPI(baseURL string, paths []string) []APIResult {
	var results []APIResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // 20 concurrent requests
	
	baseURL = strings.TrimRight(baseURL, "/")
	
	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			url := baseURL + p
			result := checkEndpoint(url)
			
			if result.IsAccessible {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(path)
	}
	
	wg.Wait()
	return results
}

func checkEndpoint(url string) APIResult {
	result := APIResult{
		URL:          url,
		IsAccessible: false,
	}
	
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Buggy/1.0 API-Discoverer")
	req.Header.Set("Accept", "application/json,text/html,application/xml,*/*")
	
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()
	
	result.Status = resp.StatusCode
	result.IsAccessible = (resp.StatusCode < 500)
	
	// Headers relevantes
	result.Headers = make(map[string]string)
	for k, v := range resp.Header {
		result.Headers[k] = strings.Join(v, ", ")
	}
	
	// Lê corpo para análise
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512KB
	result.Size = int64(len(body))
	bodyStr := string(body)
	
	// Detecta tipo de API
	if strings.Contains(bodyStr, "openapi") || 
	   strings.Contains(bodyStr, "swagger") ||
	   strings.Contains(bodyStr, "\"swagger\":") ||
	   strings.Contains(bodyStr, "\"openapi\":") {
		result.HasOpenAPI = true
		result.Type = "OpenAPI/Swagger"
		
		// Extrai endpoints da spec
		result.Endpoints = extractEndpointsFromOpenAPI(bodyStr)
	}
	
	if strings.Contains(bodyStr, "graphql") ||
	   strings.Contains(bodyStr, "GraphQL") ||
	   strings.Contains(bodyStr, "__schema") ||
	   strings.Contains(bodyStr, "query IntrospectionQuery") {
		result.HasGraphQL = true
		result.Type = "GraphQL"
	}
	
	// Detecta pelo Content-Type
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if strings.Contains(bodyStr, "paths") || strings.Contains(bodyStr, "endpoints") {
			result.Type = "REST API"
		}
	}
	
	// Detecta WordPress REST API
	if strings.Contains(bodyStr, "wp-json") || strings.Contains(bodyStr, "WP REST") {
		result.Type = "WordPress REST API"
	}
	
	return result
}

func extractEndpointsFromOpenAPI(spec string) []string {
	var endpoints []string
	
	// Parse simples para extrair paths
	lines := strings.Split(spec, "\n")
	inPaths := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.Contains(line, "\"paths\"") || strings.Contains(line, "paths:") {
			inPaths = true
			continue
		}
		
		if inPaths {
			// Detecta paths como "/users", "/posts/{id}"
			if strings.HasPrefix(line, "\"/") || strings.HasPrefix(line, "/") {
				path := strings.Trim(line, "\":,")
				path = strings.TrimSpace(path)
				if strings.HasPrefix(path, "/") {
					endpoints = append(endpoints, path)
				}
			}
			
			// Fim da seção paths
			if strings.Contains(line, "\"components\"") || 
			   strings.Contains(line, "\"definitions\"") ||
			   strings.Contains(line, "components:") ||
			   strings.Contains(line, "definitions:") {
				inPaths = false
			}
		}
	}
	
	return endpoints
}

func main() {
	baseURLsFile := flag.String("urls", "", "JSON file with base URLs")
	outputFile := flag.String("output", "api_results.json", "Output file")
	workers := flag.Int("workers", 10, "Concurrent host workers")
	flag.Parse()
	
	if *baseURLsFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: api_discoverer -urls <file.json>")
		os.Exit(1)
	}
	
	// Lê URLs
	data, _ := os.ReadFile(*baseURLsFile)
	var baseURLs []string
	json.Unmarshal(data, &baseURLs)
	
	var output FinalOutput
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, *workers)
	
	for _, url := range baseURLs {
		wg.Add(1)
		go func(baseURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			results := discoverAPI(baseURL, apiPaths)
			
			mu.Lock()
			output.Results = append(output.Results, results...)
			output.TotalAPIs += len(results)
			
			for _, r := range results {
				if r.HasOpenAPI {
					output.OpenAPIs = append(output.OpenAPIs, r.URL)
				}
				if r.HasGraphQL {
					output.GraphQLs = append(output.GraphQLs, r.URL)
				}
				if strings.Contains(r.URL, "swagger") {
					output.Swaggers = append(output.Swaggers, r.URL)
				}
			}
			mu.Unlock()
		}(url)
	}
	
	wg.Wait()
	
	// Output
	outputJSON, _ := json.MarshalIndent(output, "", "  ")
	os.WriteFile(*outputFile, outputJSON, 0644)
	fmt.Println(string(outputJSON))
}