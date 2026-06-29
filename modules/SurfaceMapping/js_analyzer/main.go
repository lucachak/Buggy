package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type JSSecret struct {
	URL      string `json:"url"`
	Type     string `json:"type"`
	Secret   string `json:"secret"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Context  string `json:"context"`
}

type JSAnalysisResult struct {
	URL        string     `json:"url"`
	Secrets    []JSSecret `json:"secrets"`
	Endpoints  []string   `json:"endpoints_found"`
	FileSize   int64      `json:"file_size"`
}

type FinalOutput struct {
	Results []JSAnalysisResult `json:"results"`
	Summary struct {
		TotalFiles     int      `json:"total_files"`
		TotalSecrets   int      `json:"total_secrets"`
		HighSeverity   int      `json:"high_severity"`
		APIsFound      []string `json:"apis_found"`
		UniqueDomains  []string `json:"unique_domains"`
	} `json:"summary"`
}

// Patterns de alto valor para bug bounty
var secretPatterns = map[string]struct {
	Regex    *regexp.Regexp
	Severity string
}{
	"API Key": {
		Regex:    regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)["\s:=]+['"]?([a-zA-Z0-9_\-]{20,})['"]?`),
		Severity: "critical",
	},
	"AWS Key": {
		Regex:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: "critical",
	},
	"AWS Secret": {
		Regex:    regexp.MustCompile(`(?i)aws[_-]?secret["\s:=]+['"]?([a-zA-Z0-9\/+=]{40,})['"]?`),
		Severity: "critical",
	},
	"Google API": {
		Regex:    regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Severity: "high",
	},
	"GitHub Token": {
		Regex:    regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`),
		Severity: "high",
	},
	"JWT Token": {
		Regex:    regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`),
		Severity: "high",
	},
	"Private Key": {
		Regex:    regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----`),
		Severity: "critical",
	},
	"Slack Token": {
		Regex:    regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-_]+`),
		Severity: "high",
	},
	"Stripe Key": {
		Regex:    regexp.MustCompile(`(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}`),
		Severity: "critical",
	},
	"Firebase": {
		Regex:    regexp.MustCompile(`(?i)firebase["\s:=]+['"]?([a-z0-9-]+\.firebaseio\.com)['"]?`),
		Severity: "high",
	},
	"Internal URL": {
		Regex:    regexp.MustCompile(`(?i)(https?://(?:internal|dev|staging|test|localhost|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s"']+)`),
		Severity: "medium",
	},
	"OAuth Client ID": {
		Regex:    regexp.MustCompile(`[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com`),
		Severity: "high",
	},
	"Database URL": {
		Regex:    regexp.MustCompile(`(?i)(?:mongodb|postgres|mysql|redis|jdbc)://[^\s"']+`),
		Severity: "critical",
	},
}

// Patterns para descobrir endpoints de API
var apiEndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)["'\x60](https?://[^\s"'\x60]+(?:api|graphql|v[0-9]+)/[^\s"'\x60]+)["'\x60]`),
	regexp.MustCompile(`(?i)(?:fetch|axios|get|post|put|delete)\s*\(\s*['"\x60](/[^\s"'\x60]+)['"\x60]`),
	regexp.MustCompile(`(?i)(?:baseURL|apiUrl|endpoint|API_URL)\s*[:=]\s*['"\x60]([^\s"'\x60]+)['"\x60]`),
	regexp.MustCompile(`(?i)(?:path|url|href)\s*:\s*['"\x60](/[^\s"'\x60]+)['"\x60]`),
}

var (
	client *http.Client
	wg     sync.WaitGroup
	mu     sync.Mutex
)

func init() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 30 * time.Second,
	}
	client = &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}
}

func analyzeJS(url string) JSAnalysisResult {
	result := JSAnalysisResult{
		URL:      url,
		Secrets:  []JSSecret{},
		Endpoints: []string{},
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Buggy/1.0 JS-Analyzer")

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	// Só processa JavaScript
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "javascript") && 
	   !strings.Contains(contentType, "text/plain") &&
	   !strings.HasSuffix(url, ".js") {
		return result
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB max
	content := string(body)
	result.FileSize = int64(len(body))

	// Divide em linhas para contexto
	lines := strings.Split(content, "\n")

	// Busca segredos
	for secretType, pattern := range secretPatterns {
		matches := pattern.Regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 0 {
				secret := match[0]
				if len(match) > 1 && match[1] != "" {
					secret = match[len(match)-1] // Último grupo capturado
				}

				// Encontra linha do contexto
				lineNum := findLineNumber(lines, secret)
				context := getContext(lines, lineNum, 2)

				result.Secrets = append(result.Secrets, JSSecret{
					URL:      url,
					Type:     secretType,
					Secret:   maskSecret(secret),
					Line:     lineNum,
					Severity: pattern.Severity,
					Context:  context,
				})
			}
		}
	}

	// Busca endpoints de API
	for _, pattern := range apiEndpointPatterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				if !contains(result.Endpoints, endpoint) {
					result.Endpoints = append(result.Endpoints, endpoint)
				}
			}
		}
	}

	return result
}

func findLineNumber(lines []string, secret string) int {
	for i, line := range lines {
		if strings.Contains(line, secret) {
			return i + 1 // 1-indexed
		}
	}
	return 0
}

func getContext(lines []string, lineNum, margin int) string {
	if lineNum == 0 {
		return ""
	}
	
	start := lineNum - margin - 1
	if start < 0 {
		start = 0
	}
	end := lineNum + margin
	if end > len(lines) {
		end = len(lines)
	}
	
	contextLines := lines[start:end]
	// Limpa espaços e trunca
	context := strings.TrimSpace(strings.Join(contextLines, "\\n"))
	if len(context) > 200 {
		context = context[:200] + "..."
	}
	return context
}

func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func main() {
	urlsFile := flag.String("urls", "", "JSON file with JS URLs to analyze")
	outputFile := flag.String("output", "js_results.json", "Output JSON file")
	workers := flag.Int("workers", 15, "Concurrent workers")
	flag.Parse()

	if *urlsFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: js_analyzer -urls <file.json>")
		os.Exit(1)
	}

	data, _ := os.ReadFile(*urlsFile)
	var urls []string
	json.Unmarshal(data, &urls)

	urlChan := make(chan string, len(urls))
	resultsChan := make(chan JSAnalysisResult, len(urls))

	// Worker pool
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlChan {
				resultsChan <- analyzeJS(url)
			}
		}()
	}

	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var output FinalOutput
	apiSet := make(map[string]bool)
	domainSet := make(map[string]bool)
	
	for result := range resultsChan {
		output.Results = append(output.Results, result)
		output.Summary.TotalFiles++
		
		secrets := len(result.Secrets)
		output.Summary.TotalSecrets += secrets
		
		for _, secret := range result.Secrets {
			if secret.Severity == "critical" || secret.Severity == "high" {
				output.Summary.HighSeverity++
			}
		}
		
		for _, endpoint := range result.Endpoints {
			apiSet[endpoint] = true
			// Extrai domínio
			if strings.HasPrefix(endpoint, "http") {
				parts := strings.Split(endpoint, "/")
				if len(parts) > 2 {
					domainSet[parts[2]] = true
				}
			}
		}
	}

	for api := range apiSet {
		output.Summary.APIsFound = append(output.Summary.APIsFound, api)
	}
	for domain := range domainSet {
		output.Summary.UniqueDomains = append(output.Summary.UniqueDomains, domain)
	}

	outputJSON, _ := json.MarshalIndent(output, "", "  ")
	os.WriteFile(*outputFile, outputJSON, 0644)
	fmt.Println(string(outputJSON))
}