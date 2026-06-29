
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

type TechResult struct {
    URL         string   `json:"url"`
    CMS         []string `json:"cms"`
    WAF         string   `json:"waf"`
    Frameworks  []string `json:"frameworks"`
    Server      string   `json:"server"`
    Language    string   `json:"language"`
    Headers     map[string]string `json:"headers"`
}

type FinalOutput struct {
    Results  []TechResult `json:"results"`
    Summary  Summary      `json:"summary"`
}

type Summary struct {
    TotalURLs     int      `json:"total_urls"`
    WAFDetected   bool     `json:"waf_detected"`
    WAFType       string   `json:"waf_type"`
    AllCMS        []string `json:"all_cms"`
    AllFrameworks []string `json:"all_frameworks"`
    AllServers    []string `json:"all_servers"`
}

var (
    client *http.Client
    wg     sync.WaitGroup
    mu     sync.Mutex
    results []TechResult
)

// Assinaturas de WAF (compiladas para performance)
var wafSignatures = map[string]struct {
    Headers  []string
    Cookies  []string
    Patterns []string
}{
    "Cloudflare": {
        Headers: []string{"CF-RAY", "CF-Cache-Status"},
        Cookies: []string{"__cfduid", "cf_clearance"},
        Patterns: []string{`cloudflare`},
    },
    "AWS WAF": {
        Headers: []string{"X-Amzn-RequestId", "X-Amz-Cf-Id"},
    },
    "ModSecurity": {
        Patterns: []string{`ModSecurity`, `Not Acceptable`},
    },
}

// Assinaturas de CMS
var cmsSignatures = map[string]struct {
    Patterns []string
    Cookies  []string
}{
    "WordPress": {
        Patterns: []string{`wp-content`, `wp-includes`, `wordpress`},
        Cookies:  []string{`wp-*`, `wordpress_*`},
    },
    "Drupal": {
        Patterns: []string{`Drupal`, `drupal\.org`},
        Cookies:  []string{`SESS.*`},
    },
}

func init() {
    // HTTP client com timeout e SSL permissivo
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client = &http.Client{
        Transport: tr,
        Timeout:   10 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse // Não segue redirects
        },
    }
}

func analyzeURL(url string) TechResult {
    result := TechResult{
        URL:     url,
        CMS:     []string{},
        Frameworks: []string{},
    }

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return result
    }
    req.Header.Set("User-Agent", "Buggy/1.0 SurfaceMapper")

    resp, err := client.Do(req)
    if err != nil {
        return result
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB max
    bodyStr := string(body)

    // Headers
    headers := make(map[string]string)
    for k, v := range resp.Header {
        headers[k] = strings.Join(v, ", ")
    }
    result.Headers = headers
    result.Server = headers["Server"]

    // Language detection
    if powered := headers["X-Powered-By"]; powered != "" {
        result.Language = detectLanguage(powered)
    }

    // WAF Detection (prioridade)
    result.WAF = detectWAF(headers, bodyStr, resp.Cookies())

    // CMS Detection
    result.CMS = detectCMS(headers, bodyStr, resp.Cookies())

    // Framework Detection
    result.Frameworks = detectFrameworks(headers, bodyStr)

    return result
}

func detectWAF(headers map[string]string, body string, cookies []*http.Cookie) string {
    for wafName, sigs := range wafSignatures {
        // Headers
        for _, header := range sigs.Headers {
            if _, exists := headers[header]; exists {
                return wafName
            }
        }
        // Patterns no body
        for _, pattern := range sigs.Patterns {
            if matched, _ := regexp.MatchString(pattern, body); matched {
                return wafName
            }
        }
        // Cookies
        for _, cookiePattern := range sigs.Cookies {
            for _, cookie := range cookies {
                if matched, _ := regexp.MatchString(cookiePattern, cookie.Name); matched {
                    return wafName
                }
            }
        }
    }
    return ""
}

func detectCMS(headers map[string]string, body string, cookies []*http.Cookie) []string {
    var cms []string
    for cmsName, sigs := range cmsSignatures {
        for _, pattern := range sigs.Patterns {
            if matched, _ := regexp.MatchString(pattern, body); matched {
                cms = append(cms, cmsName)
                break
            }
        }
    }
    return cms
}

func detectFrameworks(headers map[string]string, body string) []string {
    frameworks := []string{}
    frameworkPatterns := map[string]string{
        "React":    `react\.js|react-dom|__REACT_DEVTOOLS`,
        "Angular":  `ng-version|angular\.js`,
        "Vue.js":   `vue\.js|v-bind|v-model`,
        "Laravel":  `laravel`,
        "Django":   `django|csrftoken`,
        "ASP.NET":  `__VIEWSTATE|__EVENTVALIDATION`,
    }
    
    for fw, pattern := range frameworkPatterns {
        if matched, _ := regexp.MatchString(pattern, body); matched {
            frameworks = append(frameworks, fw)
        }
    }
    return frameworks
}

func detectLanguage(poweredBy string) string {
    langMap := map[string]string{
        "php": "PHP", "asp.net": "ASP.NET", "node": "Node.js",
        "python": "Python", "ruby": "Ruby", "java": "Java",
        "go": "Go",
    }
    lower := strings.ToLower(poweredBy)
    for key, lang := range langMap {
        if strings.Contains(lower, key) {
            return lang
        }
    }
    return poweredBy
}

func main() {
    urlsFile := flag.String("urls", "", "JSON file with URLs to analyze")
    outputFile := flag.String("output", "tech_results.json", "Output JSON file")
    workers := flag.Int("workers", 20, "Number of concurrent workers")
    flag.Parse()

    if *urlsFile == "" {
        fmt.Fprintln(os.Stderr, "Usage: tech_detector -urls <file.json>")
        os.Exit(1)
    }

    // Lê URLs do JSON
    data, err := os.ReadFile(*urlsFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
        os.Exit(1)
    }

    var urls []string
    if err := json.Unmarshal(data, &urls); err != nil {
        fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
        os.Exit(1)
    }

    // Worker pool
    urlChan := make(chan string, len(urls))
    resultsChan := make(chan TechResult, len(urls))

    // Start workers
    for i := 0; i < *workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for url := range urlChan {
                resultsChan <- analyzeURL(url)
            }
        }()
    }

    // Send URLs
    for _, url := range urls {
        urlChan <- url
    }
    close(urlChan)

    // Wait and collect
    go func() {
        wg.Wait()
        close(resultsChan)
    }()

    var allResults []TechResult
    for r := range resultsChan {
        allResults = append(allResults, r)
    }

    // Generate summary
    summary := Summary{
        TotalURLs: len(allResults),
    }
    
    cmsSet := make(map[string]bool)
    fwSet := make(map[string]bool)
    serverSet := make(map[string]bool)

    for _, r := range allResults {
        if r.WAF != "" {
            summary.WAFDetected = true
            summary.WAFType = r.WAF
        }
        for _, c := range r.CMS {
            cmsSet[c] = true
        }
        for _, f := range r.Frameworks {
            fwSet[f] = true
        }
        if r.Server != "" {
            serverSet[r.Server] = true
        }
    }

    for c := range cmsSet {
        summary.AllCMS = append(summary.AllCMS, c)
    }
    for f := range fwSet {
        summary.AllFrameworks = append(summary.AllFrameworks, f)
    }
    for s := range serverSet {
        summary.AllServers = append(summary.AllServers, s)
    }

    // Output
    output := FinalOutput{
        Results: allResults,
        Summary: summary,
    }

    outputJSON, _ := json.MarshalIndent(output, "", "  ")
    os.WriteFile(*outputFile, outputJSON, 0644)
    
    // Also print to stdout for piping
    fmt.Println(string(outputJSON))
}