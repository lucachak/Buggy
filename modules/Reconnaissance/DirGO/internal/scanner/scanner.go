package scanner

import (
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── ANSI ────────────────────────────────────
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[91m"
	green  = "\033[92m"
	yellow = "\033[93m"
	cyan   = "\033[96m"
	gray   = "\033[90m"
)

func col(s string, codes ...string) string {
	return strings.Join(codes, "") + s + reset
}

var redirectCodes = map[int]bool{301: true, 302: true, 303: true, 307: true, 308: true}

var techHeaders = []string{
	"Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
	"X-WordPress", "X-Joomla", "X-AspNet-Version", "X-AspNetMvc-Version",
	"X-Runtime", "X-Version", "Via", "CF-RAY",
}

// ─── Scanner ─────────────────────────────────
type Scanner struct {
	cfg     Config
	client  *http.Client
	results []Result
	mu      sync.Mutex
	scanned atomic.Int64
	found   atomic.Int64
	total   int64
	startAt time.Time
}

func New(cfg Config) *Scanner {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: cfg.Concurrency,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.Timeout * float64(time.Second)),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Scanner{cfg: cfg, client: client}
}

func (s *Scanner) probe(url string) *Result {
	maxRetries := s.cfg.Retry
	if maxRetries < 1 {
		maxRetries = 1
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			if s.cfg.Verbose {
				fmt.Println(col(fmt.Sprintf("  [E] bad URL %s: %v", url, err), gray))
			}
			return nil
		}
		req.Header.Set("User-Agent", "Dirpy/2.0")

		t0 := time.Now()
		resp, err := s.client.Do(req)
		elapsed := float64(time.Since(t0).Microseconds()) / 1000.0

		if err != nil {
			if isTimeout(err) && attempt < maxRetries-1 {
				continue
			}
			if s.cfg.Verbose {
				fmt.Println(col(fmt.Sprintf("  [E] %s  %v", url, err), gray))
			}
			return nil
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if s.cfg.FilterCodes[resp.StatusCode] {
			return nil
		}

		result := &Result{
			URL:       url,
			Status:    resp.StatusCode,
			Size:      int64(len(body)),
			ElapsedMs: elapsed,
			Depth:     0,
		}

		// Marca como diretório se aplicável
		result.IsDir = isDirResult(result)

		if redirectCodes[resp.StatusCode] {
			result.Redirect = resp.Header.Get("Location")
		}
		if s.cfg.ShowTech {
			result.Tech = extractTech(resp.Header)
		}
		return result
	}
	return nil
}

func (s *Scanner) Run(targets, paths []string) {
	s.total = int64(len(targets) * len(paths))
	s.startAt = time.Now()

	type job struct{ url string }
	jobs := make(chan job, s.cfg.Concurrency*4)

	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := s.probe(j.url)
				n := s.scanned.Add(1)
				if r != nil {
					s.found.Add(1)
					s.mu.Lock()
					s.results = append(s.results, *r)
					s.mu.Unlock()
					if !s.cfg.Silent {
						s.printResult(r)
					}
				}
				if !s.cfg.Silent && n%25 == 0 {
					s.printProgress()
				}
			}
		}()
	}

	for _, target := range targets {
		if len(targets) > 1 {
			fmt.Printf("\n  %s Scanning: %s\n", col("►", cyan), col(target, bold))
		}
		base := strings.TrimRight(target, "/")
		for _, path := range paths {
			jobs <- job{url: base + path}
		}
	}
	close(jobs)
	wg.Wait()
}

// ─── Recursive scan ──────────────────────────

func (s *Scanner) RunRecursive(targets, paths []string) {
	// Primeira passada
	s.Run(targets, paths)

	if !s.cfg.Recursive {
		return
	}

	visited := make(map[string]bool)
	for _, r := range s.Results() {
		visited[r.URL] = true
	}

	dirs := s.extractDirectories()
	depth := 1

	for len(dirs) > 0 && (s.cfg.MaxDepth == 0 || depth <= s.cfg.MaxDepth) {
		if !s.cfg.Silent {
			fmt.Printf("\n  %s Recursing depth %d — %d directories found\n",
				col("↳", cyan), depth, len(dirs))
		}

		var newDirs []string
		for _, dir := range dirs {
			if visited[dir] {
				continue
			}
			visited[dir] = true

			base := strings.TrimRight(dir, "/")
			for _, path := range paths {
				fullURL := base + path
				if visited[fullURL] {
					continue
				}
				visited[fullURL] = true

				r := s.probe(fullURL)
				n := s.scanned.Add(1)
				if r != nil {
					r.Depth = depth
					s.found.Add(1)
					s.mu.Lock()
					s.results = append(s.results, *r)
					s.mu.Unlock()
					if !s.cfg.Silent {
						s.printResult(r)
					}
					if r.IsDir && (s.cfg.MaxDepth == 0 || depth < s.cfg.MaxDepth) {
						newDirs = append(newDirs, r.URL)
					}
				}
				if !s.cfg.Silent && n%25 == 0 {
					s.printProgress()
				}
			}
		}
		dirs = newDirs
		depth++
	}
}

func (s *Scanner) extractDirectories() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var dirs []string
	seen := make(map[string]bool)

	for _, r := range s.results {
		if r.IsDir && !seen[r.URL] {
			// Garante que termina com /
			dirURL := r.URL
			if !strings.HasSuffix(dirURL, "/") {
				dirURL += "/"
			}
			seen[dirURL] = true
			dirs = append(dirs, dirURL)
		}
	}
	return dirs
}

func isDirResult(r *Result) bool {
	if r.Status == 200 || r.Status == 403 || r.Status == 401 {
		if r.Redirect != "" {
			return true
		}
		if strings.HasSuffix(r.URL, "/") {
			return true
		}
		lastPart := r.URL[strings.LastIndex(r.URL, "/")+1:]
		if !strings.Contains(lastPart, ".") {
			return true
		}
	}
	return false
}

// ─── Display ─────────────────────────────────

func (s *Scanner) printResult(r *Result) {
	statusStr := colorizeStatus(r.Status)
	sizeStr := col(fmt.Sprintf("%8d B", r.Size), gray)
	timeStr := col(fmt.Sprintf("%7.1fms", r.ElapsedMs), gray)
	urlStr := r.URL
	if r.Status == 200 {
		urlStr = col(r.URL, bold)
	}
	line := fmt.Sprintf("  %s  %s  %s  %s", statusStr, sizeStr, timeStr, urlStr)
	if r.Redirect != "" {
		line += col("  → "+r.Redirect, cyan)
	}
	if r.Depth > 0 {
		line += col(fmt.Sprintf("  d=%d", r.Depth), yellow)
	}
	if len(r.Tech) > 0 {
		parts := make([]string, 0, len(r.Tech))
		for k, v := range r.Tech {
			parts = append(parts, k+": "+v)
		}
		line += col("  "+strings.Join(parts, " | "), yellow)
	}
	fmt.Println(line)
}

func (s *Scanner) printProgress() {
	scanned := s.scanned.Load()
	found := s.found.Load()
	elapsed := time.Since(s.startAt).Seconds()
	var rps, eta float64
	if elapsed > 0 {
		rps = float64(scanned) / elapsed
	}
	if rps > 0 {
		eta = float64(s.total-scanned) / rps
	}
	pct := float64(scanned) / float64(s.total) * 100
	fmt.Printf("\r  %s %d/%d (%.1f%%)  %s  ETA %.0fs  found: %s          ",
		col("►", cyan),
		scanned, s.total, pct,
		col(fmt.Sprintf("%.0f req/s", rps), green),
		eta,
		col(strconv.FormatInt(found, 10), bold),
	)
}

func (s *Scanner) PrintSummary() {
	elapsed := time.Since(s.startAt).Seconds()
	scanned := s.scanned.Load()
	found := s.found.Load()
	var rps float64
	if elapsed > 0 {
		rps = float64(scanned) / elapsed
	}
	fmt.Println()
	fmt.Println(col("  "+strings.Repeat("─", 70), gray))
	fmt.Printf("  %s  %d requests  %s found  in %.2fs  (%.0f req/s)\n\n",
		col("Done!", green, bold),
		scanned,
		col(strconv.FormatInt(found, 10), bold),
		elapsed, rps,
	)
}

func (s *Scanner) Results() []Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]Result, len(s.results))
	copy(cp, s.results)
	return cp
}

func (s *Scanner) SaveJSON(path string, meta map[string]interface{}) error {
	results := s.Results()
	if meta == nil {
		meta = map[string]interface{}{}
	}
	meta["total_found"] = len(results)
	payload := map[string]interface{}{"meta": meta, "results": results}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	fmt.Println(col("  [✓] JSON saved to: "+path, green))
	return nil
}

func (s *Scanner) SaveCSV(path string) error {
	results := s.Results()
	if len(results) == 0 {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"url", "status", "size", "redirect", "elapsed_ms", "depth", "is_dir"})
	for _, r := range results {
		w.Write([]string{
			r.URL,
			strconv.Itoa(r.Status),
			strconv.FormatInt(r.Size, 10),
			r.Redirect,
			fmt.Sprintf("%.1f", r.ElapsedMs),
			strconv.Itoa(r.Depth),
			strconv.FormatBool(r.IsDir),
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	fmt.Println(col("  [✓] CSV saved to: "+path, green))
	return nil
}

// ─── Helpers ─────────────────────────────────

func colorizeStatus(s int) string {
	str := strconv.Itoa(s)
	switch {
	case s == 200 || s == 201:
		return col(str, green, bold)
	case redirectCodes[s]:
		return col(str, cyan)
	case s == 401:
		return col(str, yellow, bold)
	case s == 403:
		return col(str, yellow)
	case s == 404:
		return col(str, gray)
	case s >= 500:
		return col(str, red)
	default:
		return str
	}
}

func extractTech(h http.Header) map[string]string {
	out := map[string]string{}
	for _, name := range techHeaders {
		if v := h.Get(name); v != "" {
			out[name] = v
		}
	}
	return out
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "deadline exceeded")
}
