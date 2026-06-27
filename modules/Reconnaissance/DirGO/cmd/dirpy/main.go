package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lucachak/dirpy/internal/output"
	"github.com/lucachak/dirpy/internal/scanner"
	"github.com/lucachak/dirpy/internal/urlbuilder"
	"github.com/lucachak/dirpy/internal/wordlist"
)

func main() {
	urlFlag := flag.String("u", "", "Target URL or host")
	portsFlag := flag.String("p", "", "Ports (comma-separated): 80,443,8080")
	wordlistFlag := flag.String("w", "", "Path to wordlist file")
	extensionsFlag := flag.String("x", "", "Extensions (comma-separated): php,txt,bak")
	filterCodesFlag := flag.String("c", "404", "Status codes to filter (comma-separated)")
	concurrencyFlag := flag.Int("t", 50, "Number of workers")
	timeoutFlag := flag.Float64("timeout", 10.0, "Timeout in seconds")
	retryFlag := flag.Int("retry", 1, "Retry count on timeout")
	techFlag := flag.Bool("tech", false, "Fingerprint technology")
	jsonFlag := flag.String("json", "", "Save results to JSON file")
	csvFlag := flag.String("csv", "", "Save results to CSV file")
	verboseFlag := flag.Bool("v", false, "Verbose output")
	silentFlag := flag.Bool("silent", false, "Silent mode")
	recursiveFlag := flag.Bool("r", false, "Recursive scan into directories")
	maxDepthFlag := flag.Int("depth", 0, "Max recursion depth (0 = unlimited)")
	outputDirFlag := flag.String("output-dir", "output", "Output directory for reports")
	exportWordlistFlag := flag.String("export-wordlist", "", "Export built-in wordlist")

	flag.Parse()

	if *exportWordlistFlag != "" {
		if err := wordlist.WriteBuiltin(*exportWordlistFlag); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[✓] Wordlist saved to: %s\n", *exportWordlistFlag)
		return
	}

	if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "error: -u/--url is required")
		flag.Usage()
		os.Exit(1)
	}

	filterCodes := parseFilterCodes(*filterCodesFlag)

	var ports []int
	if *portsFlag != "" {
		for _, s := range strings.Split(*portsFlag, ",") {
			p, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid port: %s\n", s)
				os.Exit(1)
			}
			ports = append(ports, p)
		}
	}

	var extensions []string
	if *extensionsFlag != "" {
		for _, s := range strings.Split(*extensionsFlag, ",") {
			extensions = append(extensions, strings.TrimSpace(s))
		}
	}

	ub, err := urlbuilder.New(*urlFlag, ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	targets := ub.Targets()

	var paths []string
	if *wordlistFlag != "" {
		paths, err = wordlist.ExpandFile(*wordlistFlag, extensions)
	} else {
		paths = wordlist.BuiltinPaths(extensions)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "error: wordlist is empty")
		os.Exit(1)
	}

	output.PrintBanner(targets, paths, *concurrencyFlag)

	cfg := scanner.Config{
		Concurrency: *concurrencyFlag,
		Timeout:     *timeoutFlag,
		Retry:       *retryFlag,
		ShowTech:    *techFlag,
		Verbose:     *verboseFlag,
		Silent:      *silentFlag,
		FilterCodes: filterCodes,
		Recursive:   *recursiveFlag,
		MaxDepth:    *maxDepthFlag,
	}

	// Criar diretório de output
	if *jsonFlag != "" || *csvFlag != "" {
		if err := os.MkdirAll(*outputDirFlag, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "error creating output dir: %v\n", err)
			os.Exit(1)
		}
	}

	s := scanner.New(cfg)

	if *recursiveFlag {
		s.RunRecursive(targets, paths)
	} else {
		s.Run(targets, paths)
	}

	s.PrintSummary()

	// Salvar relatórios no diretório de output
	meta := map[string]interface{}{
		"target": *urlFlag,
		"ports":  ports,
	}

	if *jsonFlag != "" {
		jsonPath := filepath.Join(*outputDirFlag, *jsonFlag)
		s.SaveJSON(jsonPath, meta)
	}
	if *csvFlag != "" {
		csvPath := filepath.Join(*outputDirFlag, *csvFlag)
		s.SaveCSV(csvPath)
	}

	results := s.Results()
	if len(results) == 0 {
		fmt.Println("  [~] No results found.")
	} else {
		fmt.Printf("  %d result(s) found.\n\n", len(results))
	}
}

func parseFilterCodes(s string) map[int]bool {
	codes := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		c, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil {
			codes[c] = true
		}
	}
	return codes
}
