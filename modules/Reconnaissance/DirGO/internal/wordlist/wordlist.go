package wordlist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// BuiltinPaths returns built-in paths with optional extensions.
func BuiltinPaths(extensions []string) []string {
	words := Builtin()
	return expandExtensions(words, extensions)
}

// ExpandFile loads a wordlist file and expands with extensions.
func ExpandFile(path string, extensions []string) ([]string, error) {
	words, err := loadWordlistFile(path)
	if err != nil {
		return nil, err
	}
	return expandExtensions(words, extensions), nil
}

// WriteBuiltin writes the built-in wordlist to a file.
func WriteBuiltin(path string) error {
	return os.WriteFile(path, []byte(builtinWordlist), 0644)
}

func loadWordlistFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("wordlist not found: %s", path)
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, line)
	}
	return words, sc.Err()
}

func expandExtensions(words, extensions []string) []string {
	seen := make(map[string]struct{}, len(words)*(1+len(extensions)))
	paths := make([]string, 0, len(words)*(1+len(extensions)))

	add := func(p string) {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			paths = append(paths, p)
		}
	}

	for _, w := range words {
		base := "/" + strings.TrimPrefix(strings.TrimRight(w, "/"), "/")
		add(base)
		for _, ext := range extensions {
			add(base + "." + strings.TrimPrefix(ext, "."))
		}
	}
	return paths
}
