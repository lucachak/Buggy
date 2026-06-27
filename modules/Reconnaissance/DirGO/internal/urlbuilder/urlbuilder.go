package urlbuilder

import (
	"fmt"
	"net/url"
	"strings"
)

// Builder handles target URL construction.
type Builder struct {
	baseURL string
	ports   []int
	parsed  *url.URL
}

// New creates a Builder from a raw URL and optional ports.
func New(rawURL string, ports []int) (*Builder, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	return &Builder{
		baseURL: strings.TrimRight(rawURL, "/"),
		ports:   ports,
		parsed:  parsed,
	}, nil
}

// Targets returns one base URL per port, or the original URL if no ports given.
func (b *Builder) Targets() []string {
	if len(b.ports) == 0 {
		return []string{b.baseURL}
	}
	scheme := b.parsed.Scheme
	host := b.parsed.Hostname()
	targets := make([]string, 0, len(b.ports))
	for _, p := range b.ports {
		targets = append(targets, fmt.Sprintf("%s://%s:%d", scheme, host, p))
	}
	return targets
}
