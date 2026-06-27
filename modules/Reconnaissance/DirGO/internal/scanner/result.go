package scanner

// Result holds everything from a single HTTP probe.
type Result struct {
	URL       string            `json:"url"`
	Status    int               `json:"status"`
	Size      int64             `json:"size"`
	Redirect  string            `json:"redirect,omitempty"`
	Tech      map[string]string `json:"tech,omitempty"`
	ElapsedMs float64           `json:"elapsed_ms"`
	IsDir     bool              `json:"is_dir"`
	Depth     int               `json:"depth"`
}

// Config holds scanner parameters.
type Config struct {
	Concurrency int
	Timeout     float64
	Retry       int
	ShowTech    bool
	Verbose     bool
	Silent      bool
	FilterCodes map[int]bool
	Recursive   bool
	MaxDepth    int
}
