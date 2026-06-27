package output

import (
	"fmt"
	"strings"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[91m"
	green  = "\033[92m"
	yellow = "\033[93m"
	cyan   = "\033[96m"
	gray   = "\033[90m"
)

func color(s string, codes ...string) string {
	return strings.Join(codes, "") + s + reset
}

func Gray(s string) {
	fmt.Println(color(s, gray))
}

func PrintBanner(targets []string, paths []string, concurrency int) {
	fmt.Println()
	fmt.Println(color("  Dirpy v2  |  async directory bruteforcer", gray))
	fmt.Println()
	fmt.Printf("  %s %s\n", color("Targets:", bold), strings.Join(targets, ", "))
	fmt.Printf("  %s %d paths\n", color("Wordlist:", bold), len(paths))
	fmt.Printf("  %s %d workers\n", color("Concurrency:", bold), concurrency)
	fmt.Println()
	fmt.Println(color("  "+strings.Repeat("─", 70), gray))
	fmt.Printf("  %6s  %10s  %10s  URL\n", "Status", "Size", "Time")
	fmt.Println(color("  "+strings.Repeat("─", 70), gray))
}
