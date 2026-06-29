package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "net"
    "os"
    "sort"
    "sync"
    "time"
)

type ScanResult struct {
    Host      string `json:"host"`
    OpenPorts []int  `json:"open_ports"`
    Services  map[int]string `json:"services"`
}

var commonPorts = []int{
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    27017, 9200, 11211, 1433, 1521, 5000, 3000, 4000, 8888,
}

var serviceMap = map[int]string{
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch",
    1433: "MSSQL", 1521: "Oracle", 3000: "Grafana/Node",
    5000: "Docker Registry", 11211: "Memcached",
}

func scanPort(host string, port int, timeout time.Duration) bool {
    target := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", target, timeout)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

func scanHost(host string, ports []int, timeout time.Duration) ScanResult {
    result := ScanResult{
        Host:      host,
        OpenPorts: []int{},
        Services:  make(map[int]string),
    }

    var mu sync.Mutex
    var wg sync.WaitGroup
    sem := make(chan struct{}, 100) // Max 100 concurrent connections

    for _, port := range ports {
        wg.Add(1)
        go func(p int) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()

            if scanPort(host, p, timeout) {
                mu.Lock()
                result.OpenPorts = append(result.OpenPorts, p)
                if service, ok := serviceMap[p]; ok {
                    result.Services[p] = service
                } else {
                    result.Services[p] = "unknown"
                }
                mu.Unlock()
            }
        }(port)
    }

    wg.Wait()
    sort.Ints(result.OpenPorts)
    return result
}

func main() {
    hostsFile := flag.String("hosts", "", "JSON file with hosts to scan")
    portsFlag := flag.String("ports", "top100", "Ports: top100, top1000, or comma-separated")
    timeoutFlag := flag.Int("timeout", 2, "Timeout in seconds per port")
    workersFlag := flag.Int("workers", 20, "Concurrent host workers")
    outputFile := flag.String("output", "port_results.json", "Output file")
    flag.Parse()

    if *hostsFile == "" {
        fmt.Fprintln(os.Stderr, "Usage: port_scanner -hosts <file.json>")
        os.Exit(1)
    }

    // Parse hosts
    data, err := os.ReadFile(*hostsFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }

    var hosts []string
    json.Unmarshal(data, &hosts)

    // Parse ports
    var ports []int
    switch *portsFlag {
    case "top100":
        ports = commonPorts
    case "top1000":
        ports = make([]int, 1000)
        for i := 1; i <= 1000; i++ {
            ports[i-1] = i
        }
    default:
        fmt.Sscanf(*portsFlag, "%d", &ports)
    }

    timeout := time.Duration(*timeoutFlag) * time.Second

    // Scan hosts concurrently
    var results []ScanResult
    var mu sync.Mutex
    var wg sync.WaitGroup
    sem := make(chan struct{}, *workersFlag)

    for _, host := range hosts {
        wg.Add(1)
        go func(h string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()

            result := scanHost(h, ports, timeout)
            if len(result.OpenPorts) > 0 {
                mu.Lock()
                results = append(results, result)
                mu.Unlock()
            }
        }(host)
    }

    wg.Wait()

    outputJSON, _ := json.MarshalIndent(results, "", "  ")
    os.WriteFile(*outputFile, outputJSON, 0644)
    fmt.Println(string(outputJSON))
}