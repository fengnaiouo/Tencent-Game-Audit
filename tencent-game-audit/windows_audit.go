package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type SystemSnapshot struct {
	RunEntries       []PersistenceItem `json:"run_entries"`
	Services         []PersistenceItem `json:"services"`
	ScheduledTasks   []PersistenceItem `json:"scheduled_tasks"`
	StartupFiles     []PersistenceItem `json:"startup_files"`
	SuspiciousCOM    []PersistenceItem `json:"suspicious_com"`
	Processes        []ProcessItem     `json:"processes"`
	ExternalTCP      []ConnectionItem  `json:"external_tcp"`
	NetworkIOCHits   []string          `json:"network_ioc_hits"`
	NamedPipeHits    []string          `json:"named_pipe_hits"`
	Defender         DefenderStatus    `json:"defender"`
	CollectionErrors []string          `json:"collection_errors,omitempty"`
}

type PersistenceItem struct {
	Name       string `json:"name"`
	Location   string `json:"location"`
	Command    string `json:"command"`
	Confidence string `json:"confidence"`
}
type ProcessItem struct {
	PID        uint32 `json:"pid"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	Command    string `json:"command"`
	Confidence string `json:"confidence"`
}
type ConnectionItem struct {
	PID     uint32 `json:"pid"`
	Process string `json:"process"`
	Local   string `json:"local"`
	Remote  string `json:"remote"`
	State   string `json:"state"`
}
type DefenderStatus struct {
	Available             bool    `json:"available"`
	AntivirusEnabled      *bool   `json:"antivirus_enabled,omitempty"`
	RealTimeProtection    *bool   `json:"real_time_protection,omitempty"`
	AntivirusSignatureAge *uint32 `json:"signature_age_days,omitempty"`
}

// collectWindowsSnapshot uses inbox PowerShell/CIM cmdlets only. It does not
// create scheduled tasks, query remote hosts, or change any system setting.
func collectWindowsSnapshot() SystemSnapshot {
	s := SystemSnapshot{RunEntries: []PersistenceItem{}, Services: []PersistenceItem{}, ScheduledTasks: []PersistenceItem{}, StartupFiles: []PersistenceItem{}, SuspiciousCOM: []PersistenceItem{}, Processes: []ProcessItem{}, ExternalTCP: []ConnectionItem{}, NetworkIOCHits: []string{}, NamedPipeHits: []string{}}
	if runtime.GOOS != "windows" {
		s.CollectionErrors = append(s.CollectionErrors, "Windows-only system collection skipped")
		return s
	}
	ps := `$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{run_entries=@();services=@();scheduled_tasks=@();startup_files=@();suspicious_com=@();processes=@();external_tcp=@();network_ioc_hits=@();named_pipe_hits=@();defender=@{available=$false}}
$sus='(?i)(powershell.{0,40}-(enc|encodedcommand)|-windowstyle\s+hidden|mshta\.exe|regsvr32\.exe|rundll32\.exe\s+javascript:|wscript\.exe|cscript\.exe|\\Users\\Public\\)'
$netioc='(?i)(insightjs\.com|insightjs\.org|89\.127\.233\.127|89\.126\.250\.172|hooks\.slack\.com)'
$scrub={param([string]$s) if(!$s){return ''}; $s=[regex]::Replace($s,'(?i)(token|password|passwd|secret|api[_-]?key)\s*[:=]\s*[^\s;]+','$1=[REDACTED]'); $s=[regex]::Replace($s,'(?i)Bearer\s+[^\s;]+','Bearer [REDACTED]'); $s=[regex]::Replace($s,'(?i)(-enc(?:odedcommand)?\s+)\S+','$1[REDACTED]'); return $s}
foreach($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')){ $p=Get-ItemProperty $k; if($p){foreach($v in $p.PSObject.Properties){if($v.Name -notmatch '^PS' -and $v.Value){$c=[string]$v.Value; if($c -match $sus){$o.run_entries+=@{name=$v.Name;location=$k;command=(& $scrub $c);confidence='medium'}}}}}}
foreach($s in Get-CimInstance Win32_Service){$c=[string]$s.PathName; if($s.StartMode -eq 'Auto' -and ($c -match $sus -or $c -match '(?i)\\Users\\[^\\]+\\AppData\\')){$o.services+=@{name=$s.Name;location=$s.StartName;command=(& $scrub $c);confidence='low; verify vendor and signature'}}}
foreach($t in Get-ScheduledTask){foreach($a in $t.Actions){$c=[string]$a.Execute+' '+[string]$a.Arguments; if($c -match $sus){$o.scheduled_tasks+=@{name=$t.TaskName;location=$t.TaskPath;command=(& $scrub $c);confidence='medium'}}}}
foreach($d in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))){if($d -and (Test-Path $d)){Get-ChildItem -LiteralPath $d -Force -File | ForEach-Object {$o.startup_files+=@{name=$_.Name;location=$_.FullName;command='Startup folder file';confidence='info; verify signature and origin'}}}}
foreach($h in @('HKCU:\Software\Classes\CLSID','HKCU:\Software\Classes\WOW6432Node\CLSID')){foreach($k in Get-ChildItem $h -ErrorAction SilentlyContinue){foreach($vname in @('InprocServer32','LocalServer32')){$p=Get-ItemProperty ($k.PSPath+'\'+$vname) -ErrorAction SilentlyContinue; $v=[string]$p.'(default)'; if($v -match '(?i)\\AppData\\Local\\Temp\\|\\AppData\\Roaming\\|\\Users\\Public\\|\\Downloads\\'){$o.suspicious_com+=@{name=$k.PSChildName;location=$k.Name+'\'+$vname;command=(& $scrub $v);confidence='medium'}}}}}
foreach($p in Get-CimInstance Win32_Process){$c=[string]$p.CommandLine; $path=[string]$p.ExecutablePath; if($p.ProcessId -ne __AUDIT_PROCESS_ID__ -and $p.ParentProcessId -ne __AUDIT_PROCESS_ID__ -and $c -match $sus){$o.processes+=@{pid=[uint32]$p.ProcessId;name=$p.Name;path=$path;command=(& $scrub $c);confidence='medium; inspect signer and parent process'}}}
foreach($p in Get-Process -ErrorAction SilentlyContinue){try{foreach($m in $p.Modules){if($m.ModuleName -ieq 'platform_experience_helper.dll'){$o.processes+=@{pid=[uint32]$p.Id;name=$p.ProcessName;path=[string]$m.FileName;command='Loaded module: platform_experience_helper.dll';confidence='high; documented K2F persistence module loaded'}}}}catch{}}
foreach($n in Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue){if($n.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0$|::$|fe80:|169\.254\.)'){$p=Get-Process -Id $n.OwningProcess -ErrorAction SilentlyContinue;$remote=[string]$n.RemoteAddress;$o.external_tcp+=@{pid=[uint32]$n.OwningProcess;process=[string]$p.ProcessName;local=([string]$n.LocalAddress+':'+[string]$n.LocalPort);remote=($remote+':'+[string]$n.RemotePort);state=[string]$n.State}}}
foreach($d in Get-DnsClientCache -ErrorAction SilentlyContinue){if(([string]$d.Entry) -match $netioc){$o.network_ioc_hits+=([string]$d.Entry+' ['+[string]$d.Data+']')}}
$hosts=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'; if(Test-Path $hosts){foreach($line in Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue){if($line -match $netioc){$o.network_ioc_hits+=('hosts: '+$line.Trim())}}}
try{foreach($p in Get-ChildItem -LiteralPath '\\.\pipe\' -ErrorAction Stop){if($p.Name -match '(?i)k2f_chan'){$o.named_pipe_hits+=$p.Name}}}catch{}
try{$d=Get-MpComputerStatus -ErrorAction Stop;$o.defender=@{available=$true;antivirus_enabled=[bool]$d.AntivirusEnabled;real_time_protection=[bool]$d.RealTimeProtectionEnabled;signature_age_days=[uint32]$d.AntivirusSignatureAge}}catch{}
$o | ConvertTo-Json -Depth 6 -Compress`
	ps = strings.ReplaceAll(ps, "__AUDIT_PROCESS_ID__", itoa(uint32(os.Getpid())))
	encoded := base64.StdEncoding.EncodeToString(encodeUTF16LE(ps))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			detail = ": " + detail
		}
		s.CollectionErrors = append(s.CollectionErrors, "PowerShell snapshot collection failed: "+err.Error()+detail)
		return s
	}
	if err := json.Unmarshal(out, &s); err != nil {
		s.CollectionErrors = append(s.CollectionErrors, "PowerShell snapshot JSON parse failed: "+err.Error())
		return s
	}
	for _, conn := range s.ExternalTCP {
		remoteIP := conn.Remote
		if i := strings.LastIndex(remoteIP, ":"); i >= 0 {
			remoteIP = remoteIP[:i]
		}
		if isKnownNetworkIOCIP(remoteIP) {
			s.NetworkIOCHits = append(s.NetworkIOCHits, "active TCP: "+conn.Remote+" ["+conn.Process+" PID "+itoa(conn.PID)+"]")
		}
	}
	return s
}

func encodeUTF16LE(s string) []byte {
	r := []rune(s)
	b := make([]byte, 0, len(r)*2)
	for _, v := range r {
		if v <= 0xffff {
			b = append(b, byte(v), byte(v>>8))
		} else {
			v -= 0x10000
			hi, lo := uint16(0xd800+(v>>10)), uint16(0xdc00+(v&0x3ff))
			b = append(b, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		}
	}
	return b
}

func (s SystemSnapshot) addFindings(r *Report) {
	for _, x := range s.RunEntries {
		addFinding(r, "REVIEW", "Suspicious Run key", x.Location, x.Name+" = "+x.Command, x.Confidence)
	}
	for _, x := range s.Services {
		addFinding(r, "REVIEW", "Unusual automatic service", x.Location, x.Name+" | "+x.Command, x.Confidence)
	}
	for _, x := range s.ScheduledTasks {
		addFinding(r, "REVIEW", "Suspicious scheduled task action", x.Location, x.Name+" | "+x.Command, x.Confidence)
	}
	for _, x := range s.StartupFiles {
		addFinding(r, "INFO", "Startup folder entry", x.Location, x.Name, x.Confidence)
	}
	for _, x := range s.SuspiciousCOM {
		addFinding(r, "REVIEW", "Per-user COM registration in writable path", x.Location, x.Name+" -> "+x.Command, x.Confidence)
	}
	for _, x := range s.Processes {
		severity := "REVIEW"
		category := "Suspicious live process command/path"
		if strings.Contains(x.Confidence, "documented K2F persistence module loaded") {
			severity = "CRITICAL"
			category = "K2F persistence DLL loaded in process"
		}
		addFinding(r, severity, category, x.Path, x.Name+" PID="+itoa(x.PID)+" "+strings.TrimSpace(x.Command), x.Confidence)
	}
	for _, x := range s.NetworkIOCHits {
		addFinding(r, "CRITICAL", "Known K2F network IOC (DNS/hosts/TCP)", "", x, "high")
	}
	for _, x := range s.NamedPipeHits {
		addFinding(r, "CRITICAL", "K2F named pipe present", x, "Named pipe name matches documented K2F control channel", "high")
	}
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
