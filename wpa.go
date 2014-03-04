
package wpa

import (
	"bufio"
	"os/exec"
	"fmt"
	"bytes"
	"time"
	"os"
	"strings"
	"log"
	"io"
	"github.com/go-av/gexpect"
)

type Network struct {
	Stat string // ASSOSIACTING, COMPLETED ...
	Ssid string
	Bssid string
	KeyMgmt string // "WPA-PSK", "WEP", ""
	SignalLevel int

	Config *Config
}

type Config struct {
	Ssid string
	Bssid string
	KeyMgmt string // "WPA-PSK", "WEP", ""
	ScanSsid bool
	Key string
	Priority int
	Static bool
	Ip string
	Netmask string
	Gateway string
	Dns string
}

func spawnCli() (child *gexpect.ExpectSubprocess) {
	var err error
	child, err = gexpect.Spawn("wpa_cli -p /var/run/wpa")
	if err != nil {
		log.Println("wpa:", "spawn wpa_cli failed")
	}
	go func () {
		time.Sleep(time.Second*8)
		child.Close()
	}()
	return
}

func runCli(arg string) (r io.Reader) {
	cmd := exec.Command("wpa_cli", "-p", "/var/run/wpa", arg)
	b := new(bytes.Buffer)
	cmd.Stdout = b
	cmd.Run()
	return b
}

func getstr(v, pref string, out *string) {
	if !strings.HasPrefix(v, pref) {
		return
	}
	v = strings.TrimPrefix(v, pref)
	if strings.HasPrefix(v, `"`) {
		v = strings.Trim(v, `"`)
	}
	*out = v
}

func getint(v, pref string, out *int) {
	s := ""
	getstr(v, pref, &s)
	fmt.Sscanf(s, "%d", out)
}

func getbool(v, pref string, out *bool) {
	s := ""
	getstr(v, pref, &s)
	if s == "1" {
		*out = true
	}
}

func findConfig(configs []Config, ssid, bssid string) (*Config, int) {
	for i, c := range configs {
		if c.Ssid == ssid && (c.Bssid == "" || c.Bssid == bssid) {
			return &configs[i], i
		}
	}
	return nil, -1
}

func status() (stat string, id int, ssid, bssid string) {
	r := runCli("status")
	log.Println("wpa:", "get status")

	br := bufio.NewReader(r)

	id = -1

	for {
		l, err := br.ReadString('\n')
		if err != nil {
			break
		}
		l = strings.TrimSpace(l)
		if l == ">" {
			break
		}
		getstr(l, "ssid=", &ssid)
		getstr(l, "bssid=", &bssid)
		getstr(l, "wpa_state=", &stat)
		getint(l, "id=", &id)
	}

	log.Println("wpa:", "status:", stat, id, ssid)

	return
}

func Status() (stat string) {
	stat, _, _, _ = status()
	return
}

func ScanResults() (results []Network) {
	configs := LoadConfig()
	stat, id, _, _ := status()

	r := runCli("scan_results")
	br := bufio.NewReader(r)

	log.Println("wpa.scan_results:", "start read")

	for {
		l, err := br.ReadString('\n')
		if err != nil {
			break
		}
		l = strings.TrimSpace(l)
		if l == ">" {
			break
		}
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		if len(f[0]) != len("78:a1:06:b0:99:4c") || f[0][2] != ':' {
			continue
		}
		n := Network{}
		n.Bssid = f[0]
		fmt.Sscanf(f[2], "%d", &n.SignalLevel)

		if strings.HasPrefix(f[3], "[WEP") {
			n.KeyMgmt = "WEP"
		}
		if strings.HasPrefix(f[3], "[WPA") {
			n.KeyMgmt = "WPA-PSK"
		}
		if len(f) >= 4 {
			n.Ssid = strings.Join(f[4:], " ")
		}

		i := -1
		n.Config, i = findConfig(configs, n.Ssid, n.Bssid)
		if n.Config != nil && i == id {
			n.Stat = stat

			// move to front
			log.Println("wpa.scan_results:   >>current asossiacting")
			if len(results) > 0 {
				tmp := results[0]
				results[0] = n
				n = tmp
			}
		}
		log.Println("wpa.scan_results:", len(results), n, "config:", i)
		results = append(results, n)
	}

	return
}

func Scan() (results []Network) {
	child := spawnCli()

	child.Expect("> ")

	child.SendLine("scan")
	log.Println("wpa.scan:", "send scan")
	child.Expect("> ")

	child.Expect("<3>CTRL-EVENT-SCAN-RESULTS")
	log.Println("wpa.scan:", "got scan results")

	child.Close()

	return ScanResults()
}

func SaveConfig(configs []Config) {
	f, err := os.Create("/etc/wpa.conf")
	if err != nil {
		return
	}

	fmt.Fprintln(f, "ctrl_interface=DIR=/var/run/wpa")
	for _, n := range configs {
		fmt.Fprintln(f, "network={")
		fmt.Fprintf(f, "ssid=\"%s\"\n", n.Ssid)
		if n.Bssid != "" {
			fmt.Fprintf(f, "bssid=%s\n", n.Bssid)
		}
		if n.KeyMgmt == "" || n.KeyMgmt == "NONE" {
			fmt.Fprintf(f, "key_mgmt=%s\n", "NONE")
		} else {
			fmt.Fprintf(f, "key_mgmt=%s\n", n.KeyMgmt)
			fmt.Fprintf(f, "psk=\"%s\"\n", n.Key)
		}
		if n.Priority != 0 {
			fmt.Fprintf(f, "priority=%d\n", n.Priority)
		}
		if n.ScanSsid {
			fmt.Fprintf(f, "scan_ssid=1\n")
		}
		if !n.Static {
			fmt.Fprintln(f, "#static=1")
		} else {
			fmt.Fprintf(f, "#ip=%s\n", n.Ip)
			fmt.Fprintf(f, "#netmask=%s\n", n.Netmask)
			fmt.Fprintf(f, "#gateway=%s\n", n.Gateway)
			fmt.Fprintf(f, "#dns=%s\n", n.Dns)
		}
		fmt.Fprintln(f, "}")
	}

	f.Close()
}

func LoadConfig() (configs []Config) {
	f, err := os.Open("/etc/wpa.conf")
	if err != nil {
		log.Println("wpa:", "loadConfg", err)
		return
	}

	depth := 0
	br := bufio.NewReader(f)
	n := Config{}

	for {
		l, e := br.ReadString('\n')
		if e != nil {
			break
		}
		l = strings.Trim(l, "\n\r\t #")
		if strings.HasPrefix(l, "network={") {
			depth++
			n = Config{}
		}
		if depth == 1 {
			getstr(l, "ssid=", &n.Ssid)
			getstr(l, "bssid=", &n.Bssid)
			getstr(l, "key_mgmt=", &n.KeyMgmt)
			getstr(l, "psk=", &n.Key)
			getbool(l, "static=", &n.Static)
			getbool(l, "scan_ssid=", &n.ScanSsid)
			getint(l, "priority=", &n.Priority)
			getstr(l, "ip=", &n.Ip)
			getstr(l, "netmask=", &n.Netmask)
			getstr(l, "gateway=", &n.Gateway)
			getstr(l, "dns=", &n.Dns)
		}
		if strings.HasPrefix(l, "}") {
			configs = append(configs, n)
			depth--
		}
	}
	f.Close()
	return
}

func DelConfig(nc Config) {
	configs := LoadConfig()
	_, i := findConfig(configs, nc.Ssid, nc.Bssid)
	if i != -1 {
		configs = append(configs[0:i], configs[i+1:]...)
	}
	SaveConfig(configs)
}

func SetConfig(nc Config) {
	configs := LoadConfig()
	if c, _ := findConfig(configs, nc.Ssid, nc.Bssid); c == nil {
		configs = append(configs, nc)
	}
	SaveConfig(configs)
}

func WaitCompleted(ssid, bssid string, timeout time.Duration) bool {
	for timeout > 0 {
		stat, _, ssid1, bssid1 := status()
		if ssid1 == ssid &&
			(bssid == "" || bssid1 == bssid) &&
			stat == "COMPLETED" {
			return true
		}
		dur := time.Second*1
		time.Sleep(dur)
		timeout -= dur
	}
	return false
}

func Connect(ssid, bssid string, nc Config) bool {
	configs := LoadConfig()
	for i := range configs {
		configs[i].Priority = 0
	}
	if c, _ := findConfig(configs, ssid, bssid); c != nil {
		c.Priority = 1
	} else {
		nc.Ssid = ssid
		nc.Bssid = bssid
		nc.Priority = 1
		configs = append(configs, nc)
	}
	SaveConfig(configs)

	log.Println("wpa.connect", "reconfigure and reassociate")
	runCli("reconfigure")
	runCli("reassociate")

	if WaitCompleted(ssid, bssid, time.Second*10) {
		return true
	} else {
		log.Println("wpa.connect", "failed and del config")
		DelConfig(nc)
		return false
	}
}

func DoCli(args []string) {
	if len(args) < 2 {
		log.Println("docli:", "at least 3 os.Args")
		return
	}

	dev := args[0]
	stat := args[1]

	log.Println("docli:", "args:", dev, stat)

	if stat != "CONNECTED" {
		log.Println("docli:", "not connected yet. stat=", stat)
		return
	}

	configs := LoadConfig()
	_id := os.Getenv("WPA_ID")
	if _id == "" {
		log.Println("docli:", "missing $WPA_ID")
		return
	}
	var id int
	fmt.Sscanf(_id, "%d", &id)
	if id > len(configs) {
		log.Println("docli:", "$WPA_ID out of range")
		return
	}
	n := configs[id]

	if !n.Static {
		log.Println("docli:", "do dhcp config #", id)
		exec.Command("dhclient", dev).Run()
	} else {
		log.Println("docli:", "do static config #", id)
		log.Println("docli:", "  ip", n.Ip)
		log.Println("docli:", "  netmask", n.Netmask)
		log.Println("docli:", "  gateway", n.Gateway)
		log.Println("docli:", "  dns", n.Dns)

		exec.Command("ifconfig", dev, n.Ip, "netmask", n.Netmask, "up").Run()

		if n.Gateway != "" {
			exec.Command("route", "add", "default", "gw", n.Gateway).Run()
		}

		if n.Dns != "" {
			if f, err := os.Create("/etc/resolv.conf"); err == nil {
				fmt.Fprintln(f, "nameserver", n.Dns)
				f.Close()
			}
		}
	}
}

