// protonproxy: a tiny HTTPS (CONNECT) proxy whose traffic exits through a
// WireGuard tunnel, e.g. a Proton VPN free server. No system VPN adapter needed.
//
// Put protonproxy.exe and proton.conf in the same folder and run it.
// On first run it creates settings.txt next to the exe.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type settings struct {
	listen    string
	username  string
	password  string
	wireguard string
	keepalive int
}

type wgConf struct {
	privateKey string // hex
	publicKey  string // hex
	endpoint   string
	addresses  []netip.Addr
	dns        []netip.Addr
	allowedIPs []string
}

func main() {
	dir := exeDir()
	s, created := loadSettings(filepath.Join(dir, "settings.txt"))
	if created {
		fmt.Println("First run: created settings.txt in", dir)
		fmt.Println("Proxy username:", s.username)
		fmt.Println("Proxy password:", s.password)
		fmt.Println()
	}

	confPath := s.wireguard
	if !filepath.IsAbs(confPath) {
		confPath = filepath.Join(dir, confPath)
	}
	wc, err := parseWG(confPath)
	if err != nil {
		fatal("Could not use " + confPath + ":\n  " + err.Error() +
			"\nSave your Proton WireGuard config there and run again.")
	}

	tnet, err := startTunnel(wc, s.keepalive)
	if err != nil {
		fatal("Could not start the WireGuard tunnel:\n  " + err.Error())
	}
	selfTest(tnet)

	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		fatal("Could not listen on " + s.listen + ":\n  " + err.Error() +
			"\nIs another copy (or Tor / wireproxy) already using that port?")
	}

	_, port, _ := net.SplitHostPort(s.listen)
	fmt.Println("Proxy is running on port", port)
	fmt.Println("Set your phone's proxy server to one of:", strings.Join(lanAddrs(), ", "))
	if s.password == "" {
		fmt.Println("WARNING: no password set, anyone on your network can use this proxy.")
	}
	fmt.Println("Close this window or press Ctrl+C to stop.")

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c, tnet, s)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	fmt.Println("Stopping.")
	ln.Close()
}

// ---- settings ----

func loadSettings(path string) (*settings, bool) {
	s := &settings{
		listen:    "0.0.0.0:8118",
		username:  "proxy",
		wireguard: "proton.conf",
		keepalive: 0,
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		s.password = randomHex(12)
		text := fmt.Sprintf("# protonproxy settings. Edit, then restart.\n"+
			"# Leave password empty to turn the login off (not recommended).\n"+
			"listen=%s\nusername=%s\npassword=%s\nwireguard=%s\n"+
			"# Seconds between keepalive packets. 0 = off.\nkeepalive=%d\n",
			s.listen, s.username, s.password, s.wireguard, s.keepalive)
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			fatal("Could not create " + path + ":\n  " + err.Error())
		}
		return s, true
	}
	if err != nil {
		fatal("Could not read " + path + ":\n  " + err.Error())
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "listen":
			s.listen = v
		case "username":
			s.username = v
		case "password":
			s.password = v
		case "wireguard":
			s.wireguard = v
		case "keepalive":
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				s.keepalive = n
			}
		}
	}
	return s, false
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fatal("Could not generate a password: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ---- WireGuard config ----

func parseWG(path string) (*wgConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &wgConf{}
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch section + "." + k {
		case "interface.privatekey":
			if c.privateKey, err = keyToHex(v); err != nil {
				return nil, fmt.Errorf("bad PrivateKey: %w", err)
			}
		case "interface.address":
			for _, p := range strings.Split(v, ",") {
				if pf, e := netip.ParsePrefix(strings.TrimSpace(p)); e == nil {
					c.addresses = append(c.addresses, pf.Addr())
				}
			}
		case "interface.dns":
			for _, p := range strings.Split(v, ",") {
				if a, e := netip.ParseAddr(strings.TrimSpace(p)); e == nil {
					c.dns = append(c.dns, a)
				}
			}
		case "peer.publickey":
			if c.publicKey, err = keyToHex(v); err != nil {
				return nil, fmt.Errorf("bad PublicKey: %w", err)
			}
		case "peer.allowedips":
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					c.allowedIPs = append(c.allowedIPs, p)
				}
			}
		case "peer.endpoint":
			c.endpoint = v
		}
	}
	switch {
	case c.privateKey == "":
		return nil, fmt.Errorf("no PrivateKey found")
	case c.publicKey == "":
		return nil, fmt.Errorf("no [Peer] PublicKey found")
	case c.endpoint == "":
		return nil, fmt.Errorf("no [Peer] Endpoint found")
	case len(c.addresses) == 0:
		return nil, fmt.Errorf("no Address found")
	}
	if len(c.allowedIPs) == 0 {
		c.allowedIPs = []string{"0.0.0.0/0"}
	}
	if len(c.dns) == 0 {
		c.dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	return c, nil
}

func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key should be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// ---- tunnel ----

func startTunnel(wc *wgConf, keepalive int) (*netstack.Net, error) {
	tun, tnet, err := netstack.CreateNetTUN(wc.addresses, wc.dns, 1280)
	if err != nil {
		return nil, err
	}
	ep, err := net.ResolveUDPAddr("udp", wc.endpoint)
	if err != nil {
		return nil, fmt.Errorf("bad Endpoint %q: %w", wc.endpoint, err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", wc.privateKey)
	fmt.Fprintf(&b, "public_key=%s\n", wc.publicKey)
	fmt.Fprintf(&b, "endpoint=%s\n", ep.String())
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	for _, ip := range wc.allowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
	}
	if err := dev.IpcSet(b.String()); err != nil {
		return nil, err
	}
	if err := dev.Up(); err != nil {
		return nil, err
	}
	return tnet, nil
}

// selfTest asks ipinfo.io (through the tunnel) which country we exit from.
func selfTest(tnet *netstack.Net) {
	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: tnet.DialContext},
	}
	req, _ := http.NewRequest("GET", "https://ipinfo.io/country", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("WARNING: tunnel test failed:", err)
		fmt.Println("The proxy will still start, but check proton.conf if pages do not load.")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	fmt.Println("Tunnel OK. Exit country:", strings.TrimSpace(string(body)))
}

// ---- proxy ----

func handle(c net.Conn, tnet *netstack.Net, s *settings) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !authOK(req, s) {
		io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
			"Proxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	if req.Method != http.MethodConnect {
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	remote, err := tnet.DialContext(ctx, "tcp", req.Host)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	defer remote.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	c.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, br); done <- struct{}{} }()
	go func() { io.Copy(c, remote); done <- struct{}{} }()
	<-done
}

func authOK(r *http.Request, s *settings) bool {
	if s.password == "" {
		return true
	}
	h := r.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return false
	}
	want := s.username + ":" + s.password
	return subtle.ConstantTimeCompare(raw, []byte(want)) == 1
}

// ---- helpers ----

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

func lanAddrs() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
				out = append(out, ip4.String())
			}
		}
	}
	return out
}

// fatal prints a message and waits for Enter, so a double-clicked window
// stays open long enough to read it.
func fatal(msg string) {
	fmt.Println()
	fmt.Println(msg)
	fmt.Println()
	fmt.Print("Press Enter to close...")
	bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(1)
}
