
package main

import (
	"bufio"
	"net/http"
	"log"
	"fmt"
	"time"

	"github.com/go-av/wpa"
	"github.com/go-av/lush/m"
	"code.google.com/p/go.net/websocket"
)

func ctrlServer(ws *websocket.Conn) {
	br := bufio.NewReader(ws)
	ch := make(chan m.M, 0)
	log.Println("ctrl:", "starts")
	go func () {
		for {
			r, ok := <-ch
			if !ok {
				break
			}
			log.Println("ctrl: out", r)
			fmt.Fprintln(ws, r.Json())
		}
		log.Println("ctrl:", "close")
	}()
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			break
		}
		in := m.M{}
		in.FromJson(l)
		log.Println("ctrl: in", in)
		if !in.Has("ts") {
			continue
		}

		if in.S("op") == "WifiScanResults" {
			ch <- m.M{"r": 0, "ts": in.I64("ts"), "list": wpa.ScanResults()}
		}

		if in.S("op") == "WifiScan" {
			go func (ts int64) {
				list := wpa.Scan()
				out := m.M{"r": 0, "ts": ts , "list": list}
				ch <- out
			}(in.I64("ts"))
		}

		if in.S("op") == "WifiConnect" {
			go func (ts int64) {
				ssid := in.S("Ssid")
				bssid := in.S("Bssid")

				if in.B("SetConfig") {
					wpa.SetConfig(wpa.Config{
						Ssid: ssid,
						Bssid: bssid,
						KeyMgmt: in.S("KeyMgmt"),
						Key: in.S("Key"),
					})
				}

				wpa.Connect(ssid, bssid)
				ok := wpa.WaitCompleted(ssid, bssid, time.Second*10)
				out := m.M{"ts": ts}
				if !ok {
					out["r"] = 1
					out["err"] = "ConnectFailed"
				} else {
					out["r"] = 0
				}

				if !ok && in.B("SetConfig") {
					wpa.DelConfig(wpa.Config{
						Ssid: ssid,
						Bssid: bssid,
					})
				}

				ch <- out
			}(in.I64("ts"))
		}
	}
	close(ch)
}

// This example demonstrates a trivial echo server.
func CtrlServer() {
	log.Println("ctrl:", "start server")
	http.Handle("/fmbox", websocket.Handler(ctrlServer))
	err := http.ListenAndServe(":8888", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}

