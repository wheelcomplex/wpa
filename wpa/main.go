
package main

import (
	"github.com/go-av/file"
	"github.com/go-av/wpa"
	"flag"
	"fmt"
	"log"
)

func dump(arr []wpa.Network) {
	fmt.Println("total", len(arr))
	for i, n := range arr {
		fmt.Println(i, n)
	}
}

func main() {
	cli := flag.Bool("cli", false, "cli mode")
	scan := flag.Bool("scan", false, "do scan")
	load := flag.Bool("load", false, "do load config")
	flag.Parse()

	if *load {
		wpa.LoadConfig()
		return
	}

	if *scan {
		results := wpa.Scan()
		dump(results)
		return
	}

	if *cli {
		f := file.AppendTo("/var/log/docli.log").LimitSize(1024*128)
		log.SetOutput(f)
		wpa.DoCli(flag.Args())
		return
	}
}

