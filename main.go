package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/eiannone/keyboard"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/romanSPB15/go-tui"
)

type Config struct {
	Device string `yaml:"capture-device" env:"CAPTURE-DEVICE"`
	Type   string `yaml:"packet-type" env:"CAPTURE-TYPE"`
}

func main() {
	app := tui.NewDebugApp()
	cfg := &Config{}
	if cleanenv.ReadConfig("config.yaml", cfg) != nil {
		return
	}

	handle, err := pcap.OpenLive(cfg.Device, 1600, true, pcap.BlockForever)
	if err != nil {
		os.WriteFile("err.txt", []byte(err.Error()), 0644)
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp"); err != nil {
		log.Fatal(err)
	}

	// fmt.Printf("Захват пакетов с %s...\r\n", cfg.Device)

	// --- Настройка TUI ---
	labels := make([]*tui.Label, 10)
	for i := range 10 {
		labels[i] = tui.NewDynamicLabel("", app.Window().Width())
		app.AddComponents(labels[i])
	}

	const bufferSize = 10
	buffer := make([]string, bufferSize)
	head := 0
	count := 0

	var mu sync.Mutex

	addToBuffer := func(s string) {
		mu.Lock()
		defer mu.Unlock()

		buffer[head] = s
		head = (head + 1) % bufferSize
		if count < bufferSize {
			count++
		}
	}

	updateLabels := func() {
		mu.Lock()
		defer mu.Unlock()

		for i := range bufferSize {
			var idx int
			if count < bufferSize {
				idx = i
				if i >= count {
					labels[i].Text = ""
					continue
				}
			} else {
				idx = (head + i) % bufferSize
			}
			labels[i].Text = buffer[idx]
		}
		app.Redraw()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	app.AddKeyHandler(keyboard.KeyArrowDown, func() {
		app.Quit()
	})

	go app.Run()

	for {
		select {
		case packet := <-packetSource.Packets():
			var line string

			switch cfg.Type {
			case "IP", "ip":
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					line = fmt.Sprintf("IP: %15s -> %15s, contents: %s", ip.SrcIP, ip.DstIP)
				} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv6)
					line = fmt.Sprintf("IPv6: %s -> %s", ip.SrcIP, ip.DstIP)
				}
			case "TCP", "tcp":
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					line = fmt.Sprintf("TCP Port: %5d -> %5d", tcp.SrcPort, tcp.DstPort)
				}
			}

			addToBuffer(line)
			updateLabels()
		case <-app.OnQuit():
			return
		}

	}
}
