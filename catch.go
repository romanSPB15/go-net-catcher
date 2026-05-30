package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func List() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Ошибка при поиске устройств: ", err)
	}

	if len(devices) == 0 {
		log.Fatal("Устройства не найдены.")
	}

	for i, device := range devices {
		fmt.Printf("[%d] Имя: %s\n", i, device.Name)
		fmt.Printf("    Описание: %s\n\n", device.Description)
	}
}
