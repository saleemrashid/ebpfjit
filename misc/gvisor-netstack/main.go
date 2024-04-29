//go:build linux

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	localPort = 80
)

var (
	localAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
)

func main() {
	runtime.GOMAXPROCS(1)

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <interface>\n", os.Args[0])
		os.Exit(1)
	}
	tapName := os.Args[1]

	fd, err := tun.OpenTAP(tapName)
	if err != nil {
		log.Fatal(err)
	}

	mtu, err := rawfile.GetMTU(tapName)
	if err != nil {
		log.Fatal(err)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            mtu,
		EthernetHeader: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	table := stack.Table{
		Rules: []stack.Rule{
			// Prerouting
			{
				Target: &stack.RedirectTarget{
					Port:            localPort,
					NetworkProtocol: ipv4.ProtocolNumber,
				},
			},
			{
				Target: &stack.AcceptTarget{},
			},
			// Input
			{
				Target: &stack.AcceptTarget{},
			},
			// Forward
			{
				Target: &stack.AcceptTarget{},
			},
			// Output
			{
				Target: &stack.AcceptTarget{},
			},
			// Postrouting
			{
				Target: &stack.MasqueradeTarget{},
			},
			{
				Target: &stack.AcceptTarget{},
			},
		},
		BuiltinChains: [stack.NumHooks]int{
			stack.Prerouting:  0,
			stack.Input:       2,
			stack.Forward:     3,
			stack.Output:      4,
			stack.Postrouting: 5,
		},
	}
	s.IPTables().ReplaceTable(stack.NATID, table, false)

	nicID := tcpip.NICID(1)

	e := s.CreateNIC(nicID, linkEP)
	if e != nil {
		log.Fatal(e)
	}
	e = s.SetSpoofing(nicID, true)
	if e != nil {
		log.Fatal(e)
	}

	e = s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   localAddr,
			PrefixLen: 0,
		},
	}, stack.AddressProperties{})
	if e != nil {
		log.Fatal(e)
	}

	subnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		log.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         nicID,
		},
	})

	l, err := gonet.ListenTCP(s, tcpip.FullAddress{Port: localPort}, ipv4.ProtocolNumber)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Print(err)
			continue
		}

		go serve(conn)
	}
}

func serve(conn net.Conn) {
	defer conn.Close()

	_, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nHello from Go\n"))
}
