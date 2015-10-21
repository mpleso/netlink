package main

import (
	"github.com/platinasystems/netlink"
)

func main() {
	n, err := netlink.New()
	if err != nil {
		panic(err)
	}
	for {
		n.Rx()
	}
}
