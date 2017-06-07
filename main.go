package main

import (
	"flag"
	nuageConfig "github.com/nuagenetworks/nuage-libnetwork/config"
	"github.com/nuagenetworks/nuage-libnetwork/driver"
)

func main() {
	nuageConfig.SetupLogging()
	nuageDriver := driver.NewNuageLibNetworkDriver()
	flagSet := flag.CommandLine
	nuageDriver.ParseArgs(flagSet)
	flag.Parse()
	nuageDriver.Run()
}
