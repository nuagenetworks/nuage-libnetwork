/*
###########################################################################
#
#   Filename:           driver.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork driver that runs all components
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package driver

import (
	"encoding/json"
	"flag"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/plugins"
	nuageApi "github.com/nuagenetworks/nuage-libnetwork/api"
	"github.com/nuagenetworks/nuage-libnetwork/audit"
	"github.com/nuagenetworks/nuage-libnetwork/client"
	nuageConfig "github.com/nuagenetworks/nuage-libnetwork/config"
	"github.com/nuagenetworks/nuage-libnetwork/ipam"
	"github.com/nuagenetworks/nuage-libnetwork/remote"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"
)

//NuageLibNetworkDriver contains handles to all the components
type NuageLibNetworkDriver struct {
	configFile   string
	runAudit     bool
	config       *nuageConfig.NuageLibNetworkConfig
	ipamDriver   *ipam.NuageIPAMDriver
	remoteDriver *remote.NuageRemoteDriver
	vsdClient    *client.NuageVSDClient
	vrsClient    *client.NuageVRSClient
	dockerClient *client.NuageDockerClient
	auditRoutine *audit.NuageAudit
}

//NewNuageLibNetworkDriver Creates a new libnetwork driver instance
func NewNuageLibNetworkDriver() *NuageLibNetworkDriver {
	return &NuageLibNetworkDriver{}
}

//ParseArgs parses the command line arguments
func (nuagedriver *NuageLibNetworkDriver) ParseArgs(flagSet *flag.FlagSet) {
	flagSet.StringVar(&nuagedriver.configFile, "config",
		"", "YAML configuration for LibNetwork")
	flagSet.BoolVar(&nuagedriver.runAudit, "audit",
		false, "Run VSD/VRS Audit for plugin")
}

//Run stitches different modules of nuage libnetwork driver
func (nuagedriver *NuageLibNetworkDriver) Run() {
	log.Warnf("Starting Nuage Libnetwork Remote Driver and IPAM Driver")
	var err error
	nuagedriver.config, err = nuageConfig.ReadConfigFile(nuagedriver.configFile)
	if err != nil {
		log.Errorf("Reading config file failed with error: %v", err)
		return
	}

	nuageConfig.SetLogLevel(nuagedriver.config)

	channels := &nuageApi.NuageLibNetworkChannels{}
	var ipamServeMux, remoteServeMux *http.ServeMux
	// if v2 listen all requests on one socket. if v1 it will listen
	// on both sockets
	remoteServeMux = http.NewServeMux()
	if nuagedriver.config.PluginVersion == "v1" {
		ipamServeMux = http.NewServeMux()
	} else {
		ipamServeMux = remoteServeMux
		handleDriverActivationCalls(ipamServeMux)
	}

	if err = nuagedriver.setupModules(channels, ipamServeMux, remoteServeMux); err != nil {
		log.Errorf("Initialization failed with error: %v", err)
		return
	}

	nuagedriver.startModules(ipamServeMux, remoteServeMux)

	if nuagedriver.runAudit {
		nuagedriver.auditRoutine.AuditNow()
		return
	}

	//signal handler
	go nuagedriver.signalHandler(channels)

	select {
	case <-channels.Stop:
		log.Infof("Shutting down Nuage libnetwork Remote and IPAM driver plugins...")
	}
	time.Sleep(1500 * time.Millisecond)
	log.Infof("Nuage libnetwork Remote and IPAM driver plugins shutdown complete.")
}

func (nuagedriver *NuageLibNetworkDriver) setupModules(channels *nuageApi.NuageLibNetworkChannels, ipamServeMux, remoteServeMux *http.ServeMux) error {
	channels.Stop = make(chan bool)
	channels.VRSChannel = make(chan *nuageApi.VRSEvent)
	channels.VSDChannel = make(chan *nuageApi.VSDEvent)
	channels.DockerChannel = make(chan *nuageApi.DockerEvent)
	var err error
	nuagedriver.vrsClient, err = client.NewNuageVRSClient(nuagedriver.config, channels)
	if err != nil {
		log.Errorf("Initializing VRS client failed with error: %v", err)
		return err
	}
	nuagedriver.vsdClient, err = client.NewNuageVSDClient(nuagedriver.config, channels)
	if err != nil {
		log.Errorf("Initializing VSD client failed with error: %v", err)
		return err
	}
	nuagedriver.dockerClient, err = client.NewNuageDockerClient(nuagedriver.config, channels)
	if err != nil {
		log.Errorf("Initializing Docker client failed with error: %v", err)
		return err
	}
	nuagedriver.remoteDriver, err = remote.NewNuageRemoteDriver(nuagedriver.config, channels, remoteServeMux)
	if err != nil {
		log.Errorf("Initializing remote driver failed with error: %v", err)
		return err
	}
	nuagedriver.ipamDriver, err = ipam.NewNuageIPAMDriver(nuagedriver.config, channels, ipamServeMux)
	if err != nil {
		log.Errorf("Initializing ipam driver failed with error: %v", err)
		return err
	}
	nuagedriver.auditRoutine = audit.NewNuageAudit(channels)
	log.Debugf("Finished setting up modules")
	return nil
}

func (nuagedriver *NuageLibNetworkDriver) startModules(ipamServeMux, remoteServeMux *http.ServeMux) {

	go nuagedriver.vrsClient.Start()
	go nuagedriver.vsdClient.Start()
	go nuagedriver.dockerClient.Start()
	if nuagedriver.runAudit {
		return
	}

	go nuagedriver.auditRoutine.Start()
	// if v2 then listen all requests on one socket. if v1 then will listen
	// on both sockets
	if nuagedriver.config.PluginVersion == "v1" {
		go nuagedriver.handleSocketCalls(ipamServeMux, "nuage-ipam")
	}
	go nuagedriver.handleSocketCalls(remoteServeMux, "nuage")
	log.Debugf("Finished starting modules")
}

func handleDriverActivationCalls(serveMux *http.ServeMux) {
	routeMap := map[string]func(http.ResponseWriter, *http.Request){
		"/Plugin.Activate":   activate,
		"/Plugin.Deactivate": deactivate,
	}

	for requestRoute, dispatchRoute := range routeMap {
		serveMux.HandleFunc(requestRoute, dispatchRoute)
	}
}

func (nuagedriver *NuageLibNetworkDriver) handleSocketCalls(serveMux *http.ServeMux, pluginName string) error {
	pluginPath := path.Join(nuageConfig.PluginDir, pluginName) + ".sock"
	if err := os.Remove(pluginPath); err != nil {
		log.Warnf("Removing plugin file failed with error: %v", err)
	}
	if err := os.MkdirAll(nuageConfig.PluginDir, 0700); err != nil {
		log.Errorf("Creating plugin directory failed with error: %v", err)
		return err
	}

	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: pluginPath, Net: "unix"})
	if err != nil {
		log.Errorf("Listening on socket failed with error: %v", err)
		return err
	}
	defer l.Close()

	server := &http.Server{Handler: serveMux}
	log.Debugf("Plugin serving http requests on %s", pluginPath)
	return server.Serve(l)
}

func activate(w http.ResponseWriter, r *http.Request) {
	log.Infof("Activating libnetwork plugin")
	resp, err := json.Marshal(plugins.Manifest{Implements: []string{"NetworkDriver", "IpamDriver"}})
	if err != nil {
		log.Errorf("Marshalling JSON response failed with error: %v", err)
		return
	}
	w.Write(resp)
}

func deactivate(w http.ResponseWriter, r *http.Request) {
	log.Infof("Deactivating libnetwork plugin")
}

func (nuagedriver *NuageLibNetworkDriver) signalHandler(channels *nuageApi.NuageLibNetworkChannels) {
	var err error
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)

	for {
		switch <-sigs {
		case syscall.SIGINT:
			fallthrough
		case syscall.SIGTERM:
			close(channels.Stop)
		case syscall.SIGUSR1:
			nuagedriver.config, err = nuageConfig.ReadConfigFile(nuagedriver.configFile)
			if err != nil {
				log.Errorf("Reading config file failed with error: %v", err)
				continue
			}
			nuageConfig.SetLogLevel(nuagedriver.config)
		case syscall.SIGUSR2:
			nuagedriver.auditRoutine.AuditNow()
		}
	}
}
