/*
###########################################################################
#
#   Filename:           remote_driver.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork remote driver
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package remote

import (
	"encoding/json"
	"fmt"
	"github.com/docker/docker/pkg/plugins"
	"github.com/docker/go-plugins-helpers/network"
	nuageApi "github.com/nuagenetworks/nuage-libnetwork/api"
	nuageConfig "github.com/nuagenetworks/nuage-libnetwork/config"
	"github.com/nuagenetworks/nuage-libnetwork/utils"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"net/http"
	"strings"
	"sync"
)

//NuageRemoteDriver remote driver handler structure
type NuageRemoteDriver struct {
	sync.Mutex
	scope                   string
	pluginVersion           string
	networkSettingsMap      *utils.HashMap
	endpointIDToIntfNameMap *utils.HashMap
	stop                    chan bool
	vsdChannel              chan *nuageApi.VSDEvent
	dockerChannel           chan *nuageApi.DockerEvent
}

// NewNuageRemoteDriver factory method for remote driver
func NewNuageRemoteDriver(config *nuageConfig.NuageLibNetworkConfig, channels *nuageApi.NuageLibNetworkChannels, serveMux *http.ServeMux) (*NuageRemoteDriver, error) {
	nuageremote := &NuageRemoteDriver{}
	nuageremote.scope = config.Scope
	nuageremote.stop = channels.Stop
	nuageremote.vsdChannel = channels.VSDChannel
	nuageremote.dockerChannel = channels.DockerChannel
	nuageremote.pluginVersion = config.PluginVersion
	nuageremote.networkSettingsMap = utils.NewHashMap()
	nuageremote.endpointIDToIntfNameMap = utils.NewHashMap()
	nuageremote.registerCalls(serveMux)
	log.Debugf("Finished initializing remote driver module")
	return nuageremote, nil
}

func (nuageremote *NuageRemoteDriver) registerCalls(serveMux *http.ServeMux) {
	routeMap := map[string]func(http.ResponseWriter, *http.Request){
		"/NetworkDriver.GetCapabilities":             nuageremote.GetCapabilities,
		"/NetworkDriver.CreateNetwork":               nuageremote.CreateNetwork,
		"/NetworkDriver.DeleteNetwork":               nuageremote.DeleteNetwork,
		"/NetworkDriver.CreateEndpoint":              nuageremote.CreateEndpoint,
		"/NetworkDriver.DeleteEndpoint":              nuageremote.DeleteEndpoint,
		"/NetworkDriver.EndpointOperInfo":            nuageremote.EndpointInfo,
		"/NetworkDriver.Join":                        nuageremote.Join,
		"/NetworkDriver.Leave":                       nuageremote.Leave,
		"/NetworkDriver.AllocateNetwork":             nuageremote.AllocateNetwork,
		"/NetworkDriver.FreeNetwork":                 nuageremote.FreeNetwork,
		"/NetworkDriver.ProgramExternalConnectivity": nuageremote.ProgramExternalConnectivity,
		"/NetworkDriver.RevokeExternalConnectivity":  nuageremote.RevokeExternalConnectivity,
	}
	if nuageremote.pluginVersion == "v1" {
		routeMap["/Plugin.Activate"] = nuageremote.activate
		routeMap["/Plugin.Deactivate"] = nuageremote.deactivate
	}
	for requestRoute, dispatchRoute := range routeMap {
		serveMux.HandleFunc(requestRoute, dispatchRoute)
	}
}

// GetCapabilities tells libnetwork this driver is local scope
func (nuageremote *NuageRemoteDriver) GetCapabilities(w http.ResponseWriter, req *http.Request) {
	log.Infof("GetCapabilities Called")

	var capability string

	switch nuageremote.scope {
	case "local":
		capability = network.LocalScope
	case "global":
		capability = network.GlobalScope
	default:
		utils.HandleHTTPError(w, "GetCapabilities", fmt.Errorf("Unknown scope specified in configuration"))
		return
	}

	resp := &network.CapabilitiesResponse{Scope: capability}
	content, err := json.Marshal(resp)
	if err != nil {
		utils.HandleHTTPError(w, "Generating Getcapabilities Response", err)
		return
	}
	log.Infof("GetCapabilities finished")
	w.Write(content)
}

// CreateNetwork creates a new Network and links it to an Existing network based on the Options given
func (nuageremote *NuageRemoteDriver) CreateNetwork(w http.ResponseWriter, req *http.Request) {
	r := &network.CreateNetworkRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal CreateNetwork request", err)
		return
	}
	log.Debugf("Nuage remote driver create network %s called", r.NetworkID)
	w.Write([]byte(utils.EmptyHTTPResponse))
}

// DeleteNetwork deletes a network kn Libnetwork. The corresponding network in Nuage VSD is NOT deleted.
func (nuageremote *NuageRemoteDriver) DeleteNetwork(w http.ResponseWriter, req *http.Request) {
	r := &network.DeleteNetworkRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal DeleteNetwork request", err)
		return
	}
	log.Debugf("Nuage remote driver delete network %s called", r.NetworkID)
	w.Write([]byte(utils.EmptyHTTPResponse))
}

// AllocateNetwork creates a new Network and links it to an Existing network based on the Options given
func (nuageremote *NuageRemoteDriver) AllocateNetwork(w http.ResponseWriter, req *http.Request) {
	log.Debugf("AllocateNetwork")
	w.Write([]byte(utils.EmptyHTTPResponse))
}

// FreeNetwork deletes a network. The corresponding network in Nuage VSD is NOT deleted.
func (nuageremote *NuageRemoteDriver) FreeNetwork(w http.ResponseWriter, req *http.Request) {
	log.Debugf("FreeNetwork")
	w.Write([]byte(utils.EmptyHTTPResponse))
}

// CreateEndpoint creates a new MACVLAN Endpoint
func (nuageremote *NuageRemoteDriver) CreateEndpoint(w http.ResponseWriter, req *http.Request) {
	r := &network.CreateEndpointRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal CreateEndpoint request", err)
		return
	}

	log.Infof("CreateEndpoint payload is %+v", r)
	log.Infof("CreateEndpoint interface payload is %+v", r.Interface)

	if r.Interface.Address == "" {
		utils.HandleHTTPError(w, "CreateEndpoint", fmt.Errorf("Empty IP address passed to CreateEndpoint method in driver"))
		return
	}
	ip := strings.Split(r.Interface.Address, "/")

	networkParams, err := nuageremote.getNetworkParams(r.NetworkID)
	if err != nil {
		utils.HandleHTTPError(w, "Fetching Network Params", err)
		return
	}

	vsdReq := nuageConfig.NuageEventMetadata{
		NetworkParams: networkParams,
		IPAddress:     ip[0],
	}
	vsdResp := nuageApi.VSDChanRequest(nuageremote.vsdChannel,
		nuageApi.VSDGetContainerInfoEvent, vsdReq)
	if vsdResp.Error != nil {
		utils.HandleHTTPError(w, fmt.Sprintf("Finding mac address for ip %s in network %s", ip[0], r.NetworkID), vsdResp.Error)
		return
	}
	epInfo := vsdResp.VSDData.([]string)
	resp := &network.CreateEndpointResponse{
		Interface: &network.EndpointInterface{
			MacAddress: epInfo[0],
		},
	}

	nuageremote.endpointIDToIntfNameMap.Write(r.EndpointID, epInfo[1])

	log.Infof("CreateEndpoint(%+v) successful. Response is %+v", r, resp.Interface)
	content, err := json.Marshal(resp)
	if err != nil {
		utils.HandleHTTPError(w, "Generating CreateEndpoint Response", err)
		return
	}
	w.Write(content)
}

// Join creates a Nuage interface to be moved to the container netns
func (nuageremote *NuageRemoteDriver) Join(w http.ResponseWriter, req *http.Request) {
	r := &network.JoinRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal Join request", err)
		return
	}
	log.Infof("Join request payload %+v: ", r)
	intfName, ok := nuageremote.endpointIDToIntfNameMap.Read(r.EndpointID)
	if !ok {
		utils.HandleHTTPError(w, "Join Request", fmt.Errorf("cannot find endpointID in cache"))
		return
	}

	networkParams, err := nuageremote.getNetworkParams(r.NetworkID)
	if err != nil {
		utils.HandleHTTPError(w, fmt.Sprintf("Fetching network params for network %s", r.NetworkID), err)
		return
	}

	containerInfo := make(map[string]string)
	containerInfo[nuageConfig.BridgePortKey] = intfName.(string)
	containerInfo[nuageConfig.EntityPortKey] = strings.Replace(containerInfo[nuageConfig.BridgePortKey], "-1", "-2", -1)
	err = SetupVeth(containerInfo)
	if err != nil {
		utils.HandleHTTPError(w, fmt.Sprintf("Setting up veth %s", containerInfo[nuageConfig.BridgePortKey]), err)
		return
	}

	ifname := &network.InterfaceName{
		SrcName:   containerInfo[nuageConfig.EntityPortKey],
		DstPrefix: nuageConfig.ContainerIfacePrefix,
	}

	resp := &network.JoinResponse{
		InterfaceName:         *ifname,
		Gateway:               networkParams.Gateway,
		DisableGatewayService: false,
	}
	log.Infof("Join successful(%+v). Response is %+v", r, resp)

	content, err := json.Marshal(resp)
	if err != nil {
		utils.HandleHTTPError(w, "Generating Join Response", err)
		return
	}
	w.Write(content)
}

// Leave removes a Nuage Endpoint from a container
func (nuageremote *NuageRemoteDriver) Leave(w http.ResponseWriter, req *http.Request) {
	r := &network.LeaveRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal Leave request", err)
		return
	}
	log.Infof("Leave request for endpoint %s in network %s", r.EndpointID, r.NetworkID)
	w.Write([]byte(utils.EmptyHTTPResponse))
}

// DeleteEndpoint deletes a Nuage Endpoint
func (nuageremote *NuageRemoteDriver) DeleteEndpoint(w http.ResponseWriter, req *http.Request) {
	r := &network.DeleteEndpointRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal DeleteEndpoint request", err)
		return
	}
	log.Infof("Delete endpoint request: %v", r)
	nuageremote.endpointIDToIntfNameMap.Write(r.EndpointID, nil)
	w.Write([]byte(utils.EmptyHTTPResponse))
}

// EndpointInfo returns informatoin about a Nuage endpoint
func (nuageremote *NuageRemoteDriver) EndpointInfo(w http.ResponseWriter, req *http.Request) {
	r := &network.InfoRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal EndpointInfo request", err)
		return
	}
	log.Infof("Endpoint info request: %v", r)
	resp := &network.InfoResponse{
		Value: make(map[string]string),
	}
	content, err := json.Marshal(resp)
	if err != nil {
		utils.HandleHTTPError(w, "Generating EndpointInfo Response", err)
		return
	}
	w.Write(content)
}

// DiscoverNew is not used by local scoped drivers
func (nuageremote *NuageRemoteDriver) DiscoverNew(w http.ResponseWriter, req *http.Request) {
	r := &network.DiscoveryNotification{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal DiscoverNew request", err)
		return
	}
	log.Infof("DiscoverNew called %v", r)
	w.Write([]byte(utils.EmptyHTTPResponse))
}

// DiscoverDelete is not used by local scoped drivers
func (nuageremote *NuageRemoteDriver) DiscoverDelete(w http.ResponseWriter, req *http.Request) {
	r := &network.DiscoveryNotification{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal DiscoverDelete request", err)
		return
	}
	log.Infof("DiscoverDelete called %v", r)
	w.Write([]byte(utils.EmptyHTTPResponse))
}

// ProgramExternalConnectivity programs external connectivity to container
func (nuageremote *NuageRemoteDriver) ProgramExternalConnectivity(w http.ResponseWriter, req *http.Request) {
	r := &network.ProgramExternalConnectivityRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal ProgramExternalConnectivity request", err)
		return
	}
	log.Infof("ProgramExternalConnectivity %v", r)
	w.Write([]byte(utils.EmptyHTTPResponse))
}

// RevokeExternalConnectivity revokes external connectivity of container
func (nuageremote *NuageRemoteDriver) RevokeExternalConnectivity(w http.ResponseWriter, req *http.Request) {
	r := &network.RevokeExternalConnectivityRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal RevokeExternalConnectivity request", err)
		return
	}
	log.Infof("RevokeExternalConn %v", r)
	w.Write([]byte(utils.EmptyHTTPResponse))
}

func (nuageremote *NuageRemoteDriver) buildCache() {
	dockerResp := nuageApi.DockerChanRequest(nuageremote.dockerChannel,
		nuageApi.DockerGetOptsAllNetworksEvent, nil)
	for networkID, networkParams := range dockerResp.DockerData.(map[string]*nuageConfig.NuageNetworkParams) {
		nuageremote.networkSettingsMap.Write(networkID, networkParams)
	}
	log.Debugf("Building remote driver cache complete")
}

func (nuageremote *NuageRemoteDriver) getNetworkParams(networkID string) (*nuageConfig.NuageNetworkParams, error) {
	nuageremote.Lock()
	defer nuageremote.Unlock()

	networkParams, ok := nuageremote.networkSettingsMap.Read(networkID)
	if !ok {
		dockerResp := nuageApi.DockerChanRequest(nuageremote.dockerChannel,
			nuageApi.DockerNetworkIDInspectEvent, networkID)
		if dockerResp.Error != nil {
			log.Errorf("Fetching network params for network %s failed with error: %v", networkID, dockerResp.Error)
			return nil, dockerResp.Error
		}
		networkParams := dockerResp.DockerData.(*nuageConfig.NuageNetworkParams)
		nuageremote.networkSettingsMap.Write(networkID, networkParams)
		return networkParams, nil
	}
	return networkParams.(*nuageConfig.NuageNetworkParams), nil
}

//SetupVeth creates a veth pair and brings them up
func SetupVeth(containerInfo map[string]string) error {
	log.Debugf("SetupVeth called")
	localVethPair := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: containerInfo[nuageConfig.BridgePortKey]},
		PeerName:  containerInfo[nuageConfig.EntityPortKey],
	}

	err := netlink.LinkDel(localVethPair)
	if err != nil {
		log.Debugf("Deleting veth pair %+v failed with error: %s", localVethPair, err)
	}

	localVethPair = &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: containerInfo[nuageConfig.BridgePortKey]},
		PeerName:  containerInfo[nuageConfig.EntityPortKey],
	}

	err = netlink.LinkAdd(localVethPair)
	if err != nil {
		log.Errorf("failed to create the veth pair named: [ %v ] error: [ %s ]", localVethPair, err)
		return err
	}

	err = netlink.LinkSetUp(localVethPair)
	if err != nil {
		log.Errorf("Error enabling  Veth local iface: [ %v ]", localVethPair)
		return err
	}
	log.Debugf("Finished setting up veth")
	return nil
}

func (nuageremote *NuageRemoteDriver) activate(w http.ResponseWriter, r *http.Request) {
	log.Infof("Activating Remote Driver Plugin")
	resp, err := json.Marshal(plugins.Manifest{Implements: []string{"NetworkDriver"}})
	if err != nil {
		log.Errorf("Marshalling JSON response failed with error: %v", err)
		return
	}
	w.Write(resp)
}

func (nuageremote *NuageRemoteDriver) deactivate(w http.ResponseWriter, r *http.Request) {
	log.Infof("Deactivating Remote Driver plugin")
}
