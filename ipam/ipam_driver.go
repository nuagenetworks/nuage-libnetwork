/*
###########################################################################
#
#   Filename:           ipam_driver.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork IPAM driver
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package ipam

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/plugins"
	"github.com/docker/go-plugins-helpers/ipam"
	"github.com/docker/libnetwork/ipamapi"
	nuageApi "github.com/nuagenetworks/nuage-libnetwork/api"
	nuageConfig "github.com/nuagenetworks/nuage-libnetwork/config"
	"github.com/nuagenetworks/nuage-libnetwork/utils"
	"net"
	"net/http"
	"strings"
	"sync"
)

// NuageIPAMDriver Ipam Driver structure
type NuageIPAMDriver struct {
	sync.Mutex
	pluginVersion string
	vsdNetworkMap *utils.HashMap
	stop          chan bool
	dockerChannel chan *nuageApi.DockerEvent
	vsdChannel    chan *nuageApi.VSDEvent
}

//NewNuageIPAMDriver factory method for IPAM Driver
func NewNuageIPAMDriver(config *nuageConfig.NuageLibNetworkConfig, channels *nuageApi.NuageLibNetworkChannels, serveMux *http.ServeMux) (*NuageIPAMDriver, error) {
	nuageipam := &NuageIPAMDriver{}
	nuageipam.stop = channels.Stop
	nuageipam.dockerChannel = channels.DockerChannel
	nuageipam.vsdChannel = channels.VSDChannel
	nuageipam.vsdNetworkMap = utils.NewHashMap()
	nuageipam.pluginVersion = config.PluginVersion
	nuageipam.registerCalls(serveMux)
	log.Debugf("Finished initializing ipam driver module")
	return nuageipam, nil
}

func (nuageipam *NuageIPAMDriver) registerCalls(serveMux *http.ServeMux) {
	routeMap := map[string]func(http.ResponseWriter, *http.Request){
		"/IpamDriver.GetDefaultAddressSpaces": nuageipam.GetDefaultAddressSpaces,
		"/IpamDriver.RequestPool":             nuageipam.RequestPool,
		"/IpamDriver.ReleasePool":             nuageipam.ReleasePool,
		"/IpamDriver.RequestAddress":          nuageipam.RequestAddress,
		"/IpamDriver.ReleaseAddress":          nuageipam.ReleaseAddress,
		"/IpamDriver.GetCapabilities":         nuageipam.GetCapabilities,
	}

	if nuageipam.pluginVersion == "v1" {
		routeMap["/Plugin.Activate"] = nuageipam.activate
		routeMap["/Plugin.Deactivate"] = nuageipam.deactivate
	}

	for requestRoute, dispatchRoute := range routeMap {
		serveMux.HandleFunc(requestRoute, dispatchRoute)
	}
}

// GetCapabilities return capabilities
func (nuageipam *NuageIPAMDriver) GetCapabilities(w http.ResponseWriter, req *http.Request) {
	log.Infof("GetCapabilities called")
	resp := &ipam.CapabilitiesResponse{}
	content, err := json.Marshal(resp)
	if err != nil {
		utils.HandleHTTPError(w, "Generating Getcapabilities Response", err)
		return
	}
	log.Infof("GetCapabilities finished")
	w.Write(content)
}

//GetDefaultAddressSpaces returns the default address space
func (nuageipam *NuageIPAMDriver) GetDefaultAddressSpaces(w http.ResponseWriter, req *http.Request) {
	log.Infof("Getting default address spaces")
	resp := &ipam.AddressSpacesResponse{
		LocalDefaultAddressSpace:  "local",
		GlobalDefaultAddressSpace: "global",
	}
	content, err := json.Marshal(resp)
	if err != nil {
		utils.HandleHTTPError(w, "Generating GetDefaultAddressSpaces Response", err)
		return
	}
	w.Write(content)
}

// RequestPool allocates a new pool
func (nuageipam *NuageIPAMDriver) RequestPool(w http.ResponseWriter, req *http.Request) {
	r := &ipam.RequestPoolRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal RequestPool request", err)
		return
	}

	log.Infof("RequestPool payload is %+v", r)

	networkParams := nuageConfig.ParseNuageParams(r.Options)
	err = nuageConfig.ValidateNuageParams(networkParams)
	if err != nil {
		utils.HandleHTTPError(w, "Validating nuage params", err)
		return
	}
	networkParams.SubnetCIDR = r.Pool

	dockerResponse := nuageApi.DockerChanRequest(nuageipam.dockerChannel,
		nuageApi.DockerCheckNetworkListEvent, networkParams)
	networkOverlaps := dockerResponse.DockerData.(bool)
	if dockerResponse.Error != nil {
		utils.HandleHTTPError(w, "Checking existing networks", dockerResponse.Error)
		return
	}
	if networkOverlaps {
		utils.HandleHTTPError(w, "Checking existing networks", fmt.Errorf("Network options and subnet overlap with existing network"))
		return
	}

	vsdResp := nuageApi.VSDChanRequest(nuageipam.vsdChannel,
		nuageApi.VSDAddObjectsEvent, networkParams)
	if vsdResp.Error != nil {
		utils.HandleHTTPError(w, "Adding VSD objects", vsdResp.Error)
		return
	}

	poolID := nuageConfig.MD5Hash(networkParams) + "-" + utils.GenerateID(true)[:10]
	resp := &ipam.RequestPoolResponse{
		PoolID: poolID,
		Pool:   r.Pool,
	}

	nuageipam.vsdNetworkMap.Write(resp.PoolID, networkParams)
	log.Infof("RequestPool response is %+v", resp)

	content, err := json.Marshal(resp)
	if err != nil {
		utils.HandleHTTPError(w, "Generating RequestPool Response", err)
		return
	}
	w.Write(content)
}

// ReleasePool releases a pool of ip addresses
func (nuageipam *NuageIPAMDriver) ReleasePool(w http.ResponseWriter, req *http.Request) {
	r := &ipam.ReleasePoolRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal ReleasePool request", err)
		return
	}

	log.Infof("Releasing pool of addresses")
	networkParams, err := nuageipam.getNetworkInfo(r.PoolID)
	if err != nil {
		log.Errorf("populating network params failed with error: %v", err)
	} else {
		vsdResp := nuageApi.VSDChanRequest(nuageipam.vsdChannel,
			nuageApi.VSDDeleteObjectsEvent, networkParams)
		if vsdResp.Error != nil {
			log.Errorf("Deleting VSD objects failed with error: %v", vsdResp.Error)
		}
	}
	nuageipam.vsdNetworkMap.Write(r.PoolID, nil)
	log.Infof("Pool under id %v is released", r.PoolID)

	w.Write([]byte(utils.EmptyHTTPResponse))
}

//RequestAddress allocates an ip address
func (nuageipam *NuageIPAMDriver) RequestAddress(w http.ResponseWriter, req *http.Request) {
	r := &ipam.RequestAddressRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal RequestAddress request", err)
		return
	}

	var resp *ipam.RequestAddressResponse
	log.Infof("RequestAddress payload is %+v", *r)
	if reqType, ok := r.Options[ipamapi.RequestAddressType]; ok && reqType == "com.docker.network.gateway" {
		resp, err = nuageipam.GateWayAddressRequest(r)
		if err != nil {
			utils.HandleHTTPError(w, "Requesting gateway address", err)
			return
		}
	} else {
		networkParams, err := nuageipam.getNetworkInfo(r.PoolID)
		if err != nil {
			utils.HandleHTTPError(w, "Populating network params", err)
			return
		}
		vsdReq := nuageConfig.NuageEventMetadata{
			NetworkParams: networkParams,
			IPAddress:     r.Address,
		}

		vsdResp := nuageApi.VSDChanRequest(nuageipam.vsdChannel,
			nuageApi.VSDAddContainerEvent, vsdReq)
		if vsdResp.Error != nil {
			utils.HandleHTTPError(w, "Creating container on VSD", vsdResp.Error)
			return
		}

		ipAddress := vsdResp.VSDData.(string)
		resp = &ipam.RequestAddressResponse{
			Address: ipAddress,
		}
	}
	log.Infof("RequestAddress served with response %+v", *resp)

	content, err := json.Marshal(resp)
	if err != nil {
		utils.HandleHTTPError(w, "Generating RequestAddress Response", err)
		return
	}
	w.Write(content)
}

//ReleaseAddress releases an ip address
//TODO: Donot do anything if it is gateway address
func (nuageipam *NuageIPAMDriver) ReleaseAddress(w http.ResponseWriter, req *http.Request) {
	r := &ipam.ReleaseAddressRequest{}
	err := utils.ReadRequest(req, r)
	if err != nil {
		utils.HandleHTTPError(w, "Unmarshal ReleaseAddress request", err)
		return
	}

	log.Infof("releasing address = %v under poolID = %v", r.Address, r.PoolID)
	networkParams, err := nuageipam.getNetworkInfo(r.PoolID)
	if err != nil {
		utils.HandleHTTPError(w, "populating network params", err)
		return
	}
	vsdReq := nuageConfig.NuageEventMetadata{
		NetworkParams: networkParams,
		IPAddress:     r.Address,
	}

	vsdResp := nuageApi.VSDChanRequest(nuageipam.vsdChannel,
		nuageApi.VSDDeleteContainerEvent, vsdReq)
	if vsdResp.Error != nil {
		utils.HandleHTTPError(w, "Deleting VSD container", vsdResp.Error)
		return
	}

	log.Infof("released address = %v under poolID = %v", r.Address, r.PoolID)
	w.Write([]byte(utils.EmptyHTTPResponse))
}

//GateWayAddressRequest function takes of gateway and default ip assignment
func (nuageipam *NuageIPAMDriver) GateWayAddressRequest(r *ipam.RequestAddressRequest) (*ipam.RequestAddressResponse, error) {
	var resp ipam.RequestAddressResponse

	networkParams, ok := nuageipam.vsdNetworkMap.Read(r.PoolID)
	if !ok {
		return nil, fmt.Errorf("Gateway address request for unknown network")
	}
	networkOptions := networkParams.(*nuageConfig.NuageNetworkParams)

	ip, subnet, err := net.ParseCIDR(networkOptions.SubnetCIDR)
	if err != nil {
		log.Errorf("Parsing %s for CIDR info failed with error: %v", networkOptions.SubnetCIDR, err)
		return nil, err
	}

	if r.Address != "" {
		size, _ := subnet.Mask.Size()
		resp.Address = r.Address + "/" + fmt.Sprintf("%d", size)
	} else {
		netGW, err := utils.IPIncrement(ip)
		if err != nil {
			log.Errorf("Error getting Gateway %s", err)
			return nil, err
		}
		gatewayAddr := &net.IPNet{IP: netGW, Mask: subnet.Mask}
		resp.Address = gatewayAddr.String()
	}
	log.Infof("Gateway address request response is %+v", resp)
	return &resp, nil
}

func (nuageipam *NuageIPAMDriver) getNetworkInfo(poolID string) (*nuageConfig.NuageNetworkParams, error) {
	nuageipam.Lock()
	defer nuageipam.Unlock()
	log.Debugf("fetching network info for pool id %s", poolID)
	networkInfo, ok := nuageipam.vsdNetworkMap.Read(poolID)
	if !ok {
		networkParamsHash := strings.Split(poolID, "-")

		dockerResp := nuageApi.DockerChanRequest(nuageipam.dockerChannel,
			nuageApi.DockerPoolIDNetworkOptsEvent, networkParamsHash[0])
		networkInfo := dockerResp.DockerData.(*nuageConfig.NuageNetworkParams)
		if dockerResp.Error != nil {
			log.Errorf("Fetching network opts from docker failed with error: %v", dockerResp.Error)
			return nil, dockerResp.Error
		}

		vsdResp := nuageApi.VSDChanRequest(nuageipam.vsdChannel,
			nuageApi.VSDAddObjectsEvent, networkInfo)
		if vsdResp.Error != nil {
			log.Errorf("adding vsd objects failed with error : %v", vsdResp.Error)
			return nil, vsdResp.Error
		}
		nuageipam.vsdNetworkMap.Write(poolID, networkInfo)
		return networkInfo, nil
	}
	return networkInfo.(*nuageConfig.NuageNetworkParams), nil
}

func (nuageipam *NuageIPAMDriver) activate(w http.ResponseWriter, r *http.Request) {
	log.Infof("Activating IPAM driver plugin")
	resp, err := json.Marshal(plugins.Manifest{Implements: []string{"IpamDriver"}})
	if err != nil {
		log.Errorf("Marshalling JSON response failed with error: %v", err)
		return
	}
	w.Write(resp)
}

func (nuageipam *NuageIPAMDriver) deactivate(w http.ResponseWriter, r *http.Request) {
	log.Infof("Deactivating IPAM driver plugin")
}
