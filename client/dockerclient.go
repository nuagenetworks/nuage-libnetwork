/*
###########################################################################
#
#   Filename:           dockerclient.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork docker client API
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package client

import (
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	dockerClient "github.com/docker/docker/client"
	nuageApi "github.com/nuagenetworks/nuage-libnetwork/api"
	nuageConfig "github.com/nuagenetworks/nuage-libnetwork/config"
	"github.com/nuagenetworks/nuage-libnetwork/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

//NuageDockerClient structure holds docker client
type NuageDockerClient struct {
	socketFile         string
	dclient            *dockerClient.Client
	connectionRetry    chan bool
	connectionActive   chan bool
	stop               chan bool
	dockerChannel      chan *nuageApi.DockerEvent
	vsdChannel         chan *nuageApi.VSDEvent
	networkParamsTable *utils.HashMap
	pluginVersion      string
}

//NewNuageDockerClient creates a new docker client
func NewNuageDockerClient(config *nuageConfig.NuageLibNetworkConfig, channels *nuageApi.NuageLibNetworkChannels) (*NuageDockerClient, error) {
	var err error
	nuagedocker := &NuageDockerClient{}
	nuagedocker.stop = channels.Stop
	nuagedocker.dockerChannel = channels.DockerChannel
	nuagedocker.vsdChannel = channels.VSDChannel
	nuagedocker.connectionRetry = make(chan bool)
	nuagedocker.connectionActive = make(chan bool)
	nuagedocker.networkParamsTable = utils.NewHashMap()
	nuagedocker.pluginVersion = config.PluginVersion
	nuagedocker.socketFile = config.DockerSocketFile
	nuagedocker.dclient, err = connectToDockerDaemon(nuagedocker.socketFile)
	if err != nil {
		log.Errorf("Connecting to docker client failed with error %v", err)
		return nil, err
	}
	log.Debugf("Finished initializing docker module")
	return nuagedocker, nil
}

//GetRunningContainerList fetches the list of running containers from docker
func (nuagedocker *NuageDockerClient) GetRunningContainerList() ([]types.Container, error) {
	var activeContainersList []types.Container
	var err error
	nuagedocker.executeDockerCommand(
		func() error {
			activeContainersList, err = nuagedocker.dclient.ContainerList(context.Background(), types.ContainerListOptions{})
			return err
		})
	if err != nil {
		log.Errorf("Getting list of running containers failed with error: %v", err)
	}
	log.Debugf("number of containers in docker ps = %d", len(activeContainersList))
	return activeContainersList, nil
}

//CheckNetworkList checks if the given params matches existing network params
func (nuagedocker *NuageDockerClient) CheckNetworkList(nuageParams *nuageConfig.NuageNetworkParams) (bool, error) {
	networkList, err := nuagedocker.dockerNetworkList()
	if err != nil {
		log.Errorf("Retrieving existing networks from docker failed with error: %v", err)
		return true, err
	}

	_, newSubnet, err := net.ParseCIDR(nuageParams.SubnetCIDR)
	if err != nil {
		log.Errorf("ParseCIDR failed for address %s with error: %v", nuageParams.SubnetCIDR, err)
		return true, err
	}
	for _, network := range networkList {
		existingNetworkOptions := nuageConfig.ParseNuageParams(network.IPAM.Options)
		matchingNetworkOpts := nuageConfig.IsSameNetworkOpts(existingNetworkOptions, nuageParams)

		var overlappingSubnets bool
		for _, nwConfig := range network.IPAM.Config {
			_, existingSubnet, err := net.ParseCIDR(nwConfig.Subnet)
			if err != nil {
				log.Errorf("ParseCIDR failed for address %s with error: %v", nwConfig.Subnet, err)
				return true, err
			}
			if newSubnet.Contains(existingSubnet.IP) || existingSubnet.Contains(newSubnet.IP) {
				overlappingSubnets = true
			}
		}

		if matchingNetworkOpts && overlappingSubnets {
			return true, fmt.Errorf("Network options and subnet overlap with existing network")
		}
	}

	return false, nil
}

//GetNetworkOptsFromPoolID fetches network options for a given docker network
func (nuagedocker *NuageDockerClient) GetNetworkOptsFromPoolID(poolID string) (*nuageConfig.NuageNetworkParams, error) {
	networkOpts := &nuageConfig.NuageNetworkParams{}
	networkList, err := nuagedocker.dockerNetworkList()
	if err != nil {
		log.Errorf("Retrieving existing networks from docker failed with error: %v", err)
		return nil, err
	}
	for _, network := range networkList {
		if network.IPAM.Options == nil || len(network.IPAM.Config) == 0 {
			continue
		}
		networkOpts = nuageConfig.ParseNuageParams(network.IPAM.Options)
		networkOpts.SubnetCIDR = network.IPAM.Config[0].Subnet
		if poolID == nuageConfig.MD5Hash(networkOpts) {
			return networkOpts, nil
		}
	}
	return nil, fmt.Errorf("network options with matching poolID not found")
}

//GetNetworkOptsFromNetworkID fetches a network from docker
func (nuagedocker *NuageDockerClient) GetNetworkOptsFromNetworkID(networkID string) (*nuageConfig.NuageNetworkParams, error) {
	var networkInspect types.NetworkResource
	var err error

	nuagedocker.executeDockerCommand(
		func() error {
			networkInspect, err = nuagedocker.dclient.NetworkInspect(context.Background(), networkID, types.NetworkInspectOptions{})
			return err
		})
	if err != nil {
		log.Errorf("Retrieving existing networks from docker failed with error: %v", err)
		return nil, err
	}

	if networkInspect.IPAM.Options == nil || len(networkInspect.IPAM.Config) == 0 {
		return nil, fmt.Errorf("error reading network %s information from docker", networkID)
	}

	networkParams := nuageConfig.ParseNuageParams(networkInspect.IPAM.Options)
	networkParams.SubnetCIDR = networkInspect.IPAM.Config[0].Subnet
	networkParams.Gateway = networkInspect.IPAM.Config[0].Gateway

	nuagedocker.networkParamsTable.Write(networkID, networkParams)

	return networkParams, nil
}

//GetContainerInspect returns the container inspect output of a container
func (nuagedocker *NuageDockerClient) GetContainerInspect(uuid string) (types.ContainerJSON, error) {
	var containerInspect types.ContainerJSON
	var err error

	nuagedocker.executeDockerCommand(
		func() error {
			containerInspect, err = nuagedocker.dclient.ContainerInspect(context.Background(), uuid)
			return err
		})
	if err != nil {
		log.Errorf("Inspect on container %s failed with error %v", uuid, err)
		return types.ContainerJSON{}, err
	}

	return containerInspect, nil
}

//GetNetworkConnectEvents listens for event when a container is connected to "nuage" network
func (nuagedocker *NuageDockerClient) GetNetworkConnectEvents() {
	log.Debugf("docker listening for network connect events")
	filterArgs := filters.NewArgs()
	filterArgs.Add("type", "network")
	filterArgs.Add("event", "connect")
	options := types.EventsOptions{
		Filters: filterArgs,
	}

	eventsChanRO, errChan := nuagedocker.dclient.Events(context.Background(), options)
	for {
		select {
		case eventMsg := <-eventsChanRO:
			if eventMsg.Actor.Attributes["type"] == nuageConfig.DockerNetworkType[nuagedocker.pluginVersion] {
				log.Debugf("got docker event %+v", eventMsg)
				dockerResp := nuageApi.DockerChanRequest(nuagedocker.dockerChannel, nuageApi.DockerNetworkConnectEvent, eventMsg)
				if dockerResp.Error != nil {
					log.Errorf("handling docker event %+v failed with error: %v", eventMsg, dockerResp.Error)
				}
			}
		case <-errChan:
			nuagedocker.connectionRetry <- true
			<-nuagedocker.connectionActive
			go nuagedocker.GetNetworkConnectEvents()
			return
		}
	}
}

func (nuagedocker *NuageDockerClient) GetOptsAllNetworks() (map[string]*nuageConfig.NuageNetworkParams, error) {
	table := make(map[string]*nuageConfig.NuageNetworkParams)
	for _, networkID := range nuagedocker.networkParamsTable.GetKeys() {
		networkParams, ok := nuagedocker.networkParamsTable.Read(networkID)
		if ok {
			table[networkID] = networkParams.(*nuageConfig.NuageNetworkParams)
		}
	}
	return table, nil
}

func (nuagedocker *NuageDockerClient) buildCache() {
	log.Debugf("building cache from docker")
	networkList, err := nuagedocker.dockerNetworkList()
	if err != nil {
		log.Errorf("Fetching network list from docker failed with error %v", err)
		return
	}
	for _, network := range networkList {
		networkOpts := nuageConfig.ParseNuageParams(network.IPAM.Options)
		networkParams := &nuageConfig.NuageNetworkParams{
			Organization: networkOpts.Organization,
			Domain:       networkOpts.Domain,
			Zone:         networkOpts.Zone,
			SubnetName:   networkOpts.SubnetName,
			User:         networkOpts.User,
		}
		for _, nwConfig := range network.IPAM.Config {
			networkParams.SubnetCIDR = nwConfig.Subnet
			networkParams.Gateway = nwConfig.Gateway
		}
		nuagedocker.networkParamsTable.Write(network.ID, networkParams)
	}
	return
}

func (nuagedocker *NuageDockerClient) dockerNetworkList() ([]types.NetworkResource, error) {
	var networkList []types.NetworkResource
	var err error

	nuagedocker.executeDockerCommand(
		func() error {
			filterArgs := filters.NewArgs()
			filterArgs.Add("driver", nuageConfig.DockerNetworkType[nuagedocker.pluginVersion])
			options := types.NetworkListOptions{
				Filters: filterArgs,
			}
			networkList, err = nuagedocker.dclient.NetworkList(context.Background(), options)
			return err
		})
	if err != nil {
		log.Errorf("Retrieving existing networks from docker failed with error: %v", err)
		return networkList, err
	}
	return networkList, nil
}

//for every network connect assign the ip for the relavent endpoint id
func (nuagedocker *NuageDockerClient) processEvent(msg events.Message) {
	log.Debugf("%+v", msg)
	id := msg.Actor.Attributes["container"]
	inspect, err := nuagedocker.dclient.ContainerInspect(context.Background(), id)
	if err != nil {
		log.Errorf("Inspect on container %s failed with error %v", id, err)
	} else {
		var ip string
		networkParamsIntf, ok := nuagedocker.networkParamsTable.Read(msg.Actor.ID)
		if !ok {
			log.Errorf("NuageDockerClient: NetworkID not found in local cache")
			return
		}
		networkParams := networkParamsIntf.(*nuageConfig.NuageNetworkParams)
		for _, nwConfig := range inspect.NetworkSettings.Networks {
			if msg.Actor.ID == nwConfig.NetworkID {
				ip = nwConfig.IPAddress
			}
		}
		pg, _ := checkPolicyGroup(inspect.Config.Env)
		orchestrationID, _ := checkOrchestrationID(inspect.Config.Env)
		newReq := nuageConfig.NuageEventMetadata{
			Name:            strings.Replace(inspect.Name, "/", "", -1),
			UUID:            inspect.ID,
			PolicyGroup:     pg,
			OrchestrationID: orchestrationID,
			IPAddress:       ip,
			NetworkParams:   networkParams,
		}
		nuageApi.VSDChanRequest(nuagedocker.vsdChannel, nuageApi.VSDUpdateContainerEvent, newReq)
	}
}

func checkPolicyGroup(vars []string) (string, bool) {
	return checkEnvVar("NUAGE-POLICY-GROUP", vars)
}

func checkOrchestrationID(vars []string) (string, bool) {
	return checkEnvVar("MESOS_TASK_ID", vars)
}

func checkEnvVar(key string, envVars []string) (string, bool) {
	for _, variable := range envVars {
		if ok, err := regexp.MatchString(key, variable); ok {
			kv := strings.Split(variable, "=")
			if len(kv) == 0 {
				log.Errorf("Splitting %s in KV pair failed with error: %v", variable, err)
				return "", false
			}
			return kv[1], true
		}
	}
	return "", false
}

//Start listen for events on docker channel
func (nuagedocker *NuageDockerClient) Start() {
	log.Infof("Starting docker client")

	go func() {
		<-nuagedocker.connectionActive
		go nuagedocker.buildCache()
		go nuagedocker.GetNetworkConnectEvents()
	}()

	nuagedocker.handleConnectionRetry()

	for {
		select {
		case dockerEvent := <-nuagedocker.dockerChannel:
			go nuagedocker.handleDockerEvent(dockerEvent)
		case <-nuagedocker.connectionRetry:
			nuagedocker.handleConnectionRetry()
		case <-nuagedocker.stop:
			return
		}
	}
}

func (nuagedocker *NuageDockerClient) handleDockerEvent(event *nuageApi.DockerEvent) {
	var data interface{}
	var err error
	log.Debugf("Received a docker event %+v", event)
	switch event.EventType {
	case nuageApi.DockerCheckNetworkListEvent:
		data, err = nuagedocker.CheckNetworkList(event.DockerReqObject.(*nuageConfig.NuageNetworkParams))
	case nuageApi.DockerNetworkIDInspectEvent:
		data, err = nuagedocker.GetNetworkOptsFromNetworkID(event.DockerReqObject.(string))
	case nuageApi.DockerPoolIDNetworkOptsEvent:
		data, err = nuagedocker.GetNetworkOptsFromPoolID(event.DockerReqObject.(string))
	case nuageApi.DockerContainerListEvent:
		data, err = nuagedocker.GetRunningContainerList()
	case nuageApi.DockerGetOptsAllNetworksEvent:
		data, err = nuagedocker.GetOptsAllNetworks()
	case nuageApi.DockerNetworkConnectEvent:
		nuagedocker.processEvent(event.DockerReqObject.(events.Message))
	default:
		log.Errorf("NuageDockerClient: unknown api invocation")
	}
	event.DockerRespObjectChan <- &nuageApi.DockerRespObject{DockerData: data, Error: err}
	log.Debugf("Served docker event %+v", event)
}

func (nuagedocker *NuageDockerClient) handleConnectionRetry() {
	if _, err := nuagedocker.dclient.Ping(context.Background()); err != nil {
		log.Errorf("Ping to docker host failed with error = %v. trying to reconnect", err)
		log.Errorf("will try to reconnect in every 3 seconds")
		var err error
		for {
			nuagedocker.dclient, err = connectToDockerDaemon(nuagedocker.socketFile)
			_, err = nuagedocker.dclient.Ping(context.Background())
			if err != nil {
				time.Sleep(3 * time.Second)
			} else {
				log.Infof("docker connection is now active")
				nuagedocker.connectionActive <- true
				break
			}
		}
	} else {
		nuagedocker.connectionActive <- true
	}
}

func connectToDockerDaemon(socketFile string) (*dockerClient.Client, error) {
	err := os.Setenv("DOCKER_HOST", socketFile)
	if err != nil {
		log.Errorf("Setting DOCKER_HOST failed with error: %v", err)
		return nil, err
	}
	client, err := dockerClient.NewEnvClient()
	if err != nil {
		log.Errorf("Connecting to docker client failed with error %v", err)
		return nil, err
	}
	return client, nil
}

func (nuagedocker *NuageDockerClient) executeDockerCommand(dockerCommand func() error) {
	err := dockerCommand()
	if err != nil && isDockerConnectionError(err.Error()) {
		log.Errorf(err.Error())
		nuagedocker.connectionRetry <- true
		<-nuagedocker.connectionActive
		nuagedocker.executeDockerCommand(dockerCommand)
		return
	}
	return
}

func isDockerConnectionError(errMsg string) bool {
	ok, err := regexp.MatchString("Cannot connect to the Docker daemon", errMsg)
	if err != nil {
		log.Errorf("NuageDockerClient: matching strings failed with error %v", err)
	}
	return ok
}
