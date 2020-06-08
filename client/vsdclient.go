/*
###########################################################################
#
#   Filename:           vsdclient.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork VSD client
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package client

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/mitchellh/mapstructure"
	"github.com/nuagenetworks/go-bambou/bambou"
	nuageApi "github.com/nuagenetworks/nuage-libnetwork/api"
	nuageConfig "github.com/nuagenetworks/nuage-libnetwork/config"
	"github.com/nuagenetworks/nuage-libnetwork/utils"
	"github.com/nuagenetworks/vspk-go/vspk"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

//NuageVSDClient contains necessary information for a VSD session
type NuageVSDClient struct {
	sync.Mutex
	url                      string
	username                 string
	password                 string
	organization             string
	hypervisorID             string
	timeInterval             int
	numOfRetryAttempts       int
	intfSeqNum               int
	vsdConnection            *bambou.Session
	vsdUser                  *vspk.Me
	intfSeqNumTable          *utils.HashMap
	ipToVSDContainerMap      *utils.HashMap
	nwParamsToVSDObjectsMap  *utils.HashMap
	connectionRetry          chan bool
	connectionActive         chan bool
	stop                     chan bool
	vsdChannel               chan *nuageApi.VSDEvent
	vrsChannel               chan *nuageApi.VRSEvent
	dockerChannel            chan *nuageApi.DockerEvent
	infiniteUpdateRetryQueue chan nuageConfig.NuageEventMetadata
	auditContainers          map[string]int
}

// NewNuageVSDClient factory method for VSD client
func NewNuageVSDClient(config *nuageConfig.NuageLibNetworkConfig, channels *nuageApi.NuageLibNetworkChannels) (*NuageVSDClient, error) {
	var err error
	nuagevsd := &NuageVSDClient{}
	nuagevsd.url = config.URL
	nuagevsd.username = config.Username
	nuagevsd.organization = config.Organization
	nuagevsd.timeInterval = config.TimeInterval
	nuagevsd.numOfRetryAttempts = config.NumOfRetries
	nuagevsd.stop = channels.Stop
	nuagevsd.vrsChannel = channels.VRSChannel
	nuagevsd.vsdChannel = channels.VSDChannel
	nuagevsd.dockerChannel = channels.DockerChannel
	nuagevsd.ipToVSDContainerMap = utils.NewHashMap()
	nuagevsd.nwParamsToVSDObjectsMap = utils.NewHashMap()
	nuagevsd.intfSeqNumTable = utils.NewHashMap()
	nuagevsd.connectionRetry = make(chan bool)
	nuagevsd.connectionActive = make(chan bool)
	nuagevsd.auditContainers = make(map[string]int)
	nuagevsd.infiniteUpdateRetryQueue = make(chan nuageConfig.NuageEventMetadata)
	nuagevsd.hypervisorID, err = getHostExternalID()
	if err != nil {
		log.Errorf("Getting external host id failed with error: %v", err)
		return nil, err
	}

	nuagevsd.username, err = utils.DecodeBase64String(config.Username)
	if err != nil {
		log.Errorf("Decoding username failed with error: %v", err)
		return nil, err
	}

	nuagevsd.password, err = utils.DecodeBase64String(config.Password)
	if err != nil {
		log.Errorf("Decoding password failed with error: %v", err)
		return nil, err
	}

	nuagevsd.organization, err = utils.DecodeBase64String(config.Organization)
	if err != nil {
		log.Errorf("Decoding organization failed with error: %v", err)
		return nil, err
	}

	nuagevsd.vsdConnection, nuagevsd.vsdUser, err = nuagevsd.createVSDSession()
	if err != nil {
		log.Errorf("Creating new vsd session failed with error: %v", err)
		return nil, err
	}
	log.Debugf("Finished initializing VSD module")
	return nuagevsd, nil
}

//AddVSDObjects add the vsd objects for given organization, domain, network to cache and returns vsd subnet id
func (nuagevsd *NuageVSDClient) AddVSDObjects(vsdReq *nuageConfig.NuageNetworkParams) error {
	enterprise, err := nuagevsd.FetchEnterpriseInfo(vsdReq.Organization)
	if err != nil {
		log.Errorf("Fetching enterprise information from VSD failed with error: %v", err)
		return err
	}

	domain, err := nuagevsd.FetchDomainInfo(enterprise, vsdReq.Domain)
	if err != nil {
		log.Errorf("Fetching domain information from VSD failed with error: %v", err)
		return err
	}

	subnet, err := nuagevsd.FetchSubnetInfo(domain, vsdReq.SubnetName)
	if err != nil {
		log.Errorf("Fetching subnet information from VSD failed with error: %v", err)
		return err
	}

	nuagevsd.nwParamsToVSDObjectsMap.Write(vsdReq.String(), subnet)

	return nil
}

//DeleteVSDObjects deletes the vsd objects for give organization
func (nuagevsd *NuageVSDClient) DeleteVSDObjects(vsdReq *nuageConfig.NuageNetworkParams) error {
	nuagevsd.nwParamsToVSDObjectsMap.Write(vsdReq.String(), nil)
	return nil
}

//CreateVSDContainer creates new container on VSD under the given subnet
func (nuagevsd *NuageVSDClient) CreateVSDContainer(vsdReq nuageConfig.NuageEventMetadata) (string, error) {
	resp, ok := nuagevsd.nwParamsToVSDObjectsMap.Read(vsdReq.NetworkParams.String())
	if !ok {
		return "", fmt.Errorf("Could not find network %s info in cache", vsdReq.NetworkParams.String())
	}
	subnet := resp.(*vspk.Subnet)

	containerInfo, err := nuagevsd.populateContainerInfo()
	if err != nil {
		log.Errorf("Populating container info failed with error: %v", err)
		return "", err
	}

	//VSD container interface
	containerInterface := vspk.NewContainerInterface()
	containerInterface.Name = containerInfo[nuageConfig.BridgePortKey]
	containerInterface.MAC = containerInfo[nuageConfig.MACKey]
	containerInterface.IPAddress = vsdReq.IPAddress
	containerInterface.AttachedNetworkID = subnet.ID
	interfaceList := make([]interface{}, 1)
	interfaceList[0] = containerInterface

	//VSD container
	container := vspk.NewContainer()
	container.UUID = containerInfo[nuageConfig.UUIDKey]
	container.Name = containerInfo[nuageConfig.NameKey]
	container.Interfaces = interfaceList
	container.ExternalID = nuagevsd.hypervisorID

	var err1 *bambou.Error
	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Trying to create container %s on VSD", container.UUID)
			err1 = nuagevsd.vsdUser.CreateContainer(container)
			if err1 != nil {
				log.Errorf("Creating container %s failed with error %v", container.UUID, err1)
			}
			return err1
		}, "creating container")
	if err1 != nil {
		log.Errorf("Creating container with UUID %s on VSD failed with error: %v", container.UUID, err1)
		return "", fmt.Errorf("%v", err1)
	}
	mask := net.IPMask(net.ParseIP(containerInterface.Netmask).To4())
	prefixSize, _ := mask.Size()

	log.Debugf("Container ID = %s created on vsd with ip address = %s", container.UUID, containerInterface.IPAddress)
	nuagevsd.ipToVSDContainerMap.Write(vsdReq.NetworkParams.String()+"-"+containerInterface.IPAddress,
		container)
	return fmt.Sprintf("%s/%d", containerInterface.IPAddress, prefixSize), nil
}

//DeleteVSDContainer deletes a VSD container with ip in VSD subnet wit id vsdSubnetID
func (nuagevsd *NuageVSDClient) DeleteVSDContainer(vsdReq nuageConfig.NuageEventMetadata) error {
	var err *bambou.Error

	container, containerInterface := nuagevsd.getContainerAndInterface(vsdReq)
	if container == nil || containerInterface == nil {
		return fmt.Errorf("Failed to find container with ip %s in network %s", vsdReq.IPAddress, vsdReq.NetworkParams.String())
	}

	containerInfo := make(map[string]string)
	containerInfo[nuageConfig.UUIDKey] = container.UUID
	containerInfo[nuageConfig.BridgePortKey] = containerInterface.Name

	intfNum, err1 := GetPortSeqNum(containerInterface.Name)
	if err1 != nil {
		log.Warnf("Finding sequence number for port failed with error: %v", err1)
	}

	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Trying to delete container %s on VSD", container.UUID)
			err = container.Delete()
			if err != nil {
				log.Errorf("Deleting container %s failed with error %v", container.UUID, err)
			}
			return err
		}, "deleting container")
	if err != nil {
		log.Errorf("deleting container with ID %s on VSD failed with error: %v after all retries", container.ID, err)
	}
	log.Debugf("Deleting container %s succesful", container.UUID)

	nuageApi.VRSChanRequest(nuagevsd.vrsChannel, nuageApi.VRSDeleteEvent, containerInfo)

	nuagevsd.intfSeqNumTable.Write(string(intfNum), nil)

	nuagevsd.ipToVSDContainerMap.Write(vsdReq.NetworkParams.String()+"-"+containerInterface.IPAddress, nil)
	return nil
}

//UpdateVPortPolicyGroup updates the policy group information for vport with given ip and PG
func (nuagevsd *NuageVSDClient) UpdateVPortPolicyGroup(vsdReq nuageConfig.NuageEventMetadata) error {
	if vsdReq.PolicyGroup == "" {
		return nil
	}
	container, containerInterface := nuagevsd.getContainerAndInterface(vsdReq)
	if container == nil || containerInterface == nil {
		return fmt.Errorf("Failed to find container with ip %s in network %s", vsdReq.IPAddress, vsdReq.NetworkParams.String())
	}

	log.Debugf("Applying policies for container %s", container.UUID)
	policyFetchingInfo := &bambou.FetchingInfo{Filter: "name == \"" + vsdReq.PolicyGroup + "\""}
	var policies vspk.PolicyGroupsList
	var err *bambou.Error
	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Fetching info for policy %s", vsdReq.PolicyGroup)
			policies, err = nuagevsd.vsdUser.PolicyGroups(policyFetchingInfo)
			return err
		}, "fetching policies")
	if err != nil {
		return fmt.Errorf("Fetching policy %s information from VSD failed with error: %v", vsdReq.PolicyGroup, err)
	}
	if len(policies) == 0 {
		return fmt.Errorf("Policy %s is not found on VSD", vsdReq.PolicyGroup)
	}

	vsdVport := vspk.NewVPort()
	vsdVport.ID = containerInterface.VPortID

	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Assiging policy group to vport %s", vsdVport.ID)
			err = vsdVport.AssignPolicyGroups(policies)
			return err
		}, "assign policy")
	if err != nil {
		return fmt.Errorf("assigning policy groups on vsd failed with error: %v", err)
	}
	log.Debugf("Applying policies done for container %s", container.UUID)
	return nil
}

//UpdateContainerNameUUID updates the name and uuid of container on VSD
func (nuagevsd *NuageVSDClient) UpdateContainerNameUUID(vsdReq nuageConfig.NuageEventMetadata) error {
	var emptyJSON interface{}
	var err *bambou.Error

	container, _ := nuagevsd.getContainerAndInterface(vsdReq)
	if container == nil {
		return fmt.Errorf("Failed to find container with ip %s in network %s", vsdReq.IPAddress, vsdReq.NetworkParams.String())
	}

	fakeUUID := container.UUID
	container.ResyncInfo = emptyJSON
	container.UUID = vsdReq.UUID
	container.Name = vsdReq.Name
	container.OrchestrationID = vsdReq.OrchestrationID

	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Trying to update container fake UUID %s with real UUID %s and name %s", fakeUUID, container.UUID, container.Name)
			err = container.Save()
			return err
		}, "saving container")
	if err != nil {
		log.Errorf("Trying to update container fake UUID %s with real UUID %s and name %s failed with error %v after all retries", fakeUUID, container.UUID, container.Name, err)
		if strings.Contains(err.Error(), "Error Code: 404") {
			nuagevsd.infiniteUpdateRetryQueue <- vsdReq
		}
		return fmt.Errorf("%v", err)
	}
	log.Debugf("Save operation succesful for container %s", container.UUID)
	return nil
}

func (nuagevsd *NuageVSDClient) updateContainer(vsdReq nuageConfig.NuageEventMetadata) error {
	err := nuagevsd.UpdateContainerNameUUID(vsdReq)
	if err != nil {
		return err
	}

	err = nuagevsd.UpdateVPortPolicyGroup(vsdReq)
	if err != nil {
		return err
	}

	container, containerInterface := nuagevsd.getContainerAndInterface(vsdReq)
	if container == nil || containerInterface == nil {
		return fmt.Errorf("Failed to find container with ip %s in network %s", vsdReq.IPAddress, vsdReq.NetworkParams.String())
	}
	containerInfo := make(map[string]string)
	containerInfo[nuageConfig.UUIDKey] = container.UUID
	containerInfo[nuageConfig.NameKey] = container.Name
	containerInfo[nuageConfig.MACKey] = containerInterface.MAC
	containerInfo[nuageConfig.BridgePortKey] = containerInterface.Name
	containerInfo[nuageConfig.EnterpriseKey] = vsdReq.NetworkParams.Organization
	containerInfo[nuageConfig.DomainKey] = vsdReq.NetworkParams.Domain
	containerInfo[nuageConfig.NetworkKey] = vsdReq.NetworkParams.SubnetName
	vrsResp := nuageApi.VRSChanRequest(nuagevsd.vrsChannel, nuageApi.VRSAddEvent, containerInfo)
	if vrsResp.Error != nil {
		return vrsResp.Error
	}
	return nil
}

//GetContainerInfo returns the MAC address used to create container with ip in subnet with ID vsdSubnetID
func (nuagevsd *NuageVSDClient) GetContainerInfo(vsdReq nuageConfig.NuageEventMetadata) ([]string, error) {
	container, containerInterface := nuagevsd.getContainerAndInterface(vsdReq)
	if container == nil || containerInterface == nil {
		return nil, fmt.Errorf("Failed to find container with ip %s in network %s", vsdReq.IPAddress, vsdReq.NetworkParams.String())
	}
	return []string{containerInterface.MAC, containerInterface.Name}, nil
}

//RefreshVSDSession generated new auth token for VSD session
func (nuagevsd *NuageVSDClient) RefreshVSDSession() error {
	var err error
	nuagevsd.vsdConnection.Reset()
	nuagevsd.vsdConnection, nuagevsd.vsdUser, err = nuagevsd.createVSDSession()
	if err != nil {
		log.Errorf("renewing vsd session failed with error: %v", err)
		return err
	}
	return nil
}

//createVethPairNames creates unique names for veth pair
func (nuagevsd *NuageVSDClient) createVethPairNames() []string {
	nuagevsd.Lock()
	defer nuagevsd.Unlock()
	for {
		nuagevsd.intfSeqNum++
		if nuagevsd.intfSeqNum > nuageConfig.MaxIntfNum {
			nuagevsd.intfSeqNum = 0
		}

		if _, ok := nuagevsd.intfSeqNumTable.Read(string(nuagevsd.intfSeqNum)); ok {
			continue
		}
		nuagevsd.intfSeqNumTable.Write(string(nuagevsd.intfSeqNum), true)
		entityPortName := fmt.Sprintf("%s%x-2", nuageConfig.BasePrefix, nuagevsd.intfSeqNum)
		bridgePortName := fmt.Sprintf("%s%x-1", nuageConfig.BasePrefix, nuagevsd.intfSeqNum)
		return []string{bridgePortName, entityPortName}
	}
}

func (nuagevsd *NuageVSDClient) getContainerAndInterface(vsdReq nuageConfig.NuageEventMetadata) (*vspk.Container, *vspk.ContainerInterface) {
	resp, ok := nuagevsd.ipToVSDContainerMap.Read(vsdReq.NetworkParams.String() + "-" + vsdReq.IPAddress)
	if !ok {
		return nil, nil
	}

	container := resp.(*vspk.Container)
	if container.Interfaces == nil {
		return nil, nil
	}

	containerInterface := container.Interfaces[0].(*vspk.ContainerInterface)
	return container, containerInterface
}

//FetchEnterpriseInfo fetches enterprise information from VSD
func (nuagevsd *NuageVSDClient) FetchEnterpriseInfo(enterpriseName string) (*vspk.Enterprise, error) {
	var enterprises vspk.EnterprisesList
	var err *bambou.Error
	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Trying to fetch enterprise objects for organization %s from VSD", enterpriseName)
			enterpriseFetchingInfo := &bambou.FetchingInfo{Filter: "name == \"" + enterpriseName + "\""}
			enterprises, err = nuagevsd.vsdUser.Enterprises(enterpriseFetchingInfo)
			return err
		}, "fetching enterprises")
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	if len(enterprises) == 0 {
		return nil, fmt.Errorf("no enterprises found with name %s", enterpriseName)
	}
	return enterprises[0], nil
}

//FetchDomainInfo fetches domain information from VSD
func (nuagevsd *NuageVSDClient) FetchDomainInfo(enterprise *vspk.Enterprise, domainName string) (*vspk.Domain, error) {
	var domains vspk.DomainsList
	var err *bambou.Error
	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Trying to fetch domain %s information for enterprise %s from VSD", domainName, enterprise.Name)
			domainFetchingInfo := &bambou.FetchingInfo{Filter: "name == \"" + domainName + "\""}
			domains, err = enterprise.Domains(domainFetchingInfo)
			return err
		}, "fetching domains")
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains found with with name %s", domainName)
	}
	return domains[0], nil
}

//FetchSubnetInfo fetches enterprise information from VSD
func (nuagevsd *NuageVSDClient) FetchSubnetInfo(domain *vspk.Domain, subnetName string) (*vspk.Subnet, error) {
	var subnets vspk.SubnetsList
	var err *bambou.Error
	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Trying to fetch subnet %s information for domain %s from VSD", subnetName, domain.Name)
			subnetFetchingInfo := &bambou.FetchingInfo{Filter: "name == \"" + subnetName + "\""}
			subnets, err = domain.Subnets(subnetFetchingInfo)
			return err
		}, "fetching subnet")
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	if len(subnets) == 0 {
		return nil, fmt.Errorf("no subnets found with name %s", subnetName)
	}
	return subnets[0], nil
}

func (nuagevsd *NuageVSDClient) fetchVSDContainerList() (vspk.ContainersList, error) {
	var vsdContainerList vspk.ContainersList
	var tempContainerList vspk.ContainersList
	var err *bambou.Error
	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Trying to get container list for this hypervisor on VSD")
			containerFetchingInfo := &bambou.FetchingInfo{Filter: "externalID == \"" + nuagevsd.hypervisorID + "\""}
			containerFetchingInfo.Page = 0
			containerFetchingInfo.PageSize = 50
			for {
				tempContainerList, err = nuagevsd.vsdUser.Containers(containerFetchingInfo)
				if err != nil {
					return err
				}
				vsdContainerList = append(vsdContainerList, tempContainerList...)
				if len(tempContainerList) < 50 {
					return err
				} else {
					containerFetchingInfo.Page++
				}
			}
		}, "fetching container list")
	if err != nil {
		return vsdContainerList, fmt.Errorf("fetching container list from VSD failed with error: %v after all retries", err)
	}
	for _, vsdContainer := range vsdContainerList {
		if len(vsdContainer.Interfaces) == 0 {
			continue
		}
		containerInterface := vspk.NewContainerInterface()
		vsdContainerInterface := vsdContainer.Interfaces[0].(map[string]interface{})
		_ = mapstructure.Decode(vsdContainerInterface, containerInterface)
		interfaceList := make([]interface{}, 1)
		interfaceList[0] = containerInterface
		vsdContainer.Interfaces = interfaceList
	}
	log.Debugf("Number of containers belonging to this hypervisor %d", len(vsdContainerList))
	return vsdContainerList, nil
}

func (nuagevsd *NuageVSDClient) createVSDSession() (*bambou.Session, *vspk.Me, error) {
	var vsdConnection *bambou.Session
	var vsdUser *vspk.Me
	var err *bambou.Error

	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Creating a new VSD session")
			vsdConnection, vsdUser = vspk.NewSession(nuagevsd.username, nuagevsd.password, nuagevsd.organization, nuagevsd.url)
			if vsdConnection == nil || vsdUser == nil {
				return bambou.NewError(500, "unable to establish vsd connection")
			}
			return nil
		}, "unable to establish connection")
	if err != nil {
		log.Errorf("Creating a new VSD session failed with error %v after all retries", err)
		return nil, nil, fmt.Errorf("%v", err)
	}

	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("VSD session. skip insecure verify")
			err = vsdConnection.SetInsecureSkipVerify(true)
			return err
		}, "skipping insecure verify")
	if err != nil {
		log.Errorf("skipping insecure verify on VSD failed with error: %v after all retries", err)
		return nil, nil, fmt.Errorf("%v", err)
	}

	nuagevsd.makeVSDCall(
		func() *bambou.Error {
			log.Debugf("Start a VSD session")
			err = vsdConnection.Start()
			return err
		}, "starting connection ")
	if err != nil {
		log.Errorf("starting connection on VSD failed with error: %v after all retries", err)
		return nil, nil, fmt.Errorf("%v", err)
	}

	log.Infof("Established connection with VSD")
	return vsdConnection, vsdUser, nil
}

func (nuagevsd *NuageVSDClient) populateContainerInfo() (map[string]string, error) {
	containerInfo := make(map[string]string)
	containerUUID := utils.GenerateID()
	portNames := nuagevsd.createVethPairNames()
	containerInfo[nuageConfig.EntityPortKey] = portNames[1]
	containerInfo[nuageConfig.BridgePortKey] = portNames[0]
	containerInfo[nuageConfig.NameKey] = containerUUID
	mac, err := generateRandomMAC()
	if err != nil {
		log.Errorf("Generating MAC address failed with error: %v", err)
		return nil, err
	}
	containerInfo[nuageConfig.MACKey] = mac.String()
	containerInfo[nuageConfig.UUIDKey] = containerUUID
	return containerInfo, nil
}

// Generate a mac addr
func generateRandomMAC() (net.HardwareAddr, error) {
	hw := make(net.HardwareAddr, 6)
	randbuf := make([]byte, 6)
	h := md5.New()

	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("Getting hostname failed with error: %v", err)
		return nil, err
	}

	_, err = io.WriteString(h, hostname)
	if err != nil {
		log.Errorf("Writing hostname to buffer failed with error: %v", err)
		return nil, err
	}

	hostnameHash := hex.EncodeToString(h.Sum(nil))
	_, err = rand.Read(randbuf)
	if err != nil {
		log.Errorf("Reading random number from buffer failed with error: %v", err)
		return nil, err
	}

	randbuf[0] = byte(int(randbuf[0])&0xFE | 0x02)
	macString1, err := strconv.ParseInt(hostnameHash[:2], 16, 0)
	if err != nil {
		log.Errorf("Parsing \"%s\" failed with error: %v", hostnameHash[:2], err)
		return nil, err
	}

	macString2, _ := strconv.ParseInt(hostnameHash[2:4], 16, 0)
	if err != nil {
		log.Errorf("Parsing \"%s\" failed with error: %v", hostnameHash[2:4], err)
		return nil, err
	}

	randbuf[1] = byte(macString1)
	randbuf[2] = byte(macString2)
	copy(hw, randbuf)
	return hw, nil
}

func (nuagevsd *NuageVSDClient) buildCache() {
	vsdContainerList, err := nuagevsd.fetchVSDContainerList()
	if err != nil {
		log.Errorf("fetching container list from VSD failed with error: %v after all retries", err)
		return
	}

	for _, container := range vsdContainerList {
		if len(container.Interfaces) == 0 {
			continue
		}
		containerInterface := container.Interfaces[0].(*vspk.ContainerInterface)
		networkParams := &nuageConfig.NuageNetworkParams{
			Organization: container.EnterpriseName,
			Domain:       containerInterface.DomainName,
			SubnetName:   containerInterface.NetworkName,
		}
		nuagevsd.ipToVSDContainerMap.Write(networkParams.String()+"-"+containerInterface.IPAddress, container)
	}

	dockerResponse := nuageApi.DockerChanRequest(nuagevsd.dockerChannel, nuageApi.DockerContainerListEvent, nil)
	if dockerResponse.Error != nil {
		log.Warnf("Fetching docker list failed with error: %v", dockerResponse.Error)
	}
	dockerContainerList := dockerResponse.DockerData.([]types.Container)

	for _, container := range vsdContainerList {
		if container.Name != container.UUID {
			continue
		}
		if len(container.Interfaces) == 0 {
			continue
		}
		containerInterface := container.Interfaces[0].(*vspk.ContainerInterface)
		networkParams := &nuageConfig.NuageNetworkParams{
			Organization: container.EnterpriseName,
			Domain:       containerInterface.DomainName,
			SubnetName:   containerInterface.NetworkName,
		}
		for _, dockerContainer := range dockerContainerList {
			for _, endpointSettings := range dockerContainer.NetworkSettings.Networks {
				if endpointSettings.IPAddress == containerInterface.IPAddress &&
					endpointSettings.MacAddress == containerInterface.MAC {
					vsdReq := nuageConfig.NuageEventMetadata{
						UUID:          dockerContainer.ID,
						Name:          dockerContainer.Names[0][1:],
						IPAddress:     containerInterface.IPAddress,
						NetworkParams: networkParams,
					}
					err := nuagevsd.updateContainer(vsdReq)
					if err != nil {
						log.Errorf("Failed updating container %+v", vsdReq)
					}
				}
			}
		}
	}
}

func (nuagevsd *NuageVSDClient) auditVSD() {
	log.Debugf("VSD Audit called")
	vsdLookup := make(map[string]bool)
	vsdContainerList, err := nuagevsd.fetchVSDContainerList()
	if err != nil {
		log.Errorf("fetching container list from VSD failed with error: %v after all retries", err)
		return
	}

	dockerResponse := nuageApi.DockerChanRequest(nuagevsd.dockerChannel, nuageApi.DockerContainerListEvent, nil)
	activeContainerList := dockerResponse.DockerData.([]types.Container)

	for _, container := range activeContainerList {
		for _, endpointSettings := range container.NetworkSettings.Networks {
			vsdLookup[endpointSettings.IPAddress+endpointSettings.MacAddress] = true
		}
	}

	for _, vsdContainer := range vsdContainerList {
		if len(vsdContainer.Interfaces) == 0 {
			continue
		}
		containerInterface := vsdContainer.Interfaces[0].(*vspk.ContainerInterface)
		if _, ok := vsdLookup[containerInterface.IPAddress+containerInterface.MAC]; !ok {
			if _, present := nuagevsd.auditContainers[vsdContainer.UUID]; !present {
				nuagevsd.auditContainers[vsdContainer.UUID]++
			} else {
				nuagevsd.auditContainers[vsdContainer.UUID] = 1
			}
		}
	}

	deleteIds := []string{}

	for id, count := range nuagevsd.auditContainers {
		if count >= 10 {
			for _, vsdContainer := range vsdContainerList {
				if vsdContainer.UUID != id {
					continue
				}
				if len(vsdContainer.Interfaces) == 0 {
					continue
				}
				containerInterface := vsdContainer.Interfaces[0].(*vspk.ContainerInterface)
				nwInfo := nuageConfig.NuageNetworkParams{
					Organization: vsdContainer.EnterpriseName,
					Domain:       containerInterface.DomainName,
					SubnetName:   containerInterface.NetworkName,
				}
				nuagevsd.makeVSDCall(
					func() *bambou.Error {
						log.Debugf("Trying to delete container %s on VSD with ip %s and mac %s", vsdContainer.UUID, containerInterface.IPAddress, containerInterface.MAC)
						err := vsdContainer.Delete()
						log.Debugf("Request to delete container %s complete", vsdContainer.UUID)
						return err
					}, "deleting container")
				if err != nil {
					log.Errorf("deleting container with ID %s on VSD failed with error: %v after all retries", vsdContainer.ID, err)
				}
				nuagevsd.ipToVSDContainerMap.Write(nwInfo.String()+"-"+containerInterface.IPAddress, nil)
			}
			deleteIds = append(deleteIds, id)
		}
	}

	for _, id := range deleteIds {
		delete(nuagevsd.auditContainers, id)
	}
	nuagevsd.cleanupStaleHostPorts()
	log.Debugf("VSD Audit completed")
}

func (nuagevsd *NuageVSDClient) cleanupStaleHostPorts() {
	log.Debugf("stale host ports cleanup called")
	allHostPorts, err := netlink.LinkList()
	if err != nil {
		log.Errorf("In cleanup host ports, getting list of host interfaces failed with error: %v", err)
		return
	}

	for _, link := range allHostPorts {
		linkName := link.Attrs().Name
		r, err := regexp.Compile(linkName)
		if err != nil {
			log.Errorf("Could not compile regex for linkname %s with err: %s", linkName, err)
		}
		if ok := r.MatchString(nuageConfig.BasePrefix); err != nil || !ok {
			continue
		}

		intfNum, err := GetPortSeqNum(linkName)
		if err != nil {
			log.Warnf("Finding sequence number for port failed with error: %v", err)
			continue
		}

		if _, ok := nuagevsd.intfSeqNumTable.Read(string(intfNum)); !ok {
			err = netlink.LinkDel(link)
			if err != nil {
				log.Warnf("Deleting stale interfaces on host failed with error: %v", err)
			}
		}
	}
	log.Debugf("stale host ports cleanup finished")
}

func (nuagevsd *NuageVSDClient) getInitialSequenceNumber() int {
	var maxSeqNum int
	allHostPorts, err := netlink.LinkList()
	if err != nil {
		log.Errorf("In cleanup host ports, getting list of host interfaces failed with error: %v", err)
		return 0
	}

	for _, link := range allHostPorts {
		linkName := link.Attrs().Name
		r, err := regexp.Compile(linkName)
		if err != nil {
			log.Errorf("Could not compile regex for linkname %s with err: %s", linkName, err)
		}
		if ok := r.MatchString(nuageConfig.BasePrefix); err != nil || !ok {
			continue
		}

		intfNum, err := GetPortSeqNum(linkName)
		if err != nil {
			log.Warnf("Finding sequence number for port failed with error: %v", err)
			continue
		}

		nuagevsd.intfSeqNumTable.Write(string(intfNum), true)

		if intfNum > maxSeqNum {
			maxSeqNum = intfNum
		}
	}
	return maxSeqNum
}

// GetPortSeqNum takes a uuid and finds the post fix of the interface which is the sequence number
func GetPortSeqNum(portName string) (int, error) {
	r := regexp.MustCompile(nuageConfig.BasePrefix + `(?P<seqnum>\w+)(-\d+)`)
	match := r.FindStringSubmatch(portName)
	if len(match) == 0 {
		return 0, fmt.Errorf("Couldnot find sequence number in port name %s", portName)
	}

	intfNum, err := strconv.ParseUint(match[1], 16, 64)
	if err != nil {
		log.Errorf("Converting match string to int failed with error: %v", err)
		return 0, err
	}
	return int(intfNum), nil
}

func getHostExternalID() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("Fetching hostname failed with error: %v", err)
		return "", err
	}

	cmdStr := "/usr/bin/ovsdb-client transact \"[\\\"Open_vSwitch\\\", {\\\"op\\\" : \\\"select\\\", \\\"table\\\" : \\\"Open_vSwitch\\\", \\\"where\\\" : [ ] } ]\""
	cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.Output()
	if err != nil {
		log.Errorf("\"%s\" command failed with error: %v", cmdStr, err)
		return "", err
	}

	var objmap map[string]*json.RawMessage
	err = json.Unmarshal(output[1:len(output)-2], &objmap)
	if err != nil {
		log.Errorf("Unmarshall to json raw message failed with error: %v", err)
		return "", err
	}

	var rowMap map[string]*json.RawMessage
	rowValue := []byte(*objmap["rows"])
	if len(rowValue) == 0 {
		return "", fmt.Errorf("Unable to get hypervisor id from ovsdb table")
	}

	err = json.Unmarshal(rowValue[1:len(rowValue)-1], &rowMap)
	if err != nil {
		log.Errorf("Unmarshall to json raw message failed with error: %v", err)
		return "", err
	}

	externalIDValue := string(*rowMap["external_ids"])
	if externalIDValue == "" {
		return "", fmt.Errorf("Unable to get hypervisor id from ovsdb table")
	}

	replaceChars := strings.NewReplacer("[", "", "]", "", "\"", "")
	trimmedString := replaceChars.Replace(string(externalIDValue))
	externalIDStrings := strings.Split(trimmedString, ",")
	externalID := hostname + "-" + externalIDStrings[2]
	log.Infof("ExternalID used for this host is %s ", externalID)
	return externalID, nil
}

func (nuagevsd *NuageVSDClient) makeVSDCall(vsdRequest func() *bambou.Error, msg string) {
	for i := 0; i < nuagevsd.numOfRetryAttempts; i++ {
		err := vsdRequest()
		if err != nil {
			if strings.Contains(err.Error(), "Error Code: 401") {
				nuagevsd.connectionRetry <- true
				<-nuagevsd.connectionActive
				nuagevsd.makeVSDCall(vsdRequest, msg)
				return
			}
			if strings.Contains(err.Error(), "Error Code: 500") ||
				strings.Contains(err.Error(), "Error Code: 503") {
				if i < nuagevsd.numOfRetryAttempts {
					time.Sleep(time.Millisecond * time.Duration(float64(nuagevsd.timeInterval)*math.Exp(float64(i))))
				}
			} else {
				return
			}
		} else {
			return
		}
		log.Errorf("Try = (%d). %s on vsd failed with error %v", i, msg, err)
	}
	log.Errorf("%s on vsd failed after all retries", msg)
}

//Start listens for events on VSD channel
func (nuagevsd *NuageVSDClient) Start() {
	log.Infof("starting vsd client")
	nuagevsd.intfSeqNum = nuagevsd.getInitialSequenceNumber()
	go nuagevsd.buildCache()

	for {
		select {
		case vsdEvent := <-nuagevsd.vsdChannel:
			nuagevsd.handleVSDEvent(vsdEvent)
		case <-nuagevsd.connectionRetry:
			nuagevsd.handleVSDConnection()
		case vsdReq := <-nuagevsd.infiniteUpdateRetryQueue:
			err := nuagevsd.UpdateContainerNameUUID(vsdReq)
			if err != nil {
				log.Errorf("%s", err)
			}
			time.Sleep(100 * time.Millisecond)
		case <-nuagevsd.stop:
			return
		}
	}
}

func (nuagevsd *NuageVSDClient) handleVSDEvent(event *nuageApi.VSDEvent) {
	log.Debugf("Received VSD event %+v", event)
	switch event.EventType {
	case nuageApi.VSDAddObjectsEvent:
		go func() {
			err := nuagevsd.AddVSDObjects(event.VSDReqObject.(*nuageConfig.NuageNetworkParams))
			event.VSDRespObjectChan <- &nuageApi.VSDRespObject{Error: err}
		}()

	case nuageApi.VSDDeleteObjectsEvent:
		go func() {
			err := nuagevsd.DeleteVSDObjects(event.VSDReqObject.(*nuageConfig.NuageNetworkParams))
			event.VSDRespObjectChan <- &nuageApi.VSDRespObject{Error: err}
		}()

	case nuageApi.VSDAddContainerEvent:
		ip, err := nuagevsd.CreateVSDContainer(event.VSDReqObject.(nuageConfig.NuageEventMetadata))
		event.VSDRespObjectChan <- &nuageApi.VSDRespObject{VSDData: ip, Error: err}

	case nuageApi.VSDDeleteContainerEvent:
		err := nuagevsd.DeleteVSDContainer(event.VSDReqObject.(nuageConfig.NuageEventMetadata))
		event.VSDRespObjectChan <- &nuageApi.VSDRespObject{Error: err}

	case nuageApi.VSDUpdateContainerEvent:
		go func() {
			err := nuagevsd.updateContainer(event.VSDReqObject.(nuageConfig.NuageEventMetadata))
			event.VSDRespObjectChan <- &nuageApi.VSDRespObject{Error: err}
		}()

	case nuageApi.VSDGetContainerInfoEvent:
		go func() {
			mac, err := nuagevsd.GetContainerInfo(event.VSDReqObject.(nuageConfig.NuageEventMetadata))
			event.VSDRespObjectChan <- &nuageApi.VSDRespObject{VSDData: mac, Error: err}
		}()

	case nuageApi.VSDAuditEvent:
		go func() {
			nuagevsd.auditVSD()
			event.VSDRespObjectChan <- &nuageApi.VSDRespObject{}
		}()

	default:
		log.Errorf("NuageVSDClient: Unknown api invocation")
	}
	log.Debugf("Served VSD event %+v", event)
}

func (nuagevsd *NuageVSDClient) handleVSDConnection() {
	for {
		fetchingInfo := &bambou.FetchingInfo{Filter: "name == \"" + nuagevsd.username + "\""}
		if _, err := nuagevsd.vsdUser.Users(fetchingInfo); err != nil {
			err1 := nuagevsd.RefreshVSDSession()
			if err1 != nil {
				log.Errorf("Refreshing VSD session failed with error: %v", err1)
			}
		} else {
			nuagevsd.connectionActive <- true
			return
		}
		time.Sleep(3 * time.Second)
	}
}
