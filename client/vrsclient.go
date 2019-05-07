/*
###########################################################################
#
#   Filename:           vrsclient.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork VRS client API
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package client

import (
	"bufio"
	"bytes"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	vrsSDK "github.com/nuagenetworks/libvrsdk/api"
	"github.com/nuagenetworks/libvrsdk/api/entity"
	"github.com/nuagenetworks/libvrsdk/api/port"
	nuageApi "github.com/nuagenetworks/nuage-libnetwork/api"
	nuageConfig "github.com/nuagenetworks/nuage-libnetwork/config"
	"github.com/nuagenetworks/nuage-libnetwork/utils"
	"github.com/vishvananda/netlink"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

//NuageVRSClient contains the relavent data to hold VRS client
type NuageVRSClient struct {
	bridgeName         string
	vrsSocketFile      string
	connectionRetry    chan bool
	connectionActive   chan bool
	stop               chan bool
	vrsChannel         chan *nuageApi.VRSEvent
	dockerChannel      chan *nuageApi.DockerEvent
	vrsConnection      vrsSDK.VRSConnection
	networkParamsTable *utils.HashMap
}

//NewNuageVRSClient factory method of NuageVRSClient structure
func NewNuageVRSClient(config *nuageConfig.NuageLibNetworkConfig, channels *nuageApi.NuageLibNetworkChannels) (*NuageVRSClient, error) {
	var err error
	nvrsc := &NuageVRSClient{}
	nvrsc.bridgeName = config.VRSBridge
	nvrsc.vrsSocketFile = config.VRSSocketFile
	nvrsc.stop = channels.Stop
	nvrsc.vrsChannel = channels.VRSChannel
	nvrsc.dockerChannel = channels.DockerChannel
	nvrsc.connectionRetry = make(chan bool)
	nvrsc.connectionActive = make(chan bool)
	nvrsc.networkParamsTable = utils.NewHashMap()
	nvrsc.vrsConnection, err = connectToVRS(nvrsc.vrsSocketFile)
	if err != nil {
		log.Errorf("Connection to VRS failed with error: %v", err)
		return nil, err
	}
	log.Debugf("Finished initializing VRS modules")
	return nvrsc, nil
}

//CreatePortEntry creates a new entry in Nuage_Port_Table
func (nvrsc *NuageVRSClient) CreatePortEntry(containerInfo map[string]string) error {
	log.Debugf("Creating port entry in VRS")
	var err error

	portAttributes := port.Attributes{
		Platform: entity.Docker,
		MAC:      containerInfo[nuageConfig.MACKey],
		Bridge:   nvrsc.bridgeName,
	}

	portMetadata := make(map[port.MetadataKey]string)
	portMetadata[port.MetadataKeyDomain] = ""
	portMetadata[port.MetadataKeyNetwork] = ""
	portMetadata[port.MetadataKeyZone] = ""
	portMetadata[port.MetadataKeyNetworkType] = ""

	nvrsc.makeVRSSDKCall(
		func() error {
			err = nvrsc.vrsConnection.CreatePort(containerInfo[nuageConfig.BridgePortKey], portAttributes, portMetadata)
			return err
		})
	if err != nil {
		log.Errorf("Creating entity port failed with error: %v", err)
		return err
	}

	log.Debugf("Finished creating port entry in VRS")
	return nil
}

//CreateEntityEntry creates a new entry in Nuage_VM_Table
func (nvrsc *NuageVRSClient) CreateEntityEntry(containerInfo map[string]string) error {
	log.Debugf("Creating entity entry in VRS")
	containerMetadata := make(map[entity.MetadataKey]string)
	containerMetadata["nuage-extension"] = "true"
	containerMetadata[entity.MetadataKeyUser] = ""
	containerMetadata[entity.MetadataKeyEnterprise] = ""
	ports := []string{containerInfo[nuageConfig.BridgePortKey]}

	entityInfo := vrsSDK.EntityInfo{
		UUID:     containerInfo[nuageConfig.UUIDKey],
		Name:     containerInfo[nuageConfig.NameKey],
		Domain:   entity.Docker,
		Type:     entity.Container,
		Ports:    ports,
		Metadata: containerMetadata,
	}
	var err error

	nvrsc.makeVRSSDKCall(
		func() error {
			err = nvrsc.vrsConnection.CreateEntity(entityInfo)
			return err
		})
	if err != nil {
		log.Errorf("Creating new entity %s failed with error: %v", containerInfo[nuageConfig.UUIDKey], err)
		return err
	}

	log.Debugf("Finished creating entity entry in VRS")
	return nil
}

//DeletePortEntry deletes an entry from Nuage_Port_Table
func (nvrsc *NuageVRSClient) DeletePortEntry(containerInfo map[string]string) error {
	var err error
	nvrsc.makeVRSSDKCall(
		func() error {
			err = nvrsc.vrsConnection.DestroyPort(containerInfo[nuageConfig.BridgePortKey])
			return err
		})
	if err != nil {
		log.Errorf("Unable to delete port %s from Nuage Port table: %v", containerInfo[nuageConfig.BridgePortKey], err)
		return err
	}

	log.Debugf("port %v is removed from port table", containerInfo[nuageConfig.BridgePortKey])
	return nil
}

//DeleteEntityEntry deletes an entry from Nuage_VM_Table
func (nvrsc *NuageVRSClient) DeleteEntityEntry(containerInfo map[string]string) error {
	log.Debugf("removing entity %s", containerInfo[nuageConfig.UUIDKey])
	var err error
	nvrsc.makeVRSSDKCall(
		func() error {
			err = nvrsc.vrsConnection.DestroyEntity(containerInfo[nuageConfig.UUIDKey])
			return err
		})
	if err != nil {
		log.Errorf("Unable to delete entity %s from nuage VM table: %v", containerInfo[nuageConfig.UUIDKey], err)
		return err
	}
	log.Debugf("entity %v is removed from entity table", containerInfo[nuageConfig.UUIDKey])
	return nil
}

//AddPortToBridge adds entity port to the bridge
func (nvrsc *NuageVRSClient) AddPortToBridge(containerInfo map[string]string) error {
	var err error
	var output []byte
	log.Debugf("Adding port %s to %s bridge", containerInfo[nuageConfig.BridgePortKey], nvrsc.bridgeName)
	port := containerInfo[nuageConfig.BridgePortKey]
	nvrsc.makeVRSCall(
		func() ([]byte, error) {
			externalIDStr := fmt.Sprintf("%s=%s,", nuageConfig.EnterpriseKey, strings.Replace(containerInfo[nuageConfig.EnterpriseKey], " ", "\\ ", -1))
			externalIDStr += fmt.Sprintf("%s=%s,", nuageConfig.DomainKey, strings.Replace(containerInfo[nuageConfig.DomainKey], " ", "\\ ", -1))
			externalIDStr += fmt.Sprintf("%s=%s", nuageConfig.NetworkKey, strings.Replace(containerInfo[nuageConfig.NetworkKey], " ", "\\ ", -1))
			cmdstr := fmt.Sprintf("/usr/bin/ovs-vsctl --no-wait --if-exists del-port %s %s -- add-port %s %s -- set interface %s 'external-ids={vm_uuid=%s,vm_name=%s,%s}'", nvrsc.bridgeName, port, nvrsc.bridgeName, port, port, containerInfo[nuageConfig.UUIDKey], containerInfo[nuageConfig.NameKey], externalIDStr)
			log.Debugf("%s", cmdstr)
			output, err = exec.Command("bash", "-c", cmdstr).CombinedOutput()
			return output, err
		})
	if err != nil {
		return fmt.Errorf("Problem adding veth port to alubr0 on VRS output = %s, err = %v", output, err)
	}

	params := &nuageConfig.NuageNetworkParams{
		Organization: containerInfo[nuageConfig.EnterpriseKey],
		Domain:       containerInfo[nuageConfig.DomainKey],
		SubnetName:   containerInfo[nuageConfig.NetworkKey],
	}
	nvrsc.networkParamsTable.Write(nuageConfig.MD5Hash(params), params)
	return nil
}

func (nvrsc *NuageVRSClient) GetNetworkOptsFromPoolID(poolID string) (*nuageConfig.NuageNetworkParams, error) {
	if params, ok := nvrsc.networkParamsTable.Read(poolID); ok {
		log.Debugf("network params %v for pool id %s", params.(*nuageConfig.NuageNetworkParams), poolID)
		return params.(*nuageConfig.NuageNetworkParams), nil
	} else {
		log.Debugf("network params not found for pool id %s", poolID)
		return nil, fmt.Errorf("did not find network params for the given pool id")
	}
}

func (nvrsc *NuageVRSClient) buildCache() {
	var err error
	var output []byte
	log.Debugf("Building cache from OVSDB")
	nvrsc.makeVRSCall(
		func() ([]byte, error) {
			cmdStr := "/usr/bin/ovs-vsctl --columns=external-ids list Interface"
			output, err = exec.Command("bash", "-c", cmdStr).CombinedOutput()
			return output, err
		})
	if err != nil {
		log.Fatalf("Building cache from OVSDB failed with error: %v", err)
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) == 0 {
			continue
		}
		re := regexp.MustCompile("{(.*)}")
		matches := re.FindStringSubmatch(text)
		replacer := strings.NewReplacer("\"", "")
		var org, domain, subnetName string
		for _, str := range strings.Split(matches[1], ",") {
			kv := strings.Split(strings.TrimSpace(str), "=")
			switch kv[0] {
			case nuageConfig.EnterpriseKey:
				org = replacer.Replace(kv[1])
			case nuageConfig.DomainKey:
				domain = replacer.Replace(kv[1])
			case nuageConfig.NetworkKey:
				subnetName = replacer.Replace(kv[1])
			}
		}
		if org == "" || domain == "" || subnetName == "" {
			log.Errorf("org/domain/subnet not found in external ids %s", text)
			continue
		}
		params := &nuageConfig.NuageNetworkParams{Organization: org, Domain: domain, SubnetName: subnetName}
		nvrsc.networkParamsTable.Write(nuageConfig.MD5Hash(params), params)
		log.Debugf("added pool id %s with params %v", nuageConfig.MD5Hash(params), params)
	}
}

func (nvrsc *NuageVRSClient) createEntries(containerInfo map[string]string) error {
	log.Debugf("Container %s: Adding port to bridge", containerInfo[nuageConfig.UUIDKey])
	err := nvrsc.AddPortToBridge(containerInfo)
	if err != nil {
		log.Errorf("Adding port %s to bridge %s failed with error: %v", containerInfo[nuageConfig.BridgePortKey], nvrsc.bridgeName, err)
		return err
	}

	err = nvrsc.CreatePortEntry(containerInfo)
	if err != nil {
		log.Errorf("Creating port entries for %+v failed with error: %v", containerInfo, err)
		return err
	}

	err = nvrsc.CreateEntityEntry(containerInfo)
	if err != nil {
		log.Errorf("Creating entityr entries for %+v failed with error: %v", containerInfo, err)
		return err
	}
	return nil
}

func (nvrsc *NuageVRSClient) updateEntries(containerInfo map[string]string) error {
	return nil
}

func (nvrsc *NuageVRSClient) deleteEntries(containerInfo map[string]string) error {
	log.Debugf("Container %s: Deleting entity from entity table", containerInfo[nuageConfig.UUIDKey])
	err := nvrsc.DeleteEntityEntry(containerInfo)
	if err != nil {
		log.Errorf("Deleting entity table entries for %+v failed with error: %v", containerInfo, err)
		return err
	}

	err = nvrsc.DeletePortEntry(containerInfo)
	if err != nil {
		log.Errorf("Deleting port table entries for %+v failed with error: %v", containerInfo, err)
		return err
	}
	err = nvrsc.RemoveVethPortFromVRS(containerInfo[nuageConfig.BridgePortKey])
	if err != nil {
		log.Errorf("Unable to delete veth port %s as part of cleanup from alubr0: %v", containerInfo[nuageConfig.BridgePortKey], err)
	}

	err = nvrsc.DeleteVethPair(containerInfo)
	if err != nil {
		log.Errorf("Unable to delete veth pairs as a part of cleanup on VRS: %v", err)
	}
	return nil
}

// RemoveVethPortFromVRS will help delete veth ports from VRS alubr0
func (nvrsc *NuageVRSClient) RemoveVethPortFromVRS(port string) error {
	log.Debugf("Removing port %s from %s bridge", port, nvrsc.bridgeName)
	var err error
	var output []byte
	nvrsc.makeVRSCall(
		func() ([]byte, error) {
			cmdstr := fmt.Sprintf("/usr/bin/ovs-vsctl --no-wait del-port %s %s", nvrsc.bridgeName, port)
			output, err = exec.Command("bash", "-c", cmdstr).CombinedOutput()
			return output, err
		})
	if err != nil {
		return fmt.Errorf("Problem deleting veth port from alubr0 on VRS %v", err)
	}

	return nil
}

//DeleteVethPair deletes a veth pair from host
func (nvrsc *NuageVRSClient) DeleteVethPair(containerInfo map[string]string) error {
	containerInfo[nuageConfig.EntityPortKey] = strings.Replace(containerInfo[nuageConfig.BridgePortKey], "-1", "-2", -1)
	localVethPair := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: containerInfo[nuageConfig.BridgePortKey]},
		PeerName:  containerInfo[nuageConfig.EntityPortKey],
	}

	err := netlink.LinkDel(localVethPair)
	if err != nil {
		log.Errorf("Deleting veth pair %+v failed with error: %s", localVethPair, err)
		return err
	}
	return nil
}

func (nvrsc *NuageVRSClient) auditOVSDB() error {
	log.Debugf("VRS Audit called")
	defer log.Debugf("VRS Audit completed")
	ovsdbLookup := make(map[string]bool)
	containerInfo := make(map[string]string)
	var allOvsdbEntities []string
	var err error
	nvrsc.makeVRSSDKCall(
		func() error {
			log.Debugf("Fetch all VRS entities")
			allOvsdbEntities, err = nvrsc.vrsConnection.GetAllEntities()
			return err
		})
	if err != nil {
		log.Errorf("Getting list of all entities from OVSDB failed with error: %v", err)
	}

	dockerResponse := nuageApi.DockerChanRequest(nvrsc.dockerChannel, nuageApi.DockerContainerListEvent, nil)
	activeContainerList := dockerResponse.DockerData.([]types.Container)

	for _, container := range activeContainerList {
		ovsdbLookup[container.ID] = true
	}

	for _, entity := range allOvsdbEntities {
		if _, ok := ovsdbLookup[entity]; !ok {
			var portNames []string
			var err error
			nvrsc.makeVRSSDKCall(
				func() error {
					log.Debugf("Fetch ports for entity %s from VRS", entity)
					portNames, err = nvrsc.vrsConnection.GetEntityPorts(entity)
					return err
				})
			if err != nil {
				log.Errorf("Finding list of ports for entity %s from OVSDB failed with error: %v", entity, err)
				continue
			}

			for _, portName := range portNames {
				if strings.HasPrefix(portName, nuageConfig.BasePrefix) { //manage ports with only libnetwork prefix
					containerInfo[nuageConfig.BridgePortKey] = portName
					containerInfo[nuageConfig.UUIDKey] = entity
					err := nvrsc.deleteEntries(containerInfo)
					if err != nil {
						log.Errorf("Deleting entries in audit failed with error %v", err)
					}
				}
			}
		}
	}
	return nil
}

//Start listens for events on VRS Channel
func (nvrsc *NuageVRSClient) Start() {
	log.Infof("starting vrs client")
	nvrsc.buildCache()
	for {
		select {
		case vrsEvent := <-nvrsc.vrsChannel:
			go nvrsc.handleVRSEvent(vrsEvent)
		case <-nvrsc.connectionRetry:
			nvrsc.handleVRSConnectionEvent()
		case <-nvrsc.stop:
			log.Infof("Stopped Nuage VRS Client")
			return
		}
	}
}

func (nvrsc *NuageVRSClient) handleVRSEvent(event *nuageApi.VRSEvent) {
	var data interface{}
	var err error
	log.Debugf("Received VRS event %+v", event)
	switch event.EventType {
	case nuageApi.VRSAddEvent:
		err = nvrsc.createEntries(event.VRSReqObject.(map[string]string))
	case nuageApi.VRSUpdateEvent:
		err = nvrsc.updateEntries(event.VRSReqObject.(map[string]string))
	case nuageApi.VRSDeleteEvent:
		err = nvrsc.deleteEntries(event.VRSReqObject.(map[string]string))
	case nuageApi.VRSAuditEvent:
		err = nvrsc.auditOVSDB()
	case nuageApi.VRSPoolIDNetworkOptsEvent:
		data, err = nvrsc.GetNetworkOptsFromPoolID(event.VRSReqObject.(string))
	default:
		log.Errorf("unknown api invocation")
	}
	event.VRSRespObjectChan <- &nuageApi.VRSRespObject{VRSData: data, Error: err}
	log.Debugf("Served VRS event %+v", event)
}

func (nvrsc *NuageVRSClient) handleVRSConnectionEvent() {
	if _, err := nvrsc.vrsConnection.GetAllPorts(); err != nil {
		log.Errorf("Ping to VRS failed with failed error = %v. trying to reconnect", err)
		log.Errorf("will try to reconnect in every 3 seconds")
		var err error
		for {
			nvrsc.vrsConnection, err = vrsSDK.NewUnixSocketConnection(nvrsc.vrsSocketFile)
			if err != nil {
				time.Sleep(3 * time.Second)
			} else {
				log.Infof("vrs connection is now active")
				nvrsc.connectionActive <- true
				break
			}
		}
	} else {
		nvrsc.connectionActive <- true
	}
}

func (nvrsc *NuageVRSClient) makeVRSCall(vrsMethod func() ([]byte, error)) {
	output, err := vrsMethod()
	if err != nil && (isVRSConnectionError(string(output)) || isVRSConnectionError(err.Error())) {
		log.Errorf("output = %s error = %s", string(output), err.Error())
		nvrsc.connectionRetry <- true
		<-nvrsc.connectionActive
		nvrsc.makeVRSCall(vrsMethod)
	}
	return
}

func (nvrsc *NuageVRSClient) makeVRSSDKCall(vrsMethod func() error) {
	err := vrsMethod()
	if err != nil && isVRSConnectionError(err.Error()) {
		log.Errorf(err.Error())
		nvrsc.connectionRetry <- true
		<-nvrsc.connectionActive
		nvrsc.makeVRSSDKCall(vrsMethod)
	}
	return
}

func connectToVRS(socketFile string) (vrsSDK.VRSConnection, error) {
	vrsConnection, err := vrsSDK.NewUnixSocketConnection(socketFile)
	if err != nil {
		log.Errorf("Connection to VRS failed with error: %v", err)
		return vrsSDK.VRSConnection{}, err
	}
	return vrsConnection, nil
}

func isVRSConnectionError(errMsg string) bool {
	connectionErrMsgList := []string{"database connection failed", "connection is shut down"}
	for _, connectionErrMsg := range connectionErrMsgList {
		ok, err := regexp.MatchString(connectionErrMsg, errMsg)
		if err != nil {
			log.Errorf("matching strings failed with error %v", err)
		}
		if ok {
			return ok
		}
	}
	return false
}
