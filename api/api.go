/*
###########################################################################
#
#   Filename:           api.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork event API
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package api

import (
	"fmt"
	"time"
)

//VRSEventType defines VRS events
type VRSEventType string

//VRS event definitions
const (
	VRSAddEvent               VRSEventType = "ADD"
	VRSUpdateEvent            VRSEventType = "UPDATE"
	VRSDeleteEvent            VRSEventType = "DELETE"
	VRSAuditEvent             VRSEventType = "AUDIT"
	VRSPoolIDNetworkOptsEvent VRSEventType = "NETWORKOPTS"
)

//VSDEventType defines VSD events
type VSDEventType string

//VSD Event definitions
const (
	VSDAddObjectsEvent       VSDEventType = "ADDVSDOBJECTS"
	VSDDeleteObjectsEvent    VSDEventType = "DELVSDOBJECTS"
	VSDAddContainerEvent     VSDEventType = "ADDCONTAINER"
	VSDUpdateContainerEvent  VSDEventType = "UPDATECONTAINER"
	VSDDeleteContainerEvent  VSDEventType = "DELETECONTAINER"
	VSDUpdateVportEvent      VSDEventType = "UPDATEVPORT"
	VSDAuditContainersEvent  VSDEventType = "AUDITVSDCONTAINERS"
	VSDGetContainerInfoEvent VSDEventType = "GETCONTAINERMAC"
	VSDAuditEvent            VSDEventType = "AUDIT"
)

//DockerEventType defines DockerEvents
type DockerEventType string

//Docker Event definitions
const (
	DockerContainerListEvent      DockerEventType = "CONTAINERLIST"
	DockerCheckNetworkListEvent   DockerEventType = "NETWORKLIST"
	DockerGetOptsAllNetworksEvent DockerEventType = "CONTAINERINSPECT"
	DockerNetworkIDInspectEvent   DockerEventType = "NETWORKINSPECT"
	DockerNetworkConnectEvent     DockerEventType = "NETWORKCONNECT"
	DockerPoolIDNetworkOptsEvent  DockerEventType = "NETWORKOPTS"
)

//VRSRespObject is a response object from VRS event
type VRSRespObject struct {
	VRSData interface{}
	Error   error
}

//VSDRespObject is a response object from VSD event
type VSDRespObject struct {
	VSDData interface{}
	Error   error
}

//DockerRespObject is a response object from docker event
type DockerRespObject struct {
	DockerData interface{}
	Error      error
}

//VRSEvent struct contains data and response to communicate to VRS client
type VRSEvent struct {
	EventType         VRSEventType
	VRSReqObject      interface{}
	VRSRespObjectChan chan *VRSRespObject
}

//VSDEvent struct contains data and response to communicate to VSD client
type VSDEvent struct {
	EventType         VSDEventType
	VSDReqObject      interface{}
	VSDRespObjectChan chan *VSDRespObject
}

//DockerEvent struct contains data and response to communicate to Docker client
type DockerEvent struct {
	EventType            DockerEventType
	DockerReqObject      interface{}
	DockerRespObjectChan chan *DockerRespObject
}

//NuageLibNetworkChannels struct contains the channels used for communication
type NuageLibNetworkChannels struct {
	Stop          chan bool
	VRSChannel    chan *VRSEvent
	VSDChannel    chan *VSDEvent
	DockerChannel chan *DockerEvent
}

//VSDChanRequest make a request on VSD Channel
func VSDChanRequest(receiver chan *VSDEvent, event VSDEventType, params interface{}) *VSDRespObject {
	ticker := time.NewTicker(time.Duration(300 * time.Second))
	vsdReq := &VSDEvent{
		EventType:    event,
		VSDReqObject: params,
	}
	vsdReq.VSDRespObjectChan = make(chan *VSDRespObject)
	receiver <- vsdReq
	select {
	case vsdResp := <-vsdReq.VSDRespObjectChan:
		return vsdResp
	case <-ticker.C:
		vsdResp := &VSDRespObject{}
		vsdResp.Error = fmt.Errorf("Timeout Exceeded. Request(%+v) failed.", vsdReq)
		return vsdResp
	}
	return nil
}

//VRSChanRequest make a request on VRS Channel
func VRSChanRequest(receiver chan *VRSEvent, event VRSEventType, params interface{}) *VRSRespObject {
	ticker := time.NewTicker(time.Duration(300 * time.Second))
	vrsReq := &VRSEvent{
		EventType:    event,
		VRSReqObject: params,
	}
	vrsReq.VRSRespObjectChan = make(chan *VRSRespObject)
	receiver <- vrsReq
	select {
	case vrsResp := <-vrsReq.VRSRespObjectChan:
		return vrsResp
	case <-ticker.C:
		vrsResp := &VRSRespObject{}
		vrsResp.Error = fmt.Errorf("Timeout Exceeded. Request(%+v) failed.", vrsReq)
		return vrsResp
	}
	return nil
}

//DockerChanRequest make a request on VRS Channel
func DockerChanRequest(receiver chan *DockerEvent, event DockerEventType, params interface{}) *DockerRespObject {
	ticker := time.NewTicker(time.Duration(300 * time.Second))
	dockerReq := &DockerEvent{
		EventType:       event,
		DockerReqObject: params,
	}
	dockerReq.DockerRespObjectChan = make(chan *DockerRespObject)
	receiver <- dockerReq
	select {
	case dockerResp := <-dockerReq.DockerRespObjectChan:
		return dockerResp
	case <-ticker.C:
		dockerResp := &DockerRespObject{}
		dockerResp.Error = fmt.Errorf("Timeout Exceeded. Request(%+v) failed.", dockerReq)
		return dockerResp
	}
	return nil
}
