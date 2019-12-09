/*
###########################################################################
#
#   Filename:           audit.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork audit
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package audit

import (
	nuageApi "github.com/nuagenetworks/nuage-libnetwork/api"
	log "github.com/sirupsen/logrus"
	"time"
)

//NuageAudit contains channels for audit
type NuageAudit struct {
	stop       chan bool
	vsdChannel chan *nuageApi.VSDEvent
	vrsChannel chan *nuageApi.VRSEvent
}

//NewNuageAudit factory method for audit structure
func NewNuageAudit(channels *nuageApi.NuageLibNetworkChannels) *NuageAudit {
	audit := &NuageAudit{}
	audit.stop = channels.Stop
	audit.vsdChannel = channels.VSDChannel
	audit.vrsChannel = channels.VRSChannel
	log.Debugf("Finished initializing audit module")
	return audit
}

//Start starts the audit process
func (audit *NuageAudit) Start() {
	//run it onnce at beginning
	audit.periodicAudit()

	select {
	case <-audit.stop:
		return
	}
}

// runs audit every 12 hours
func (audit *NuageAudit) periodicAudit() {
	audit.runAudit()
	//run it for every 30 seconds from now
	time.AfterFunc(30*time.Second, audit.periodicAudit)
}

// runs audit now. Can be invoked using SIGUSR2
func (audit *NuageAudit) AuditNow() {
	log.Infof("Plugin invoked in audit mode")
	audit.runAudit()
	log.Infof("Finished doing audit")
}

func (audit *NuageAudit) runAudit() {
	//VSD Audit
	nuageApi.VSDChanRequest(audit.vsdChannel, nuageApi.VSDAuditEvent, nil)
	//VRS Audit
	nuageApi.VRSChanRequest(audit.vrsChannel, nuageApi.VRSAuditEvent, nil)
}
