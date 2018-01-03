/*
  Copyright (c) 2015, Alcatel-Lucent Inc
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
      * Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.
      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
      * Neither the name of the copyright holder nor the names of its contributors
        may be used to endorse or promote products derived from this software without
        specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package vspk

import "github.com/nuagenetworks/go-bambou/bambou"

// WirelessPortTemplateIdentity represents the Identity of the object
var WirelessPortTemplateIdentity = bambou.Identity{
	Name:     "wirelessporttemplate",
	Category: "wirelessporttemplates",
}

// WirelessPortTemplatesList represents a list of WirelessPortTemplates
type WirelessPortTemplatesList []*WirelessPortTemplate

// WirelessPortTemplatesAncestor is the interface that an ancestor of a WirelessPortTemplate must implement.
// An Ancestor is defined as an entity that has WirelessPortTemplate as a descendant.
// An Ancestor can get a list of its child WirelessPortTemplates, but not necessarily create one.
type WirelessPortTemplatesAncestor interface {
	WirelessPortTemplates(*bambou.FetchingInfo) (WirelessPortTemplatesList, *bambou.Error)
}

// WirelessPortTemplatesParent is the interface that a parent of a WirelessPortTemplate must implement.
// A Parent is defined as an entity that has WirelessPortTemplate as a child.
// A Parent is an Ancestor which can create a WirelessPortTemplate.
type WirelessPortTemplatesParent interface {
	WirelessPortTemplatesAncestor
	CreateWirelessPortTemplate(*WirelessPortTemplate) *bambou.Error
}

// WirelessPortTemplate represents the model of a wirelessporttemplate
type WirelessPortTemplate struct {
	ID                string `json:"ID,omitempty"`
	ParentID          string `json:"parentID,omitempty"`
	ParentType        string `json:"parentType,omitempty"`
	Owner             string `json:"owner,omitempty"`
	Name              string `json:"name,omitempty"`
	GenericConfig     string `json:"genericConfig,omitempty"`
	Description       string `json:"description,omitempty"`
	PhysicalName      string `json:"physicalName,omitempty"`
	WifiFrequencyBand string `json:"wifiFrequencyBand,omitempty"`
	WifiMode          string `json:"wifiMode,omitempty"`
	PortType          string `json:"portType,omitempty"`
	CountryCode       string `json:"countryCode,omitempty"`
	FrequencyChannel  string `json:"frequencyChannel,omitempty"`
}

// NewWirelessPortTemplate returns a new *WirelessPortTemplate
func NewWirelessPortTemplate() *WirelessPortTemplate {

	return &WirelessPortTemplate{
		WifiFrequencyBand: "FREQ_2_4_GHZ",
		WifiMode:          "WIFI_A_N_AC",
		PortType:          "ACCESS",
		FrequencyChannel:  "CH_0",
	}
}

// Identity returns the Identity of the object.
func (o *WirelessPortTemplate) Identity() bambou.Identity {

	return WirelessPortTemplateIdentity
}

// Identifier returns the value of the object's unique identifier.
func (o *WirelessPortTemplate) Identifier() string {

	return o.ID
}

// SetIdentifier sets the value of the object's unique identifier.
func (o *WirelessPortTemplate) SetIdentifier(ID string) {

	o.ID = ID
}

// Fetch retrieves the WirelessPortTemplate from the server
func (o *WirelessPortTemplate) Fetch() *bambou.Error {

	return bambou.CurrentSession().FetchEntity(o)
}

// Save saves the WirelessPortTemplate into the server
func (o *WirelessPortTemplate) Save() *bambou.Error {

	return bambou.CurrentSession().SaveEntity(o)
}

// Delete deletes the WirelessPortTemplate from the server
func (o *WirelessPortTemplate) Delete() *bambou.Error {

	return bambou.CurrentSession().DeleteEntity(o)
}
