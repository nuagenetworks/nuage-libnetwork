/*
###########################################################################
#
#   Filename:           utils.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork utility functions
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/random"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

//HashMap synchronized hash map
type HashMap struct {
	sync.RWMutex
	table map[string]interface{}
}

//NewHashMap creates a new hash map
func NewHashMap() *HashMap {
	h := &HashMap{}
	h.table = make(map[string]interface{})
	return h
}

//Read reads from hash map
func (h *HashMap) Read(key string) (interface{}, bool) {
	h.RLock()
	defer h.RUnlock()
	value, ok := h.table[key]
	return value, ok
}

//Write writes to hash map
func (h *HashMap) Write(key string, value interface{}) {
	h.Lock()
	defer h.Unlock()
	if value == nil {
		delete(h.table, key)
	} else {
		h.table[key] = value
	}
	return
}

//GetKeys given keys in a map
func (h *HashMap) GetKeys() []string {
	h.Lock()
	defer h.Unlock()
	keys := []string{}
	for key, _ := range h.table {
		keys = append(keys, key)
	}
	return keys
}

//IPIncrement increment the ip address
func IPIncrement(originalIP net.IP) (resultIP net.IP, err error) {
	log.Debugf("ipIncrement called")
	ip := originalIP.To4()
	if ip == nil {
		return nil, fmt.Errorf("Error Converting IP")
	}
	ip[3]++
	log.Debugf("incrementing ip done")
	return ip, nil
}

//GenerateID copied from docker. generates a unique hash string
func GenerateID(crypto bool) string {

	b := make([]byte, 32)
	r := random.Reader
	if crypto {
		r = rand.Reader
	}
	for {
		if _, err := io.ReadFull(r, b); err != nil {
			panic(err) // This shouldn't happen
		}
		id := hex.EncodeToString(b)
		if _, err := strconv.ParseInt(truncateID(id), 10, 64); err == nil {
			continue
		}
		return id
	}
}

// helper to generateID function
func truncateID(id string) string {
	shortLen := 12
	trimTo := shortLen
	if len(id) < shortLen {
		trimTo = len(id)
	}
	return id[:trimTo]
}

//DecodeBase64String decodes a given base64 string to regular string
func DecodeBase64String(str string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", fmt.Errorf("Error decoding encrypted VSD password")
	}
	return strings.Replace(string(data), "\n", "", -1), nil
}
