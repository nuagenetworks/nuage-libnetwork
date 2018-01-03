/*
###########################################################################
#
#   Filename:           utils.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork utils functions
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package utils

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

type httpError struct {
	Error string
}

const EmptyHTTPResponse = `{}`

func HandleHTTPError(w http.ResponseWriter, msg string, err error) {
	reqErr := fmt.Sprintf("%s failed with error: %v", msg, err)
	log.Errorf("%s", reqErr)

	content, err1 := json.Marshal(httpError{Error: reqErr})
	if err1 != nil {
		log.Errorf("Error received marshaling error response: %v, original error: %s", err1, reqErr)
		return
	}

	http.Error(w, string(content), http.StatusInternalServerError)
}

//ReadRequest http request body
func ReadRequest(r *http.Request, req interface{}) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Reading data from http request body failed with error: %v", err)
		return err
	}
	err = json.Unmarshal(body, req)
	if err != nil {
		log.Errorf("Unmarshal JSON request failed with error: %v", err)
		return err
	}
	return nil
}
