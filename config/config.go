/*
###########################################################################
#
#   Filename:           config.go
#
#   Author:             Siva Teja Areti
#   Created:            June 6, 2017
#
#   Description:        libnetwork plugin config
#
###########################################################################
#
#              Copyright (c) 2017 Nuage Networks
#
###########################################################################
*/

package config

import (
	"crypto/md5"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

//Config data used across packages
const (
	LOGDIR               = "/var/log/libnetwork-nuage"
	LOGFILE              = "/var/log/libnetwork-nuage/libnetwork-nuage.log"
	PluginDir            = "/run/docker/plugins"
	PluginName           = "nuage"
	ContainerIfacePrefix = "eth"
	BasePrefix           = "nln"
	EntityPortKey        = "entityport"
	BridgePortKey        = "brPort"
	UUIDKey              = "vmuuid"
	MACKey               = "mac"
	NameKey              = "name"
	PolicyGroupKey       = "policy-group"
	StaticIPKey          = "static-ip"
	MaxIntfNum           = 4000000
	InvalidPortName      = -1
	BridgeName           = "alubr0"
	VSDContainerIDKey    = "cont-uuid"
	UserKey              = "NUAGE-USER"
	EnterpriseKey        = "NUAGE-ENTERPRISE"
	DomainKey            = "NUAGE-DOMAIN"
	ZoneKey              = "NUAGE-ZONE"
	NetworkKey           = "NUAGE-NETWORK"
	NetworkTypeKey       = "NUAGE-NETWORK-TYPE"
)

var DockerNetworkType = map[string]string{"v1": "nuage", "v2": "nuage:latest"}

var logMessageCounter int

type logTextFormatter log.TextFormatter

//NuageNetworkParams nuage network metadata
type NuageNetworkParams struct {
	Organization string
	Domain       string
	Zone         string
	User         string
	SubnetName   string
	SubnetCIDR   string
	Gateway      string
}

//NuageEventMetadata struct contains the metadata required to communicate across channels
type NuageEventMetadata struct {
	IPAddress       string
	UUID            string
	Name            string
	PolicyGroup     string
	OrchestrationID string
	NetworkParams   *NuageNetworkParams
}

//NuageLibNetworkConfig configuration data for nuage libnetwork remote and ipam drivers
type NuageLibNetworkConfig struct {
	NumOfRetries     int
	TimeInterval     int
	LogFileSize      int
	URL              string
	Port             string
	Username         string
	Password         string
	Organization     string
	Scope            string
	LogLevel         string
	VRSBridge        string
	VRSSocketFile    string
	DockerSocketFile string
	PluginVersion    string
}

//ReadConfigFile reads, validates and sets defaults to config file
func ReadConfigFile(configFile string) (*NuageLibNetworkConfig, error) {
	nuageConfigParams, err := loadConfig(configFile)
	if err != nil {
		log.Errorf("Load config failed with error: %v", err)
		return nil, err
	}
	err = validateConfig(nuageConfigParams)
	if err != nil {
		log.Errorf("Validating nuage config failed with error: %v", err)
		return nil, err
	}
	return nuageConfigParams, nil
}

func loadConfig(configFile string) (*NuageLibNetworkConfig, error) {
	conf := &NuageLibNetworkConfig{}
	if configFile != "" {
		configData, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.Errorf("Reading config file failed with error: %v", err)
			return nil, err
		}
		err = parse(configData, conf)
		if err != nil {
			log.Errorf("Parsing config file failed with error: %v", err)
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("No configuration file specified")
	}
	setDefaultsInConfig(conf)
	return conf, nil
}

func validateConfig(conf *NuageLibNetworkConfig) error {
	if conf.URL == "" {
		return fmt.Errorf("Empty URL found in config file")
	}
	if conf.Username == "" {
		return fmt.Errorf("Empty username found in config file")
	}
	if conf.Password == "" {
		return fmt.Errorf("Empty password found in config file")
	}
	if conf.Organization == "" {
		return fmt.Errorf("Empty organization found in config file")
	}
	return nil
}

func setDefaultsInConfig(conf *NuageLibNetworkConfig) {
	if conf.DockerSocketFile == "" {
		log.Warnf("empty docker endpoint. using default value")
		conf.DockerSocketFile = "unix:///var/run/docker.sock"
	}
	if conf.VRSSocketFile == "" {
		log.Warnf("empty vrs endpoint. using default value")
		conf.VRSSocketFile = "/var/run/openvswitch/db.sock"
	}
	if conf.VRSBridge == "" {
		log.Warnf("empty vrs bridge. using default value \"alubr0\"")
		conf.VRSBridge = "alubr0"
	}
	if conf.LogLevel == "" || (conf.LogLevel != "Debug" && conf.LogLevel != "Info" && conf.LogLevel != "Warn" && conf.LogLevel != "Error") {
		log.Warnf("invalid log debug level \"%s\". using default value \"Info\"", conf.LogLevel)
		conf.LogLevel = "Warn"
	}
	if conf.Scope == "" || (conf.Scope != "local" && conf.Scope != "global") {
		log.Warnf("invalid scope value %s found. using default value \"global\"", conf.Scope)
		conf.Scope = "global"
	}
	if conf.NumOfRetries == 0 {
		log.Warnf("Invalid retry count %d specified. Using default value 5", conf.NumOfRetries)
		conf.NumOfRetries = 5
	}
	if conf.TimeInterval == 0 {
		log.Warnf("Invalid time interval %d specified. Using default value 100ms", conf.TimeInterval)
		conf.TimeInterval = 100
	}
	if conf.LogFileSize == 0 {
		log.Warnf("Invalid log file size %d specified. Using default value 10MB", conf.LogFileSize)
		conf.LogFileSize = 10
	}
	if conf.PluginVersion == "" {
		log.Warnf("Plugin version to be run not found in config file")
		conf.PluginVersion = "v1"
	}
}

func parse(data []byte, conf *NuageLibNetworkConfig) error {
	err := yaml.Unmarshal(data, conf)
	if err != nil {
		log.Errorf("YAML unmarshal failed with error: %v", err)
		return err
	}
	log.Warnf("Parsed configuration %+v successfully", conf)
	return nil
}

//SetupLogging sets up logging infrastructure
func SetupLogging() {
	customFormatter := new(logTextFormatter)
	log.SetFormatter(customFormatter)
	log.SetOutput(&lumberjack.Logger{
		Filename: LOGFILE,
		MaxSize:  1,
		MaxAge:   30,
	})
	log.SetLevel(log.DebugLevel)
}

//SetLogLevel sets the default log level
func SetLogLevel(conf *NuageLibNetworkConfig) {
	var supportedLogLevels = map[string]log.Level{
		"debug": log.DebugLevel,
		"info":  log.InfoLevel,
		"warn":  log.WarnLevel,
		"error": log.ErrorLevel,
	}
	log.SetOutput(&lumberjack.Logger{
		Filename: LOGFILE,
		MaxSize:  conf.LogFileSize,
		MaxAge:   30,
	})
	log.SetLevel(supportedLogLevels[strings.ToLower(conf.LogLevel)])
}

func createFile(dir, file string) (*os.File, error) {
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, err
	}
	handle, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

//Format custom format method used by logrus. Prints in standard nuage log format
func (f *logTextFormatter) Format(entry *log.Entry) ([]byte, error) {
	logMessageCounter++
	outputString := fmt.Sprintf("|%v|%s|%04d|%s|%s\n", entry.Time, strings.ToUpper(log.Level.String(entry.Level)), logMessageCounter, path.Base(os.Args[0]), entry.Message)
	for k, v := range entry.Data {
		outputString += fmt.Sprintf("|%s=%s|", k, v)
	}
	return []byte(outputString), nil
}

//ParseNuageParams Parses all the nuage options passed
func ParseNuageParams(networkOptions map[string]string) *NuageNetworkParams {
	nuageParams := &NuageNetworkParams{}
	for key, val := range networkOptions {
		switch key {
		case "organization":
			nuageParams.Organization = val
		case "domain":
			nuageParams.Domain = val
		case "zone":
			nuageParams.Zone = val
		case "subnet":
			nuageParams.SubnetName = val
		case "user":
			nuageParams.User = val
		default:
			log.Warnf("Unknown key[%s] value[%s] found in network options. Ignoring them", key, val)
		}
	}
	log.Debugf("%+v", nuageParams)
	return nuageParams
}

//ValidateNuageParams validates the nuage parameters
func ValidateNuageParams(nuageParams *NuageNetworkParams) error {
	if nuageParams.Organization == "" || nuageParams.User == "" {
		return fmt.Errorf("Organization or User required to create a NuageNet")
	}

	if nuageParams.Domain == "" {
		return fmt.Errorf("Domain Required to create a NuageNet")
	}

	if nuageParams.Zone == "" || nuageParams.SubnetName == "" {
		return fmt.Errorf("If L3Domain, both Zone and Subnets are required")
	}
	log.Debugf("Validating nuage params is successful")
	return nil
}

//IsSameNetworkOpts checks if nuage network options matches
func IsSameNetworkOpts(opts1, opts2 *NuageNetworkParams) bool {
	if opts1.Organization != opts2.Organization {
		return false
	}
	if opts1.Domain != opts2.Domain {
		return false
	}
	if opts1.Zone != opts2.Zone {
		return false
	}
	if opts1.SubnetName != opts2.SubnetName {
		return false
	}
	return true
}

//MD5Hash generates md5 hash string for given network options
func MD5Hash(networkOpts *NuageNetworkParams) string {
	str := networkOpts.Organization + networkOpts.Domain +
		networkOpts.SubnetName + networkOpts.SubnetCIDR
	return fmt.Sprintf("%x", md5.Sum([]byte(str)))
}

//String stringifies NuageNetworkParams
func (v NuageNetworkParams) String() string {
	return fmt.Sprintf("%s-%s-%s", v.Organization, v.Domain, v.SubnetName)
}
