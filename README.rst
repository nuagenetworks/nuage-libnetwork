.. _docker-20-libnetwork-integration:

.. include:: ../lib/doc-includes/VSDA-icons.inc


====================================
Docker Libnetwork Integration
====================================

.. contents::
   :local:
   :depth: 3


..
.. Date, Version, Author, and Reviewers
.. =====================================
..
.. ========= ======= =======  ==========
.. Date      Version Author   Reviewers
.. ========= ======= =======  ==========
.. 
.. 11/21/16  4.0.R6  Madhu      Siva, Harmeet, Aniket Bhatt PROD-763
.. 01/10/17  4.0.R7  Madhu      PROD-763 Siva PRs, Harmeet PRs

.. ========= ======= =============================


Libnetwork Plugin
========================

Nuage VSP Release 4.0.R6 and later supports Docker with libnetwork. 

Overview
--------

The Nuage libnetwork plugin allows the user to create new networks of type Nuage. The new networks of type Nuage in Docker are implemented in the backend by a specific subnet in VSP. A specific Docker network needs to reference a specific subnet from VSP. This is done by giving extra parameters to Docker at network creation time. The user interacts with Docker network, which calls libnetwork. The Nuage implemented plugin serves the request coming from the libnetwork backend. 

The libnetwork plugin supports both local and global scope networks. The scope defines if your network is going to propagate to all the nodes as part of your cluster. The simplest use case is for single host networking. This translates to networks that are only visible on the host on which the network is added. This use case is configured with the configuration Scope="local". Multihost networking uses a backend store in order to propagate network information to all the cluster participants. As such, a network added on one node is available on all the nodes. This use case is configured with the configuration Scope="global".

Starting from VSP 4.0.R6.1, libnetwork plugin supports built in IPAM driver where the IP address management is done by VSP.

Nuage libnetwork plugin is qualified with Docker Version 1.12.1 and API Version 1.24.

Installing Libnetwork
-----------------------

:Step 1:  Start the Docker daemon. If the plugin is to be run in "local" scope, then Docker daemon can be started on each host without any extra options. In order to run the plugin with "global" scope, docker-engines on multiple servers need to be started with a backend-store. Following commands show the commands to start Docker daemon with consul.

    ::
    
       [root@server1:~]# docker daemon --cluster-store=consul://$CONSULSERVER:8500 --cluster-advertise=$server1:2376
       [root@server2:~]# docker daemon --cluster-store=consul://$CONSULSERVER:8500 --cluster-advertise=$server2:2376


:Step 2:  Install the Nuage libnetwork rpm using the following command. This installs libnetwork-nuage binary and the required configuration file templates.

    ::
    
       [root@server1:~]# yum localinstall -y libnetwork-nuage-0-0-1.x86_64.rpm
       
    Once the rpm is installed, you can verify that the Nuage IPAM and plugin are running in the background using following command.
    
    ::
    
       [root@server1:~]# systemctl status libnetwork-nuage
         libnetwork-nuage.service - Nuage libnetwork plugin for docker
         Loaded: loaded (/etc/systemd/system/libnetwork-nuage.service; enabled; vendor preset: disabled)
         Active: active (running) since Tue 2017-01-10 17:55:16 UTC; 3h 22min ago
         Main PID: 1516 (libnetwork-nuag)
         CGroup: /system.slice/libnetwork-nuage.service
             1516 /usr/bin/libnetwork-nuage -config /etc/default/libnetwork-nuage.yaml


:Step 3: Configure the plugin parameters inside the YAML configuration file. "loglevel" can be "Info", "Debug", "Warn" or "Error" and "logfilesize" is an integer representing the upper limit on the size(in MB) of log file before it gets rotated. "scope" can be "local" or "global". 'username', 'password' and 'organization' must be base64 encoded values of their string values. Values shown below are default values that are used if there are no specified values. Place the YAML configuration file under ``/etc/default/libnetwork-nuage.yaml`` on each host where Nuage plugin is run. A sample YAML configuration file for plugin input parameters looks like the following:

    ::
    
      [root@server1 ~]# cat /etc/default/libnetwork-nuage.yaml 
         vrsendpoint:    "/var/run/openvswitch/db.sock"
         dockerdndpoint: "unix:///var/run/docker.sock"
         vrsbridge:      "alubr0"
         loglevel:       "Warn"
         logfilesize:    10
         scope:          "global"
         numofretries:   5
         timeinterval:   100
         username: Y3Nwcm9vdA==
         password: Y3Nwcm9vdA==
         organization: Y3Nw
         url: https://127.0.0.1:8443


:Step 4: Start the plugin on each host on which it has to run using the following command.

    ::
    
       systemctl start libnetwork-nuage
         


:Important Things to Remember:

* Plugin needs a restart whenever docker daemon is restarted
* Plugin needs a restart whenever VRS services are restarted
* Plugin needs a restart whenever the input configuration changes


Configuring Single Host Networking
-------------------------------------

After starting the Nuage plugin in "local" scope, Docker API is used to create a network:

::

   root@ubuntu:~# docker network create --driver=nuage --ipam-driver=nuage-ipam --ipam-opt organization=Enterprise --ipam-opt domain=Domain --ipam-opt zone=Zone --ipam-opt subnet="Subnet 2" --ipam-opt user=admin --subnet=10.21.59.0/24  --gateway=10.21.59.1 MyNet

to link to a L3Domain in Nuage, the following parameters are required: enterprise, user, domain, zone, subnet. Furthermore, the CIDR and IPAM information must be exactly the same as in Nuage.

Once the network is created, it can be seen and inspected:

::

   root@ubuntu:~# docker network ls
   NETWORK ID          NAME                DRIVER
   e793da0854ce        MyNet               nuage               
   4d7098beb610        bridge              bridge              
   cf0626f73c7c        docker_gwbridge     bridge              
   b8878a9f9d58        host                host                
   967ad3ccb5af        none                null  

::

   root@ubuntu:~# docker network inspect MyNet
   [
      {
           "Name": "MyNet",
            "Id": "8f8127c363669e8b2c07c5025386a574cbab23a194267bdc6b8d5e54658a8985",
            "Scope": "global",
            "Driver": "nuage",
           "EnableIPv6": false,
           "IPAM": {
               "Driver": "nuage-ipam",
               "Options": {
                  "domain": "Domain",
                  "organization": "Enterprise",
                  "subnet": "Subnet 2",
                  "user": "admin",
                  "zone": "Zone"
               },
               "Config": [
                   {
                       "Subnet": "10.21.59.0/24"
                       "Gateway": "10.21.59.1"
                   }
               ]
           },
           "Internal": false,
           "Containers": {
               "524fbb401c8c6f760e1e66f8be42f603e258c5c7a3807a7f66afa0a1b760295f": {
                   "Name": "tender_goldstine",
                   "EndpointID": "2b4fb640e6299ae5e00f7cbebebbef112490813cb57cd05a2e9fde5316208076",
                   "MacAddress": "7a:42:d6:aa:d0:11",
                   "IPv4Address": "10.21.59.2/24",
                   "IPv6Address": ""
               },
               "ep-20b306d0998b227289a86ee4b6a69b4171d3dca666b1fe78cdcf5df4c1f86b89": {
                   "Name": "thirsty_bassi",
                   "EndpointID": "20b306d0998b227289a86ee4b6a69b4171d3dca666b1fe78cdcf5df4c1f86b89",
                   "MacAddress": "7a:42:8d:fa:16:f3",
                   "IPv4Address": "10.21.59.3/24",
                   "IPv6Address": ""
               }
           },
           "Options": {},
           "Labels": {}
      }
   ]

To start a Container with access to that network, the network name needs to be referenced during Container definition:

::

   docker run -it --net MyNet nginx /bin/bash

This will trigger the creation of a vPort on Nuage and the vPort should be visible and fully manageable from VSP API. In this use case, the Network is only visible on this specific server. Reachability can be extended by "creating" that same network on multiple nodes.

Configuring Multi-Host Networking
------------------------------------

Multihost networking can be used when the Nuage plugin is running in "global" scope. In this mode, docker networks created on a host would be accessible on other hosts that are part of same cluster. Create a docker network on server1 with the following command:

::

   root@server1~# docker network create --driver=nuage --ipam-driver=nuage-ipam --ipam-opt organization=Enterprise --ipam-opt domain=Domain --ipam-opt zone=Zone --ipam-opt subnet="Subnet 2" --ipam-opt user=admin --subnet=10.21.59.0/24  --gateway=10.21.59.1 MyNet

That network is now available and ready for consumption on server2:

::

   [root@server2:~#] docker network ls
   NETWORK ID          NAME                DRIVER
   e793da0854ce        MyNet               nuage               
   4d7098beb610        bridge              bridge              
   cf0626f73c7c        docker_gwbridge     bridge              
   b8878a9f9d58        host                host                
   967ad3ccb5af        none                null  



