# VPN-as-a-Service

## Introduction
The VPNaaS repo encompasses an adaptation of WireGuard approach which will allow utilising DIDs and key pairs as a mechanism for deriving a symmetric key. This module aims at providing the capabilities for establishing secure and trusted connections between different domains in the 5GZORRO environment, guaranteeing privacy and integrity but without sacrificing performance. It has an important role when it comes to performing network slicing and integrating resources located at a third-party infrastructure. 
![alt text](https://github.com/5GZORRO/inter-secure-channel-setup/blob/main/images/DID_based_on_VPN_v1.png?raw=true)

## Pre-requisites

#### System Requirements
* **Number of CPUs**: 2
* **RAM (GB)**: 2
* **Storage (GB)**: 10
* **Deployment/Virtualization technology**: VMs
* **Architectures supported by Wireguard**

    | Architecture | Tag |
    | :----: | --- |
    | x86-64 | amd64-latest |
    | arm64 | arm64v8-latest |
    | armhf | arm32v7-latest |

* More information on the configuration and deployment parameters can be found on [WireGuard Github](https://github.com/linuxserver/docker-wireguard)

### Software dependecies
All key pairs sent to the VPNaaS so as to derive a shared secret should leverage the Curve25519 elliptic curve. Otherwise, the VPNaaS will not be able to correctly decrypt the information, and in consequence, the tunnel will not be configured.
### 5GZORRO Module dependencies
The VPNaaS module is consumed by the Network Service Mesh Manager, which is in charge of requesting new establishments across domains. Besides, the VPNaaS module needs to contact with the Id&P module to verify the DIDs and public keys provided by other VPNaaS modules. Thence, these 5GZORRO modules should be up and running for beginning a secure and on-demand communication. In order to install the aforementioned 5GZORRO modules, please, check the README.md file of each one:
* [Network Service Mesh Manager](https://github.com/5GZORRO/network-service-mesh-manager)
* [Identity and Permission Manager](https://github.com/5GZORRO/identity)


## Installation
#### Step 1 - Download the VPNaaS repo

```
git clone https://github.com/5GZORRO/inter-secure-channel-setup.git
```

#### Step 2 - Install requirements

This project is written in Python, and consequently, Python3 is required to deploy its funcionalities.
In addition, multiple libraries such as Flask, Flask Restful, Gevent and Werkzeug, among others, are needeed in order to execute the gateway. These dependencies can be installed through the file _requirements.txt_

```
pip install -r requirements.txt
```

#### Step 3 - Install Wireguard if not installed

First of all, we should launch the file _app_api.py_ with sudo permissions. After that, we will perform the Wireguard installation on each machine.

```
sudo python3 app_api.py <REST_server_port>
```
If you don't want to interact during the installation process, you can execute the following command and accept the default configuration:

```
yes | sudo python3 app_api.py <REST_server_port>
```

```
curl -i -X POST http://172.28.3.23:5002/installation
```

## Configuration

Note that Steps 5 and 6 are not necessary to install the VPNaaS module but they are really utilised by the NSMM to start and stop an on-demand tunnel connection.

#### Step 5 - Add a connection to a foreign gateway

From gateway that will act as a _client_ in this instance, we should forward a POST request in order to connect to _server_ gateway. In this case, we need to provide a JSON with _ip_address_server_, _port_server_, _IP_range_to_redirect_ (_wg0_ subnet of the WireGuard server), _destination_IP_range_to_redirect_ (subnet of the VIM to be achieved), and _environment_. An example could be:

```
curl -i -X POST -H "Content-Type: application/" -d "{\"ip_address_server\":\"10.0.2.5\",\"port_server\":\"5002\",\"IP_range_to_redirect\":\"192.168.2.1/24\",\"destination_IP_range_to_redirect\":\"192.168.160.0/24\",\"environment\":\"testbed\"}" http://10.0.3.4:5002/connect_to_VPN
```
A real example leveraging the VM of 5GBarcelona would be:
```
curl -i -X POST -H "Content-Type: application/" -d "{\"ip_address_server\":\"172.28.3.211\",\"port_server\":\"5002\",\"IP_range_to_redirect\":\"192.168.2.1/24, 192.168.162.0/24\",\"destination_IP_range_to_redirect\":\"192.168.160.0/24\",\"environment\":\"testbed\"}" http://172.28.3.23:5002/connect_to_VPN
```

In this moment, we wold have the VPN connection between two gateways activated.

#### Step 6 - Detele a connection to a foreign gateway

Finally, when a _client_ gateway decides to finish a connection, this should execute a command similar to the following one:

```
curl -i -X POST -H "Content-Type: application/" -d "{\"ip_address_server\":\"10.0.2.5\",\"port_server\":\"5002\"}" http://10.0.3.4:5002/disconnect_to_VPN
```
A real example leveraging the VM of 5GBarcelona would be:
```
curl -i -X POST -H "Content-Type: application/" -d "{\"ip_address_server\":\"172.28.3.211\",\"port_server\":\"5002\"}" http://172.28.3.23:5002/disconnect_to_VPN
```

## Maintainers
**José María Jorquera Valero** - *Developer and Designer* - josemaria.jorquera@um.es

**Pedro Miguel Sánchez Sánchez** - *Developer and Designer* - pedromiguel.sanchez@um.es

## License
This 5GZORRO component is published under Apache 2.0 license.