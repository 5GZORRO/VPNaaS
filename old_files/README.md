# Inter-secure-channel-setup
The inter-domain security establishment repo encompasses an adaptation of WireGuard approach which will allow utilising DIDs and VCs as a mechanism for deriving a symmetric key. Thence, this repo will be supported by others such as the identity and permissions management and DLT.

![alt text](https://github.com/5GZORRO/inter-secure-channel-setup/blob/main/images/DID_based_on_VPN.png?raw=true)

## WireGuard VPN

### Pre-requisite

* The architectures supported by this image are:

| Architecture | Tag |
| :----: | --- |
| x86-64 | amd64-latest |
| arm64 | arm64v8-latest |
| armhf | arm32v7-latest |

* More information on the configuration and deployment parameters can be found on [WireGuard Github](https://github.com/linuxserver/docker-wireguard)

## Inter-domain REST API

* The current methods and information are available [here](https://5gzorro.github.io/inter-secure-channel-setup/) 

## Getting started

#### Step 1 - Download the inter-secure-channel repo

```
git clone https://github.com/5GZORRO/inter-secure-channel-setup.git
```

#### Step 2 - Install requirements

This project is written in Python, and consequently, Python3 is required to deploy its funcionalities.
In addition, multiple libraries such as Flask, Flask Restful, Gevent, and Werkzeug are needeed in order to execute the gateway. These dependencies can be installed through the file _requirements.txt_

```python
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
curl -i -X POST http://10.0.3.4:5002/installation
```

#### Step 4 - Launch Wireguard

Next, we should execute the launch method via a POST request. Besides, such request should contain a JSON object with _ip_range_, _network_interface_, _port_, _environment_, _IdM_payload_, and _endpoint_IdM_. The latter parameter can be established to "local", if we are going to perform tests outside of 5GBarcelona/5TONIC testbeds, or "testbed" on the contrary. It should be pointed out that this step should be carried out by both gateways. More details can be acquired [here](https://5gzorro.github.io/inter-secure-channel-setup/) 

An example could be:

```
curl -i -X POST -H "Content-Type: application/" -d "{\"ip_range\":\"192.168.1.1/24\",\"net_interface\":\"eth0\",\"port\":\"5003\",\"environment\":\"testbed\","DID\":\"RHxxhYFA0y0FFSuE9lPgLV"\,\"public_key\":\"p/Mg8YYnnPeUgUQM6FgKowfkd3Nc/pi926KfGewYUXg=\",\"private_key\":\"jXGkv4Wv1ZNZf3q4EPwhcTVNGGW/kEFfU7AmCdDvcMY=\",\"timestamp\":\"1647972667\",\"endpoint_IdM\":\"http://172.28.3.153:6800/authentication/operator_key_pair/verify\"}" http://10.0.3.4:5002/launch
```

#### Step 5 - Add a connection to a foreign gateway

From gateway that will act as a _client_ in this instance, we should forward a POST request in order to connect to _server_ gateway. In this case, we need to provide a JSON with _ip_address_server_, _port_server_, _IP_range_to_redirect_ (_wg0_ subnet of the WireGuard server), _destination_IP_range_to_redirect_ (subnet of the VIM to be achieved), and _environment_. An example could be:

```
curl -i -X POST -H "Content-Type: application/" -d "{\"ip_address_server\":\"10.0.2.5\",\"port_server\":\"5002\",\"IP_range_to_redirect\":\"192.168.2.1/24\",\"destination_IP_range_to_redirect\":\"192.168.160.0/24\",\"environment\":\"testbed\"}" http://10.0.3.4:5002/connect_to_VPN
```

In this moment, we wold have the VPN connection between two gateways activated.

#### Step 6 - Detele a connection to a foreign gateway

Finally, when a _client_ gateway decides to finish a connection, this should execute a command similar to the following one:

```
curl -i -X POST -H "Content-Type: application/" -d "{\"ip_address_server\":\"10.0.2.5\",\"port_server\":\"5002\"}" http://10.0.3.4:5002/disconnect_to_VPN
```

