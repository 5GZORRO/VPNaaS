# Inter-secure-channel-setup
The inter-domain security establishment repo encompasses an adaptation of WireGuard approach which will allow utilising DIDs and VCs as a mechanism for deriving a symmetric key. Thence, this repo will be supported by others such as the identity and permissions management and DLT.

![alt text](https://github.com/josejmjv/intra-domain-example/blob/main/images/DID_based_on_VPN.png?raw=true)

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

## Requirements

This project is written in Python, and consequently, Python3 is required to deploy its funcionalities.
In addition, multiple libraries such as Flask, Flask Restful, Gevent, and Werkzeug are needeed in order to execute the gateway. These dependencies can be installed through the file requirements.txt

```python
pip install -r requirements.txt
``  
