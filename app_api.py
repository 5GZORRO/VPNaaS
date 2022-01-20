from flask import Flask, request
from flask_restful import Resource, Api
from gevent.pywsgi import WSGIServer
from ipaddress import IPv4Network
import os
import json
import requests
import sys
import subprocess
from gevent import monkey
from dotenv import load_dotenv

monkey.patch_all()
app = Flask(__name__)
api = Api(app)

#Global variables
public_key = ""
private_key = ""


# Get own public key curve25519
def get_public_key():
    file = open("public_key", mode="r")
    public_key = file.read()
    public_key = public_key[:-1]
    file.close()
    return public_key

def get_key_pair_from_IdM():
    global public_key
    global private_key

    #This method will be agnostic to the domains after changing the current end-point of the IdM
    req = requests.get("http://172.28.3.153:6200/authentication/operator_key_pair?shared_secret=5gzorroidportalnsmm")
    req = req.json()
    public_key = req["public_key"]
    private_key = req["private_key"]

def get_own_IP():
    command = "ip addr show ens3 | grep \"inet \" | awk \'{print $2}\' | cut -f1 -d\"/\""
    result = subprocess.run(command, stdout=subprocess.PIPE, shell=True)
    ip = result.stdout.decode('utf-8')
    return ip

# Get own private key curve25519
def get_private_key():
    file = open("private_key", mode="r")
    private_key = file.read()
    private_key = private_key[:-1]
    file.close()

    return private_key

def get_vpn_port():
    file = open("vpn_port", mode="r")
    vpn_port = int(file.read())
    file.close()
    return vpn_port

def set_vpn_port(n_port):
    file = open("vpn_port", mode="w")
    file.write(n_port)
    file.close()

# When acting as server, get next IP available for clients in wg0.conf
"""def get_next_IP_available():
    min1 = 0
    min2 = 0
    min3 = 0
    min4 = 1
    
    file = open("ip_management", "r")
    for line in file:
        b = line.split(".")
        b1 = int(b[0])
        b2 = int(b[1])
        b3 = int(b[2])
        b4 = int(b[3])
        if b1 > min1:
            min1 = b1
            min2 = 0
            min3 = 0
            min4 = 1
        if b2 > min2:
            min2 = b2
            min3 = 0
            min4 = 1
        if b3 > min3:
            min3 = b3
            min4 = 1
        if b4 > min4:
            min4 = b4
    file.close()
    
    # Case of last IP in range (.255), new subrange. Else, assigned ip is last IP + 1
    if min4 == 255:
        min3 = min3+1
        min4 = 1
    else:
        min4 = min4+1
    ip = str(min1)+"."+str(min2)+"."+str(min3)+"."+str(min4)

    # Save assigned IP as in usage
    file = open("ip_management", "a")
    file.write(ip+"\n")
    file.close()
    return ip"""

def get_next_IP_available_2():
    ip_range = '0.0.0.0/0'
    with open("/etc/wireguard/wg0.conf", "r") as confi:
        for line in confi:
            if "Address =" in line:
                ip_range = line.split("= ")[1]

    ip_range = ip_range.rstrip()
    if ip_range.split("/")[1] == "24":
        ip = ip_range.split(".")
        ip_range = ip[0]+"."+ip[1]+"."+ip[2]+".0/24"
    elif ip_range.split("/")[1] == "16":
        ip = ip_range.split(".")
        ip_range = ip[0]+"."+ip[1]+".0.0/16"
    elif ip_range.split("/")[1] == "8":
        ip = ip_range.split(".")
        ip_range = ip[0]+"."+"0.0.0/8"

    network = IPv4Network(ip_range)
    IP_reserved = []

    file = open("ip_management", "r")
    for line in file:
        IP_reserved.append(line.rstrip())
    file.close()

    first_IP_available = (host for host in network.hosts() if str(host) not in IP_reserved)

    assigned_ip = next(first_IP_available)

    # Save assigned IP as in usage
    file = open("ip_management", "a")
    file.write(str(assigned_ip)+"\n")
    file.close()
    return str(assigned_ip)


def liberate_free_ip(ip_vpn):
    file = open("ip_management","r")
    line_ip = 0
    for num, line in enumerate(file, 1):
        if ip_vpn in line:
            line_ip = num
    os.system("sudo sed -i '"+str(line_ip+1)+"d' ip_management")


# Returns the number, in order, of the gateway to be connected.
# n in added in one per gateway connected to as a client.
def get_n_gateway():
    file = open("n_gateway", mode="r")
    n_gateway = int(file.read())
    file.close()
    return n_gateway


def set_n_gateway(n):
    file = open("n_gateway", mode="w")
    file.write(str(n))
    file.close()


# Stores n_gate with the server ip and port to be consulted when deleting
# the connection.
def store_interface_server_association(n_gate, server_ip, server_port):
    file = open("interface_server_associations", mode="a")
    file.write(str(n_gate) + ":" + str(server_ip) + ":" + str(server_port) + "\n")
    file.close()

# Stores n_gate with the server_ip and public key to be consulted when deleting
# the connection.
def store_interface_key_association(n_gate, server_ip, public_key):
    file = open("interface_key_associations", mode="a")
    file.write(str(public_key) + ":" + str(n_gate) + ":" + str(server_ip) + "\n")
    file.close()


# Get the n_gate associated with the requested ip and port
def get_interface_server_association(server_ip, server_port):
    with open("interface_server_associations", mode="r") as file:
        for line in file:
            parts = line.split(":")
            server_port = str(server_port).split()
            parts[2] = parts[2].split()
            if server_ip == parts[1] and server_port == parts[2]:
                return int(parts[0])
    return 999999

# Get the public_key associated with the requested server_ip and port
def get_interface_key_association(n_gate, server_ip):
    with open("interface_key_associations", mode="r") as file:
        for line in file:
            parts = line.split(":")
            server_ip = str(server_ip).split()
            parts[2] = parts[2].split()
            if n_gate == parts[1] and server_ip == parts[2]:
                return int(parts[0])
    return 999999

class installation(Resource):
    def post(self):

        # WireGuard installation
        os.system("sudo add-apt-repository ppa:wireguard/wireguard")
        os.system("sudo apt-get update -y")
        os.system("sudo apt-get install -y wireguard-dkms wireguard-tools linux-headers-$(uname -r) openresolv")

        os.system("sudo apt-get install -y iptables-persistent")
        os.system("sudo systemctl enable netfilter-persistent")

        file = open("/etc/sysctl.conf", "a")
        file.write("net.ipv4.ip_forward=1\n")
        file.close()
        os.system("sudo sysctl -p")


class launch(Resource):
    def post(self):
        global private_key

        req = request.data.decode("utf-8")
        req = json.loads(req)
        ip_range = req["ip_range"]
        net_interface = req["net_interface"]
        port = req["port"]
        environment = req["environment"]

        # Take environment variable
        load_dotenv()
        secret = os.getenv('KEY')

        # Generate public/private key pairs and store them
        os.system("umask 077")

        #Two options to enable NXW's team local tests
        if environment == "local":
            os.system("wg genkey | tee private_key | wg pubkey > public_key")
            #os.system("cat private_key | wg pubkey > public_key")
            private_key = get_private_key()
        elif environment == "testbed":
            get_key_pair_from_IdM()

        # Generate server configuration
        config = open("/etc/wireguard/wg0.conf", "w")
        config.write("[Interface]\n")
        config.write("Address = " + ip_range + "\n")
        config.write("SaveConfig = " + str(False) + "\n")
        config.write("ListenPort = " + str(port) + "\n")
        config.write("PrivateKey = " + private_key + "\n")
        config.write(
            "PostUp = " + "iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o " + net_interface + " -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o " + net_interface + " -j MASQUERADE" + "\n")
        config.write(
            "PostDown = " + "iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o " + net_interface + " -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o " + net_interface + " -j MASQUERADE" + "\n")
        config.write("\n\n")
        config.close()

        os.system("sudo wg-quick up wg0")
        os.system("sudo systemctl enable wg-quick@wg0.service")
        # Store VPN port
        set_vpn_port(port)

        # Store interface generated
        set_n_gateway(0)
        file=open("ip_management","w")
        file.write(ip_range.split("/")[0]+"\n")
        file.close()

        # Server rules forwarding
        os.system("sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        os.system("sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        os.system("sudo iptables -A INPUT -p udp -m udp --dport 51820 -m conntrack --ctstate NEW -j ACCEPT")
        os.system("sudo iptables -A INPUT -s %s -p tcp -m tcp -m conntrack --ctstate NEW -j ACCEPT" % ip_range)
        os.system("sudo iptables -A INPUT -s %s -p udp -m udp -m conntrack --ctstate NEW -j ACCEPT" % ip_range)
        os.system("sudo iptables -A FORWARD -i wg0 -o wg0 -m conntrack --ctstate NEW -j ACCEPT")
        os.system("sudo iptables -t nat -A POSTROUTING -o %s -j MASQUERADE" % net_interface)
        os.system("sudo netfilter-persistent save")


class get_configuration(Resource):
    def get(self):
        global public_key

        with open("/etc/wireguard/wg0.conf", "r") as confi:
            for line in confi:
                if "Address =" in line:
                    ip_range = line.split("= ")[1]

        # DID dummy considered, we need to think on the simulated DLT in order to store these information.
        data = {
            "did": "did:5gzorro:dummy12345",
            #"public_key": get_public_key(),
            "public_key": public_key,
            "IP_range": ip_range,
            "vpn_port":get_vpn_port()
        }
        return json.dumps(data)


class add_client(Resource):
    def post(self):
        global public_key

        req = request.data.decode("utf-8")
        req = json.loads(req)
        client_public_key = req["client_public_key"]
        destination_IP_range_to_redirect = req["destination_IP_range_to_redirect"]
        environment = req["environment"]

        assigned_ip = get_next_IP_available_2()
        config = open("/etc/wireguard/wg0.conf", "a")
        config.write("[Peer]\n")
        config.write("PublicKey = " + client_public_key+"\n")
        config.write("AllowedIPs = " + assigned_ip + "/32, "+destination_IP_range_to_redirect+"\n")
        config.write("\n")
        config.close()

        #Two options to enable NXW's team local tests
        if environment == "local":
            server_public_key = get_public_key()
        elif environment == "testbed":
            server_public_key = public_key

        vpn_port= get_vpn_port()
        res = {"assigned_ip": assigned_ip, "vpn_port":vpn_port,  "server_public_key": server_public_key}

        # See how to evade interface reboot
        os.system("sudo wg-quick down wg0 && sudo wg-quick up wg0")

        return res


class remove_client(Resource):
    def post(self):
        req = request.data.decode("utf-8")
        req = json.loads(req)
        client_public_key = req["client_public_key"]

        config_line=-100
        ip_vpn = ""
        with open("/etc/wireguard/wg0.conf","r") as file:
            for num, line in enumerate(file, 1):
                if client_public_key in line:
                    config_line = num
                if num == config_line+1:
                    ip_vpn = line.split(" = ")[1]
                    ip_vpn = ip_vpn.split("/")[0]

        if config_line != -100 and ip_vpn != "":
            os.system("sudo sed -i '"+str(config_line+1)+"d' /etc/wireguard/wg0.conf")
            os.system("sudo sed -i '"+str(config_line)+"d' /etc/wireguard/wg0.conf")
            os.system("sudo sed -i '"+str(config_line-1)+"d' /etc/wireguard/wg0.conf")

            liberate_free_ip(ip_vpn)

            # See how to evade interface reboot
            os.system("sudo wg-quick down wg0 && sudo wg-quick up wg0")

            return 200


class connect_to_VPN(Resource):
    def post(self):
        global private_key
        global public_key

        req = request.data.decode("utf-8")
        req = json.loads(req)
        ip_address_server = req["ip_address_server"]
        port_server = req["port_server"]
        IP_range_to_redirect = req["IP_range_to_redirect"]
        destination_IP_range_to_redirect = req["destination_IP_range_to_redirect"]
        environment = req["environment"]

        #Two options to enable NXW's team local tests
        if environment == "local":
            client_public_key = get_public_key()
        elif environment == "testbed":
            #Each new connection a new key pair should be employed
            get_key_pair_from_IdM()
            client_public_key = public_key

        req = {"client_public_key": client_public_key, "destination_IP_range_to_redirect": destination_IP_range_to_redirect,
               "environment": environment}
        headers = {"Content-Type" : "application/json"}
        res = requests.post("http://" + str(ip_address_server) + ":" + str(port_server) + "/add_client",
                            data=json.dumps(req).encode("utf-8"), headers=headers, timeout=10)
        res = json.loads(res.text)
        assigned_ip = res["assigned_ip"]
        server_public_key = res["server_public_key"]
        vpn_port = res["vpn_port"]

        #n_gate = get_n_gateway()
        #n_gate = n_gate + 1
        n_gate = 99999
        interfaces_reserved = []

        try:
            with open("interface_server_associations", "r") as file:
                for line in file:
                    interfaces_reserved.append(str(line.split(":")[0]))
                for x in range(1,10):
                    if str(x) not in interfaces_reserved:
                        n_gate = x
                        break
        except IOError:
            n_gate = 1

        #Two options to enable NXW's team local tests
        if environment == "local":
            client_private_key = get_private_key()
        elif environment == "testbed":
            client_private_key = private_key

        config = open("/etc/wireguard/wg" + str(n_gate) + ".conf", "w")
        config.write("[Interface]\n")
        config.write("Address = " + assigned_ip + "/32\n")
        config.write("PrivateKey = " + client_private_key + "\n")
        config.write("DNS = 8.8.8.8\n\n")
        config.write("[Peer]\n")
        config.write("PublicKey = " + server_public_key + "\n")
        config.write("Endpoint = " + ip_address_server + ":" + str(vpn_port) + "\n")
        config.write("AllowedIPs = "+ IP_range_to_redirect + "\n")
        config.write("\n")
        config.close()

        set_n_gateway(n_gate)

        store_interface_server_association(n_gate, ip_address_server, port_server)
        store_interface_key_association(n_gate,ip_address_server, client_public_key)
        os.system("sudo wg-quick up wg" + str(n_gate))

        return 200


class disconnect_to_VPN(Resource):
    def post(self):
        global public_key

        req = request.data.decode("utf-8")
        req = json.loads(req)
        ip_address_server = req["ip_address_server"]
        port_server = req["port_server"]

        n_gate = get_interface_server_association(ip_address_server, port_server)
        client_public_key = get_interface_key_association(n_gate, ip_address_server)

        req = {"client_public_key": client_public_key}
        res = requests.post("http://" + str(ip_address_server) + ":" + str(port_server) + '/remove_client',
                            data=json.dumps(req).encode("utf-8"))

        if res.status_code == 200:
            os.system("sudo wg-quick down wg" + str(n_gate))
            os.system("rm /etc/wireguard/wg" + str(n_gate) + ".conf")

            config_line = -100
            with open("interface_server_associations","r") as file:
                for num, line in enumerate(file,1):
                    if str(n_gate) in line.split(":")[0]:
                        config_line = num

            if config_line != -100:
                os.system("sudo sed -i '"+str(config_line)+"d' interface_server_associations")

        return 200


def launch_server_REST(port):
    #api.app.run(ssl_context=('cert.pem','key.pem'))
    api.add_resource(installation, '/installation')
    api.add_resource(launch, '/launch')
    api.add_resource(get_configuration, '/get_configuration')
    api.add_resource(add_client, '/add_client')
    api.add_resource(remove_client, '/remove_client')
    api.add_resource(connect_to_VPN, '/connect_to_VPN')
    api.add_resource(disconnect_to_VPN, '/disconnect_to_VPN')
    http_server = WSGIServer(('0.0.0.0', port), app)
    http_server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv)!=2:
        print("Usage: python3 app_api.py [port]")
    else:
        port=int(sys.argv[1])
        launch_server_REST(port)


