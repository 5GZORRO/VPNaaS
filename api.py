from flask import Flask, request, Response
from flask_restful import Resource, Api
from gevent.pywsgi import WSGIServer
import os
import platform
import json
import time
import requests

app = Flask(__name__)
api = Api(app)

#Get own public key curve25519
def get_public_key():
    ##########LOGIC#########
    file=open("public_key", mode="r")
    public_key=file.read()
    file.close()

    return public_key
    
    
#Get own private key curve25519
def get_private_key():
    ##########LOGIC#########
    file=open("private_key", mode="r")
    private_key=file.read()
    file.close()

    return private_key
    
    
#When acting as server, get next IP available for clients in wg0.conf
def get_next_IP_available():

#Returns the number, in order, of the gateway to be connected.
#n in added in one per gateway connected to as a client.
def get_n_gateway():
    #Read current n (number of gateways configured as server)
    #Set current n to n+1
    #Return n

#Stores n_gate with the server ip and port to be consulted when deleting 
#the connection.
def store_interface_server_association(n_gate,server_ip,server_port):
    data={server_ip:{server_port:n_gate}}
    #store data
    return 0

def get_interface_server_association(server_ip,server_port):
    #n_gate = consultar server_ip,server_port
    return n_gate

class launch(Resource):
    def post(self):
        req = request.data.decode("utf-8")
        req = json.loads(req)
        ip_range=req["ip_range"]
        net_interface=req["net_interface"]
        
        ##########LOGIC#########
        #WireGuard installation
        os.system("sudo add-apt-repository ppa:wireguard/wireguard")
        os.system("sudo apt-get update -y")
        os.system("sudo apt-get install -y wireguard-dkms wireguard-tools linux-headers-$(uname -r)")
        
        #Generate public/private key pairs and store them 
        os.system("Umask 077")
        os.system("wg genkey | tee private_key | wg pubkey > public_key")
        
	
	private_key=get_private_key()
	
        #Generate server configuration
        config=open("/etc/wireguard/wg0.conf","w")
        config.write("[Interface]\n")
        config.write("Address = "+ip_range+"\n")
        config.write("SaveConfig = "+True+"\n")
        config.write("ListenPort = "+51820+"\n")
	config.write("PrivateKey ="+private_key+"\n")
        config.write("PostUp = "+"iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o "+net_interface+" -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o "+net_interface+" -j MASQUERADE"+"\n")
        config.write("PostDown = "+"iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o "+net_interface+" -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o "+net_interface+" -j MASQUERADE"+"\n")
        config.write("\n")
        config.close()

        #Server rules forwarding
        os.system("sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        os.system("sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        os.system("sudo iptables -A INPUT -p udp -m udp --dport 51820 -m conntrack --ctstate NEW -j ACCEPT")
        os.system("sudo iptables -A INPUT -s %s -p tcp -m tcp -m conntrack --ctstate NEW -j ACCEPT"%ip_range)
        os.system("sudo iptables -A INPUT -s %s -p tcp -m udp -m conntrack --ctstate NEW -j ACCEPT"%ip_range)
        os.system("sudo iptables -A FORWARD -i wg0 -o wg0 -m conntrack --ctstate NEW -j ACCEPT")
        os.system("sudo iptables -t nat -A POSTROUTING -o %s -j MASQUERADE"%net_interface)
        os.system("sudo apt-get install -y iptables-persistent")
        os.system("sudo systemctl enable netfilter-persistent")
        os.system("sudo netfilter-persistent save")
	
	file=open("/etc/sysctl.conf","a")
	file.write("net.ipv4.ip_forward=1\n")
	file.close()
	os.system("sudo sysctl -p")

class get_configuration(Resource):
    def get(self):
        with open ("/etc/wireguard/wg0.conf", rt) as confi:
            for line in confi:
                if "Address =" in line:
                    ip_range=line.split("= ")[2]

        #DID is also considered, we need to think on the simulated DLT in order to store these information.
        data={
            "public_key " : get_public_key(),
            "address" : ip_range
        }
        return json.dump(data)

class add_client(Resource):
    def post(self):
        req = request.data.decode("utf-8")
        req = json.loads(req)
        client_public_key=req["client_public_key"]
        
        ##########LOGIC#########
        asigned_ip=get_next_IP_available()
        config=open("/etc/wireguard/wg0.conf","a")
        config.write("[Peer]\n")
        config.write("PublicKey = "+client_public_key+"\n")
        config.write("AllowedIPs = "+asigned_ip+"/32\n")
        config.write("\n")
        config.close()
        
        server_public_key=get_public_key()
        res={"assigned_ip":asigned_ip,"server_public_key":server_public_key}
        
        #Ver como evitar reinicio interfaz    
        os.system("sudo wg-quick down wg0 && sudo wg-quick up wg0")
        
        return res
        
class remove_client(Resource):
    def post(self):
        req = request.data.decode("utf-8")
        req = json.loads(req)
        client_public_key=req["client_public_key"]
        
        ##########LOGIC#########
        with open("/etc/wireguard/wg0.conf") as myFile:
            for num, line in enumerate(myFile, 1):
                if client_public_key in line:
                   print ('found at line:', num)

        return 200
        
class connect_to_VPN(Resource):
    def post(self):
        req = request.data.decode("utf-8")
        req = json.loads(req)
        ip_address_server=req["ip_address_server"]
        port_server=req["port_server"]
        
        client_public_key=get_public_key()
        
        req= {"client_public_key":client_public_key}
        res=requests.post("http://"+ip_address_server:port_server+'/add_client',data=json.dumps(req).encode("utf-8"))
        res=json.loads(res.text)
        assigned_ip=res["assigned_ip"]
        server_public_key=res["server_public_key"]
        
        n_gate=get_n_gateway()
        ##########LOGIC#########
        
        client_private_key=get_private_key()
        
        config=open("/etc/wireguard/wg"+n_gate+".conf","w")
        config.write("[Interface]\n")
        config.write("Address = "+assigned_ip+"/32\n")
        config.write("PrivateKey = "+client_private_key+"\n")
        config.write("DNS = 8.8.8.8\n\n")
        config.write("[Peer]\n")
        config.write("PublicKey = "+server_public_key+"\n")
        config.write("Endpoint = "+ip_address_server+":"+port_server+"\n")
        config.write("AllowedIPs = 0.0.0.0/0\n")
        config.write("\n")
        config.close()
        
        store_interface_server_association(n_gate,ip_address_server,port_server)
        os.system("sudo wg-quick up wg"+n_gate)
        
        return 200
        
class disconnect_to_VPN(Resource):
    def post(self):    
        req = request.data.decode("utf-8")
        req = json.loads(req)
        ip_address_server=req["ip_address_server"]
        port_server=req["port_server"]
        
        n_gate=get_interface_server_association(ip_address_server,port_server)
        
        client_public_key=get_public_key()
        
        req= {"client_public_key":client_public_key}
        res=requests.post("http://"+ip_address_server:port_server+'/remove_client',data=json.dumps(req).encode("utf-8"))
        
        int(res.text)==200:
            os.system("sudo wg-quick down wg"+n_gate)
            os.system("rm /etc/wireguard/wg"+n_gate+".conf")
        
        return 200
        

def launch_server_REST():
	api.add_resource(launch, '/launch/')
	api.add_resource(get_configuration, '/get_configuration')
	api.add_resource(add_client, '/add_client')
	api.add_resource(remove_client, '/remove_client')
	api.add_resource(connect_to_VPN, '/connect_to_VPN')
	api.add_resource(disconnect_to_VPN, '/disconnect_to_VPN')
	http_server = WSGIServer(('0.0.0.0', 5002), app)
	http_server.serve_forever()

if __name__ == "__main__":
    launch_server_REST()
    
