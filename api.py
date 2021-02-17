from flask import Flask, request, Response
from flask_restful import Resource, Api
from gevent.pywsgi import WSGIServer
import os
import platform
import json
import time

app = Flask(__name__)
api = Api(app)

#Get own public key curve25519
def get_public_key():
    public_key=""
    ##########LOGIC#########
    return public_key
    
    
#Get own private key curve25519
def get_private_key():
    private_key=""
    ##########LOGIC#########
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
    

class get_configuration(Resource):
    def get(self):
    
    return ""

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
                   print 'found at line:', num

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
    
