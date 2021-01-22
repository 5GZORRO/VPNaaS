from flask import Flask, request
from flask_restful import Resource, Api
from gevent.pywsgi import WSGIServer
import os
import platform
import json
import time

app = Flask(__name__)
api = Api(app)

class resource_manager(Resource):
    def post(self):
        #Parse request and get client id, requested service and ip to be assigned
        #Request has the format: "id":"did:5g-zorro:domain1_orchestration_engine","res_id":"did:5g-zorro:domain2_example_resource","ip":"10.200.200.2"}
        req = request.data.decode("utf-8")
        req = json.loads(req)
        client_id=req["id"]
        res_id=req["id_res"]
        req_ip=req["ip_res"]
        
        #Get client public key and endpoint from DLT
        with open('dlt.json') as json_file:
            data = json.load(json_file)
        for i in data:
            if i["id"]==client_id:
                client_pub_key=i["authentication"]["public_key"]
                client_endpoint=i["service"]["serviceEndpoint"]
        
        #Get resource private key
        res_priv_key=open("priv_keys_res/"+res_id.split(":")[2],"r").read()[:-1]
        
        #Generate network configuration file for Wireguard VPN
        config_directory=os.getcwd()+"/wireguard/"+res_id.split(":")[2]
        if not os.path.exists(config_directory):
        	os.makedirs(config_directory)
        
        config=open(config_directory+"/"+"wg0.conf","w")
        config.write("[Interface]\n")
        config.write("Address = "+req_ip+"/32\n")
        config.write("PrivateKey = "+res_priv_key+"\n")
        config.write("DNS = 8.8.8.8\n\n")
        config.write("[Peer]\n")
        config.write("PublicKey = "+client_pub_key+"\n")
        config.write("Endpoint = "+client_endpoint+"\n")
        config.write("AllowedIPs = 0.0.0.0/0\n")
        config.write("\n")
        config.close()
        
        #Instantiate the requested resource and set network configuration
        os.system("docker run -d --name=resource --cap-add net_admin --cap-add sys_module -e PUID=1000 -e PGID=1000 -e TZ=Europe/London -p 51820:51820/udp -v "+ config_directory +":/config -v /lib/modules:/lib/modules --sysctl=\"net.ipv4.conf.all.src_valid_mark=1\" --restart unless-stopped ghcr.io/linuxserver/wireguard &")
        time.sleep(5)
        
        #Retrun 200 if success
        return 200

def launch_server_REST():
	api.add_resource(resource_manager, '/resource_manager/')
	http_server = WSGIServer(('0.0.0.0', 5002), app)
	http_server.serve_forever()

if __name__ == "__main__":
    launch_server_REST()
