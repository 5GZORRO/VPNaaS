import json
import os
import requests

#Get ID of the resource to utilize
id_res="did:5g-zorro:domain2_example_resource"

#Logic to determine the resource IP inside the organization
ip_res="10.200.200.2"

#Get resource endpoint and its public key
with open('dlt.json') as json_file:
    data = json.load(json_file)
for i in data:
    if i["id"]==id_res:
        res_did=i
endpoint=res_did["service"]["serviceEndpoint"]
res_public_key=res_did["authentication"]["public_key"]

print(res_public_key)
print(endpoint)

#Request resource and set IP
req={"id":"did:5g-zorro:domain1_orchestration_engine","id_res":id_res,"ip_res":ip_res}
response=requests.post("http://"+endpoint+'/resource_manager/',data=json.dumps(req).encode("utf-8"))

#If the response is positive, add the resource to the VPN configuration
if int(response.text)==200:
    config=open("/etc/wireguard/wg0.conf","a")
    config.write("[Peer]\n")
    config.write("PublicKey = "+res_public_key+"\n")
    config.write("AllowedIPs = "+ip_res+"/32\n")
    config.write("\n")
    config.close()

    #Load new Wireguard configuration
    os.system("sudo wg-quick down wg0 && sudo wg-quick up wg0")
