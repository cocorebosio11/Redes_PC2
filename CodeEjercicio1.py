import httplib
import json
class StaticEntryPusher(object):
	 
	 def __init__(self, server):
		self.server = server
	 
	 def get(self, data):
		ret = self.rest_call({}, 'GET')
		return json.loads(ret[2])
	
	 def set(self, data):
		ret = self.rest_call(data, 'POST')
		return ret[0] == 200
	
	 def remove(self, objtype, data):
		ret = self.rest_call(data, 'DELETE')
		return ret[0] == 200
	 
	 def rest_call(self, data, action):
		 path = '/wm/staticflowpusher/json'
		 headers = {
		 'Content-type': 'application/json',
		 'Accept': 'application/json',
		 }
		 body = json.dumps(data)
		 conn = httplib.HTTPConnection(self.server, 8080)
		 conn.request(action, path, body, headers)
		 response = conn.getresponse()
		 ret = (response.status, response.reason, response.read())
		 print ret
		 conn.close()
		 return ret
		 
pusher = StaticEntryPusher('127.0.0.1')
to_deny = [2, 5]

for host in to_deny:
	switch = (host - 1) // 2 + 3 + (host > 4)
	port = 2 - (host % 2)
	print(host, switch , port)
	flow = {
			  "switch": "00:00:00:00:00:00:00:0" + str(switch), 
			  "name":"flow-mod-" + str(host), 
			  "priority":"32769", 
			  "eth_type": "0x800", 
			  "in_port": str(port), 
			  "ipv4_src":"10.0.0." + str(host)+ "/32", 
			  "ipv4_dst":"10.0.0.0/24", 
			  "active":"true", 
			  "actions": "drop"
			}
	pusher.set(flow)		
				
