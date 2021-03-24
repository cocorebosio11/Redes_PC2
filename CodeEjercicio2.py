import pandas as pd
import sys
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
        path = '/wm/acl/rules/json'
        headers = { 'Content-type': 'application/json',
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
 
lines = pd.read_csv(sys.argv[1]) 
lines = lines[['dst_ip', 'dst_port']] 
lines = lines.dropna() 
 


for line, data in lines.iterrows(): 
    ip, port = data['dst_ip'], data['dst_port'] 
    curl = { 
        'switch': '00:00:00:00:00:00:00:06', 
        "name":"flow-mod-" + str(line),
        'src-ip': ip + "/32", 
        'nw-proto': 'TCP', 
        'tp-dst': port, 
        'action': 'DENY' 
    } 
    pusher.set(curl) 
