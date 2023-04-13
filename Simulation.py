import pyshark
from tensorflow.keras.models import Sequential, model_from_json
from tensorflow.keras.layers import Dense
import numpy as np
import os
from tensorflow import keras
import subprocess

 
#load json and create model
json_file = open('model.json', 'r')
loaded_model_json = json_file.read()
json_file.close()
loaded_model = model_from_json(loaded_model_json)
# load weights into new model
loaded_model.load_weights("model.h5")
print("Loaded model from disk")

feat_cols = [
 'arp.opcode',
 'arp.hw.size',
 'icmp.checksum',
 'icmp.seq_le',
 'http.content_length',
 'http.response',
 'tcp.ack',
 'tcp.ack_raw',
 'tcp.checksum',
 'tcp.connection.fin',
 'tcp.connection.rst',
 'tcp.connection.syn',
 'tcp.connection.synack',
 'tcp.flags',
 'tcp.flags.ack',
 'tcp.len',
 'tcp.seq'
 'udp.stream',
 'udp.time_delta',
 'dns.qry.name',
 'dns.qry.qu',
 'dns.retransmission',
 'dns.retransmit_request',
 'dns.retransmit_request_in',
 'mqtt.conflag.cleansess',
 'mqtt.conflags',
 'mqtt.hdrflags',
 'mqtt.len',
 'mqtt.msgtype',
 'mqtt.proto_len',
 'mqtt.topic_len',
 'mqtt.ver',
 'mbtcp.len',
 'mbtcp.trans_id',
 'mbtcp.unit_id',
 'Attack_label',
 'http.request.method-0',
 'http.request.method-0.0',
 'http.request.method-GET',
 'http.request.method-OPTIONS',
 'http.request.method-POST',
 'http.request.method-TRACE',
 'http.referer-() { _; } >_[$($())] { echo 93e4r0-CVE-2014-6278: true; echo;echo; }',
 'http.referer-0',
 'http.referer-0.0',
 'http.referer-127.0.0.1',
 'http.request.version--a HTTP/1.1',
 'http.request.version-/etc/passwd|?data=Download HTTP/1.1',
 'http.request.version-0',
 'http.request.version-0.0',
 'http.request.version-By Dr HTTP/1.1',
 'http.request.version-HTTP/1.0',
 'http.request.version-HTTP/1.1',
 'http.request.version-Src=javascript:alert(\'Vulnerable\')><Img Src=\\" HTTP/1.1',
 'dns.qry.name.len-0',
 'dns.qry.name.len-0.0',
 'dns.qry.name.len-0.debian.pool.ntp.org',
 'dns.qry.name.len-1.0',
 'dns.qry.name.len-1.debian.pool.ntp.org',
 'dns.qry.name.len-2.debian.pool.ntp.org',
 'dns.qry.name.len-3.debian.pool.ntp.org',
 'dns.qry.name.len-_googlecast._tcp.local',
 'mqtt.conack.flags-0',
 'mqtt.conack.flags-0.0',
 'mqtt.conack.flags-0x00000000',
 'mqtt.protoname-0',
 'mqtt.protoname-0.0',
 'mqtt.protoname-MQTT',
 'mqtt.topic-0',
 'mqtt.topic-0.0',
 'mqtt.topic-Temperature_and_Humidity'
]


input = np.zeros((5,71))
packet_no = 0

 #Sniff from interface in real time
capture = pyshark.LiveCapture(interface='Wi-Fi')
capture.sniff(packet_count=30)
for pkt in capture:
    if packet_no == 5:
        break
    flag = False
    feature_no = 0
    for feature in feat_cols:
        components = feature.split('.')
        obj = pkt
        counter = len(components)
        for c in components:            
            if hasattr(obj,c):
                obj = getattr(obj, c)
                counter = counter - 1
            else:
                break
        if counter == 0:
            flag = True
            if len(obj) > 2 and obj[0] == '0' and obj[1] == 'x' :
                dec = int(obj,16)
                input[packet_no][feature_no] = dec
            else:
                input[packet_no][feature_no] = obj
        feature_no += 1
    if(flag):
        packet_no += 1        


#print(input)
#evaluate loaded model on test data
loaded_model.compile(loss=keras.losses.SparseCategoricalCrossentropy(), optimizer='adam', metrics=['accuracy'])
y_pred = loaded_model.predict(input,256)
y_pred = np.argmax(y_pred,axis = 1)
print(y_pred)

attack_classes = ['DDoS_ICMP', 'DDoS_UDP', 'MITM', 'Normal', 'Port_Scanning',
       'Ransomware', 'SQL_injection', 'Vulnerability_scanner', 'XSS']

counts = np.bincount(y_pred)
final_pred = np.argmax(counts)
if final_pred == 3:
    print("Normal traffic detected")
else:
    print("Possible attack traffic detected....")
    print("Attack : "+attack_classes[final_pred])
    print("Sending sms and email alert to the admin")
    subprocess.call(["python","email_service.py"])  
    subprocess.call(["python","sms_service.py"])      

