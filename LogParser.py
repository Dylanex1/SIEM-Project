import json

log = "Feb 17 14:32:10 server1 sshd[1023]: Failed password for root from 192.168.1.10 port 53422 ssh2"
#Feb 17 14:33:01 server1 sshd[1050]: Failed password for invalid user admin from 10.0.0.5 port 60211 ssh2
#Feb 17 14:34:44 server1 sshd[1077]: Failed password for test from 172.16.0.3 port 49821 ssh2
#Feb 17 14:35:12 server1 sshd[1100]: Accepted password for alice from 192.168.1.20 port 50111 ssh2
#Feb 17 14:36:45 server1 sshd[1122]: Accepted publickey for bob from 192.168.1.21 port 50991 ssh2
#Feb 17 14:37:03 server1 sshd[1150]: Invalid user guest from 203.0.113.55 port 42122
#Feb 17 14:37:55 server1 sshd[1165]: Connection closed by authenticating user root 192.168.1.10 port 53422 [preauth]
#Feb 17 14:38:10 server1 sshd[1180]: Received disconnect from 192.168.1.10 port 53422:11: Bye Bye [preauth]
#Feb 17 14:39:22 server1 sshd[1201]: Failed password for root from 192.168.1.10 port 22 ssh2: RSA SHA256:abc123
#Feb 17 14:40:33 server1 sshd[1220]: error: maximum authentication attempts exceeded for root from 192.168.1.10 port 22 ssh2 [preauth]

#This method is to capture syslog events, specifically used to extract time details and what event type it was and user details of who was accessed by what IP
def syslogParser():
    header,message = log.split(": ",1)
    header = header.split()
    message = message.split()
    event = {} #dictionary to store KVP
    #declare variables and get the header piece for logs
    event["month"] = header[0]
    event["day"] = header[1] 
    event["time"] = header[2]
    event["host"] = header[3]  
    event["serviceAndPID"] = header[4]
    event["user"] = ""
    event["sourceIP"] = ""
    event["port"] = ""
    event["eventType"] = ""
    event["authnMethod"] = "None"
    
    #get the message body 
    
    
    #get the event type and authentication 
    if(len(message) > 0 and message[0] == "Failed"):
        if(len(message) > 1 and message[1] == "password"):
            event["authnMethod"] ="password"
        elif(len(message) > 1 and message[1] == "publickey"):
           event["authnMethod"] ="publickey"
           
        event["eventType"] = "FailedLogin"
        
    elif(len(message) > 0 and message[0] == "Accepted"):
        if(message[1] == "password"):
            event["authnMethod"] = "password"
        elif(len(message) > 1 and message[1] == "publickey"):
            event["authnMethod"] ="publickey"
            
        event["eventType"] = "SuccessfulLogin"
        
    elif(len(message) > 0 and message[0] == "Invalid"):
        if(message[1] == "user"):
            event["eventType"] = "InvalidUser"
    elif(len(message) > 0 and message[0] == "Connection"):
        if(len(message) > 1 and message[1] == "Opened"):
            event["eventType"] = "ConnOpen"
        elif(len(message) > 1 and message[1] == "Closed"):
            event["eventType"] = "ConnClosed"
    elif(len(message) > 0 and message[0] == "Received"):
        event["eventType"] = "ReceivedDisconnect"
        

#get the user, sourceIP and port 
    if "from" in message:
        from_index = message.index("from")
        event["sourceIP"] = message[from_index + 1]
        event["user"] = message[from_index - 1]
    elif "user" in message:
        user_index = message.index("user")
        event["user"] = message[user_index + 1]

        
        
    if "port" in message:
        port_index = message.index("port")
        event["port"] = message[port_index+1]
    return event
        
    
    