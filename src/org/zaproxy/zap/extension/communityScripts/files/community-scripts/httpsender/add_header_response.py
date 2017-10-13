
headers = dict({"Content-Type": "text/plain"});

def sendingRequest(msg, initiator, helper): 
    pass;


def responseReceived(msg, initiator, helper): 
    for x in list(headers):
      msg.getResponseHeader().setHeader(x, headers[x]);


