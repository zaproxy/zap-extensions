
headers = dict({"X-MIP-ACCESS-TOKEN": "XXXXXxXX-xxXX-XXXx-xxxX-XXxxXxXXxXxX",
                "X-MIP-CHANNEL": "ANDROID",
                "X-MIP-Device-Id": "1",
                "X-MIP-APP-VERSION": "1.0.1",
                "X-MIP-APP-VERSION-ID": "1"});

def sendingRequest(msg, initiator, helper): 
    for x in list(headers):
      msg.getRequestHeader().setHeader(x, headers[x]);


def responseReceived(msg, initiator, helper): 
    pass;    

