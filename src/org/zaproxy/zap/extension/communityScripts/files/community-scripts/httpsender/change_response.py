
OLD_STRING = "display:none;";
NEW_STRING = "";

def sendingRequest(msg, initiator, helper): 
    pass;



def responseReceived(msg, initiator, helper): 
    global OLD_STRING;
    global NEW_STRING;

    body = msg.getResponseBody().toString();
    newbody = body.replace(OLD_STRING, NEW_STRING);
    msg.setResponseBody(newbody);
    msg.getResponseHeader().setContentLength(msg.getResponseBody().length())


