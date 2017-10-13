
OLD_STRING = "00.000.000/0000-00";
NEW_STRING = "88.888.888/8888-88";

def sendingRequest(msg, initiator, helper): 
    global OLD_STRING;
    global NEW_STRING;

    body = msg.getRequestBody().toString();
    newbody = body.replace(OLD_STRING, NEW_STRING);
    msg.setRequestBody(newbody);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());



def responseReceived(msg, initiator, helper): 
    pass;


