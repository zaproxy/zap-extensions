# Auxiliary variables/constants needed for processing.
http_status_code = 401;

# Called after injecting the payloads and before forward the message to the server.
def processMessage(utils, message) :
    pass;

# Called after receiving the fuzzed message from the server
def processResult(utils, fuzzResult) :
    global http_status_code;

    if(fuzzResult.getHttpMessage().getResponseHeader().getStatusCode() == http_status_code):
        return bool(0);
    
    # Returns true to accept the result, false to discard and not show it
    return bool(1);


