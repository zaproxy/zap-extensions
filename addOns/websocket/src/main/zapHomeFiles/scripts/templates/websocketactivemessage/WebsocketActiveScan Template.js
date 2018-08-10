var PluginActiveScanner = Java.type("org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.scripts.interfaces.WebSocketActiveMessageScript");

OPCODE_CONTINUATION = 0x0;

OPCODE_TEXT = 0x1;
OPCODE_BINARY = 0x2;

OPCODE_CLOSE = 0x8;
OPCODE_PING = 0x9;
OPCODE_PONG = 0xA;

RISK_INFO 	= 0;
RISK_LOW 	= 1;
RISK_MEDIUM = 2;
RISK_HIGH 	= 3;

CONFIDENCE_LOW = 1;
CONFIDENCE_MEDIUM = 2;
CONFIDENCE_HIGH = 3;


function scan(msgNode, parentScan){
    print("Node Name: " + msgNode.getNodeName());
    parentScan.sendMessage(msgNode.getWebSocketMessageDTO());
}

function applyScan(webSocketMessageNode){
    return true;
}

function messageReceived(msg){
    print("Message Received: " + msg.getReadablePayload());
}

function connectionStateChanged(state){
    print("Connection State Changed: " + state.toString());
}