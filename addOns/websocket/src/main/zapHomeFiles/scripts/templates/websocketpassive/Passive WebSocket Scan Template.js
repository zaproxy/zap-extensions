// Passive scan rules should not send messages
// Right click the script in the Scripts tree and select "enable"  or "disable"

OPCODE_CONTINUATION = 0x0;
OPCODE_TEXT = 0x1;
OPCODE_BINARY = 0x2;
OPCODE_CLOSE = 0x8;
OPCODE_PING = 0x9;
OPCODE_PONG = 0xA;

RISK_INFO = 0;
RISK_LOW = 1;
RISK_MEDIUM = 2;
RISK_HIGH = 3;

CONFIDENCE_LOW = 1;
CONFIDENCE_MEDIUM = 2;
CONFIDENCE_HIGH = 3;

/**
 * This function scans passively WebSocket messages. The scan function will be called for
 * messages via ZAP.
 *
 * @param helper - the WebSocketPassiveHelper interface provides the newAlert() method in order
 *                 to raise the appropriate alerts
 *
 * Some useful function(s) about  WebSocketPassiveHelper:
 * helper.newAlert() -> Returns an WebSocketAlertRaiser instance which is used
 *                      for building and raising alerts.

 * * Some useful functions about WebSocketAlertRaiser:
 * * alertRaiser.setRiskConfidence(risk, confidence) -> Sets the Risk and the Confidence of the alert. (by default RISK_INFO, CONFIDENCE_MEDIUM).
 * * alertRaiser.setName(name)                       -> Sets the name (by default "").
 * * alertRaiser.setDescription(description)         -> Sets a description about potential threat (by default "").
 * * alertRaiser.setParam(param)                     -> Sets in which parameter threat is noticed (by default "").
 * * alertRaiser.setSolution(solution)               -> Sets a possible solution (by default "").
 * * alertRaiser.setReference(reference)             -> Sets extra references (ex. a web link) (by default "").
 * * alertRaiser.setEvidence(evidence)               -> Sets what's the evidence of potential thread (by default "").
 * * alertRaiser.setCweId(cweId)                    -> Sets the CWE ID of the issue (by default 0)
 * * alertRaiser.setWascId(wascId)                   -> Sets the WASC ID of the issue (by default 0)
 * * alertRaiser.raise()                             -> Build and Raise the alert (returns the WebSocketAlertWrapper)

 * @param msg - the Websocket Message being scanned. This is a WebSocketMessageDTO object.
 *
 * Some useful functions and fields of WebSocketMessageDTO:
 * msg.channel        -> Channel of the message (WebSocketChannelDTO)
 * msg.id             -> Unique ID of the message (int)
 * msg.opcode         -> Opcode of the message (int) (Opcodes defined bellow)
 * msg.readableOpcode -> Textual representation of opcode (String)
 * msg.isOutgoing     -> Outgoing or incoming message (boolean)
 * msg.getReadablePayload() -> Return readable representation of payload
 *
 * * Some useful functions and fields of WebSocketChannelDTO:
 * * channel.id         -> Unique ID of the message (int)
 * * channel.host       -> Host of the WebSocket Server (String)
 * * channel.port       -> Port where the channel is connected at. Usually at 80 or 443.
 * * channel.url        -> URL used in HTTP handshake (String).
 */
function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()){
        return;
    }

    // Test the request or response here
    print(msg.getReadablePayload());

    if(true){
        helper.newAlert()
            .setRiskConfidence(RISK_INFO, CONFIDENCE_LOW)
            .setName("Name of the alert")
            .setDescription("Description of the Alert.")
            .setParam("Parameter of the Alert.")
            .setSolution("Solution of the Alert.")
            .setReference("Reference of the Alert.")
            .setEvidence("Evidence of the Alert")
            .setCweId(0)
            .setWascId(0)
            .raise();
    }
}

