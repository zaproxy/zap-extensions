// * This script analyzes incoming websocket messages for base64 strings.

// * Regex Test: https://regex101.com/r/OOElRY/3
// ** Forked by: https://regex101.com/library/dS0sM8

// Author: Manos Kirtas (manolis.kirt@gmail.com)

// Passive scan rules should not send messages
// Right click the script in the Scripts tree and select "enable"  or "disable"

OPCODE_TEXT = 0x1;
RISK_INFO = 0;
CONFIDENCE_MEDIUM = 2;

PRINT_RESULTS = false;

var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');

var base64Regex = /((?:[A-Za-z0-9+\/]{4}\n?)*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=))/gmi;

base64Decoder = java.util.Base64.getDecoder();
JavaString = Java.type("java.lang.String");

function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()){
        return;
    }
    var message = String(msg.getReadablePayload());
    var matches;

    if( (matches = message.match(base64Regex)) != null ){
        matches.forEach(function(evidence){

            var decodedEvidence = new JavaString(base64Decoder.decode(evidence));
            if(PRINT_RESULTS){
                print("Message: " + message);
                print("Evidence: " + evidence);
                print("Decoded Evidence: " + decodedEvidence);
            }

            raiseAlert(helper, evidence, decodedEvidence);
        });
    }
}

function raiseAlert(helper, evidence, decodedEvidence){
    createAlertBuilder(helper, evidence, decodedEvidence).raise();
}

function createAlertBuilder(helper, evidence, decodedEvidence){
    return helper.newAlert()
        .setPluginId(getId())
        .setRiskConfidence(RISK_INFO, CONFIDENCE_MEDIUM)
        .setName("Base64 Disclosure in WebSocket message")
        .setDescription("A Base64-encoded string has been found in the websocket incoming message. Base64-encoded data may contain sensitive " +
                        "information such as usernames, passwords or cookies which should be further inspected. Decoded evidence: "
                        + decodedEvidence + ".")
        .setSolution("Base64-encoding should not be used to store or send sensitive information.")
        .setEvidence(evidence);
}

function getExampleAlerts(){
    return [createAlertBuilder(WebSocketPassiveScript.getExampleHelper(), "example", "example").build().getAlert()];
}

function getName(){
    return "Base64 Disclosure script";
}

function getId(){
    return 110002;
}
