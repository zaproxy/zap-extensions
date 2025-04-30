// This script scans incoming WebSocket messages for email address.

// * Author: Manos Kirtas (Manos Kirtas)
// * Based on: community-scripts/passive/Find Emails.js

OPCODE_TEXT = 0x1;
RISK_INFO = 0;
CONFIDENCE_HIGH = 3;

var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');

var emailRegex = new RegExp("([a-z0-9_.+-]+@[a-z0-9]+[a-z0-9-]*\.[a-z0-9-.]*[a-z0-9]{2,})", 'gmi');

function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()){
        return;
    }
    var message = String(msg.getReadablePayload());
    var matches;

    if((matches = message.match(emailRegex)) != null) {
        matches.forEach(function(evidence){
            raiseAlert(helper, evidence);
        });
    }
}

function raiseAlert(helper, evidence){
    createAlertBuilder(helper, evidence).raise();
}

function createAlertBuilder(helper, evidence){
    return helper.newAlert()
        .setPluginId(getId())
        .setRiskConfidence(RISK_INFO, CONFIDENCE_HIGH)
        .setName("Email address found in WebSocket message")
        .setDescription("An email address was found in a WebSocket Message.")
        .setSolution("Remove emails that are not public.")
        .setEvidence(evidence)
        .setCweId(200) //Information Exposure
        .setWascId(13); // Information Leakage
}

function getExampleAlerts(){
    return [createAlertBuilder(WebSocketPassiveScript.getExampleHelper(), "").build().getAlert()];
}

function getName(){
    return "Email Disclosure script";
}

function getId(){
    return 110004;
}
