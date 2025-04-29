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
var ScanRuleMetadata = Java.type(
    "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);
function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
  id: 110002
  name: Base64 Disclosure in WebSocket message
  description: >
    A Base64-encoded string has been found in the WebSocket incoming message. Base64-encoded data may contain sensitive information such as usernames, passwords, or cookies which should be further inspected. 
  solution: >
    Base64-encoding should not be used to store or send sensitive information. Always use proper encryption or hashing mechanisms to protect sensitive data.
  risk: informational
  confidence: medium
  status: release
  codeLink: https://github.com/zaproxy/zap-extensions/blob/main/addOns/websocket/src/main/zapHomeFiles/scripts/templates/websocketpassive/Base64%20Disclosure.js
  `);
  }
  
var base64Regex = /((?:[A-Za-z0-9+\/]{4}\n?)*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=))/gmi;

base64Decoder = java.util.Base64.getDecoder();
JavaString = Java.type("java.lang.String");

function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()){
        return;
    }
    var message = String(msg.getReadablePayload());
    var matches;
    var found = [];

    if( (matches = message.match(base64Regex)) != null ){
        matches.forEach(function(evidence){
            found.push(evidence);
        });
    }

    if (found.length > 0) {
        const otherInfo = found.length > 1 ? `Other instances: ${found.slice(1).toString()}` : "";
        createAlertBuilder(helper, found[0], otherInfo, msg).raise();
    }
}

function createAlertBuilder(helper, evidence, otherInfo, msg){
    return helper.newAlert()
        .setEvidence(evidence)
        .setOtherInfo(otherInfo)
        .setMessage(msg);
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
