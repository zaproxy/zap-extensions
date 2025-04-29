// * This Script analyzes incoming websocket messages for error debug messages

// * Based on org.zaproxy.zap.extension.pscanrules.InformationDisclosureDebugErrors
// * Debug Error messages are equal to:
// * * https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/zapHomeFiles/xml/debug-error-messages.txt

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_LOW = 1;
CONFIDENCE_MEDIUM = 2;

var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');
var ScanRuleMetadata = Java.type(
    "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);
function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
  id: 110003
  name: Information Disclosure - Debug Error Messages via WebSocket
  description: >
    The response appeared to contain common error messages returned by platforms such as ASP.NET, and Web-servers such as IIS and Apache.
    You can configure the list of common debug messages.
  solution: >
    Disable debugging messages before pushing to production.
  risk: low
  confidence: medium
  cweId: 200
  wascId: 13 
  status: release
  codeLink: https://github.com/zaproxy/zap-extensions/blob/main/addOns/websocket/src/main/zapHomeFiles/scripts/templates/websocketpassive/Debug%20Error%20Disclosure.js
  `);
  }
var debug_messages = [
    /Error Occurred While Processing Request/igm,
    /Internal Server Error/igm,
    /test page for apache/igm,
    /failed to open stream: HTTP request failed!/igm,
    /Parse error: parse error, unexpected T_VARIABLE/igm,
    /The script whose uid is/igm,
    /PHP Parse error/igm,
    /PHP Warning/igm,
    /PHP Error/igm,
    /Warning: Cannot modify header information - headers already sent/igm,
    /mysqli error is/igm,
    /mysql error is/igm,
    /404 SC_NOT_FOUND/igm,
    /ASP.NET_SessionId/igm,
    /servlet error:/igm,
    /Under construction/igm,
    /Welcome to Windows 2000 Internet Services/igm,
    /welcome to iis 4.0/igm,
    /Warning: Supplied argument is not a valid File-Handle resource/igm,
    /Warning: Division by zero in/igm,
    /Warning: SAFE MODE Restriction in effect./igm,
    /Error Message : Error loading required libraries./igm,
    /Fatal error: Call to undefined function/igm,
    /access denied for user/igm,
    /incorrect syntax near/igm,
    /Unclosed quotation mark before the character string/igm,
    /There seems to have been a problem with the/igm,
    /customErrors mode/igm,
    /This error page might contain sensitive information because ASP.NET/igm
];

function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()){
        return;
    }
    var message = String(msg.getReadablePayload());
    var matches;
    var found = [];

    debug_messages.forEach(function(pattern){
        if((matches = message.match(pattern)) != null){
            matches.forEach(function(evidence){
                found.push(evidence);
            });
        }
    });

    if (found.length > 0) {
        const otherInfo = found.length > 1 ? `Other instances: ${found.slice(1).toString()}` : "";
        createAlertBuilder(helper, found[0], otherInfo, msg).raise();
    }
}

function createAlertBuilder(helper, evidence, otherInfo, msg){
    return helper.newAlert()
        .setEvidence(evidence)
        .setOtherInfo(otherInfo)
        .setMessage(msg)
}

function getExampleAlerts(){
    return [createAlertBuilder(WebSocketPassiveScript.getExampleHelper(), "").build().getAlert()];
}

function getName(){
    return "Debug Error Disclosure script";
}

function getId(){
    return 110003;
}
