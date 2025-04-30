// * This Script analyzes incoming websocket messages for error debug messages

// * Based on org.zaproxy.zap.extension.pscanrules.InformationDisclosureDebugErrors
// * Debug Error messages are equal to:
// * * https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/zapHomeFiles/xml/debug-error-messages.txt

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_LOW = 1;
CONFIDENCE_MEDIUM = 2;

var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');

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

    debug_messages.forEach(function(pattern){
        if((matches = message.match(pattern)) != null){
            matches.forEach(function(evidence){
                raiseAlert(helper, evidence);
            });
        }
    });
}

function raiseAlert(helper, evidence){
    createAlertBuilder(helper, evidence).raise();
}

function createAlertBuilder(helper, evidence){
    return helper.newAlert()
        .setPluginId(getId())
        .setName("Information Disclosure - Debug Error Messages via WebSocket")
        .setRiskConfidence(RISK_LOW, CONFIDENCE_MEDIUM)
        .setDescription("The response appeared to contain common error messages returned"
                        + " by platforms such as ASP.NET, and Web-servers such as IIS and Apache. You can configure"
                        + " the list of common debug messages.")
        .setSolution("Disable debugging messages before pushing to production.")
        .setEvidence(evidence)
        .setCweId(200) // CWE-200: Information Exposure
        .setWascId(13); // WASC Id 13 - Info leakage
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
