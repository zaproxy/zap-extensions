// This script scans websocket messages for private IP V4 addresses as well as Amazon EC2 private hostnames
// Private IP V4 such as: 10.x.x.x, 172.x.x.x, 192.168.x.x
// Amazon EC2 private hostname: such as ip-10-0-56-78

// * This Passive Scan base on http passive scan plugin:
// ** org.zaproxy.zap.extension.pscanrules.TestInfoPrivateAddressDisclosure

// * Regex test: https://regex101.com/r/SztaPj/2/

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_LOW 	= 1;
CONFIDENCE_MEDIUM = 2;

REGULAR_IP_OCTET = "(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})";
REGULAR_PORTS = "(:(0|[1-9]\\d{0,3}|[1-5]\\d{4}|6[0-4]\\d{3}|65([0-4]\\d{2}|5[0-2]\\d|53[0-5]))\\b)?";

var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');

var patternPre = [];

/** Pattern for private IP V4 addresses as well as Amazon EC2 private hostnames */
patternPre.push(
    "(",
    "\\b10\\.(",
    REGULAR_IP_OCTET,
    "\\.){2}",
    REGULAR_IP_OCTET,
    "\\b|",
    "\\b172\\.",
    "(3[01]|2[0-9]|1[6-9])\\.",
    REGULAR_IP_OCTET,
    "\\.",
    REGULAR_IP_OCTET,
    "\\b|",
    "\\b192\\.168\\.",
    REGULAR_IP_OCTET,
    "\\.",
    REGULAR_IP_OCTET,
    "\\b|",
    // find IPs from AWS hostnames such as "ip-10-2-3-200"
    "\\bip-10-(",
    REGULAR_IP_OCTET,
    "-){2}",
    REGULAR_IP_OCTET,
    "\\b|",
    "\\bip-172-",
    "(3[01]|2[0-9]|1[6-9])-",
    REGULAR_IP_OCTET,
    "-",
    REGULAR_IP_OCTET,
    "\\b|",
    "\\bip-192-168-",
    REGULAR_IP_OCTET,
    "-",
    REGULAR_IP_OCTET,
    "\\b)",
    REGULAR_PORTS
);

function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()){
        return;
    }
    var ipRegex = new RegExp(patternPre.join(""),"gim");
    var message = String(msg.getReadablePayload());
    var matches;

    if((matches = message.match(ipRegex)) != null){

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
        .setRiskConfidence(RISK_LOW, CONFIDENCE_MEDIUM)
        .setName("Private IP Disclosure via WebSocket")
        .setDescription("A private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x)\
 or an Amazon EC2 private hostname (for example, ip-10-0-56-78) has been found in the incoming\
 WebSocket message. This information might be helpful for further attacks targeting\
 internal systems.")
        .setSolution("Remove the private IP address from the WebSocket messages.")
        .setReference("https://tools.ietf.org/html/rfc1918")
        .setEvidence(evidence);
}

function getExampleAlerts(){
    return [createAlertBuilder(WebSocketPassiveScript.getExampleHelper(), "").build().getAlert()];
}

function getName(){
    return "Private IP Disclosure script";
}

function getId(){
    return 110006;
}
