// This Script checks incoming WebSocket XML formatted messages for suspicious comments.

// * Is based on: org.zaproxy.zap.extension.pscanrulesBeta.InformationDisclosureSuspiciousComments
// ** And the comment list is copied from
// *** https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrulesBeta/src/main/zapHomeFiles/xml/suspicious-comments.txt

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_INFO 	= 0;
CONFIDENCE_MEDIUM = 2;

var XmlUtils = Java.type("org.zaproxy.zap.utils.XmlUtils");
var StringReader = Java.type("java.io.StringReader");
var InputSource = Java.type("org.xml.sax.InputSource");
var Node = Java.type("org.w3c.dom.Node");
var Comment = Java.type("org.w3c.dom.Comment");
var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');
var ScanRuleMetadata = Java.type(
    "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
  id: 110008
  name: Information Disclosure - Suspicious Comments in XML via WebSocket
  description: >
    The response appears to contain suspicious comments which may help an attacker. 
  solution: >
    Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.
  risk: informational
  confidence: medium
  cweId: 200
  wascId: 13
  status: release
  codeLink: https://github.com/zaproxy/zap-extensions/blob/main/addOns/websocket/src/main/zapHomeFiles/scripts/templates/websocketpassive/XML%20Comments%20Disclosure.js
  `);
}
var commentPatterns = [/\bTODO\b/gmi,
                  /\bFIXME\b/gmi,
                  /\bBUG\b/gmi,
                  /\bBUGS\b/gmi,
                  /\bXXX\b/gmi,
                  /\bQUERY\b/gmi,
                  /\bDB\b/gmi,
                  /\bADMIN\b/gmi,
                  /\bADMINISTRATOR\b/gmi,
                  /\bUSER\b/gmi,
                  /\bUSERNAME\b/gmi,
                  /\bSELECT\b/gmi,
                  /\bWHERE\b/gmi,
                  /\bFROM\b/gmi,
                  /\bLATER\b/gmi
                ];

function scan(helper,msg) {

    if(msg.getOpcode()!= OPCODE_TEXT || msg.isOutgoing()){
        return;
    }

    var message = String(msg.getReadablePayload());
    var xmlDoc = getParsedDocument(message);

    if(xmlDoc == null){
        return;
    }
    var commentsList = [];
    getComments(xmlDoc.getDocumentElement(), commentsList);

    var found = [];
    commentsList.forEach(function(comment){
        commentPatterns.forEach(function(pattern){
            if(pattern.test(comment)){
                found.push(comment);
            }
        });
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

function getComments(node, commentsList){
	  var nodeList = node.getChildNodes();
    for(var i = 0; i < nodeList.getLength(); i++){
        var currentNode = nodeList.item(i);
        if(currentNode.getNodeType() == Node.COMMENT_NODE){
            commentsList.push(String(currentNode.getNodeValue()));
        }
        if (currentNode.hasChildNodes()) {
            getComments(currentNode, commentsList);
        }
    }
}

function getParsedDocument(message){
    var result = null;
    var factory = XmlUtils.newXxeDisabledDocumentBuilderFactory();
    factory.setIgnoringComments(false);
    var builder = factory.newDocumentBuilder();
    var is = new InputSource(new StringReader(message));
    try{
        result = builder.parse(is);
    }catch(error){
        result = null;
    }
    return result;
}

function getName(){
    return "Suspicious XML Comments Disclosure script";
}

function getId(){
    return 110008;
}
