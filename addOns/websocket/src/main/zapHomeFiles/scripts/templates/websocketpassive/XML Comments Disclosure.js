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

    commentsList.forEach(function(comment){
        commentPatterns.forEach(function(pattern){
            if(pattern.test(comment)){
                raiseAlert(helper, comment);
            }
        });
    });
}

function raiseAlert(helper, evidence){
    createAlertBuilder(helper, evidence).raise();
}

function createAlertBuilder(helper, evidence){
    return helper.newAlert()
        .setPluginId(getId())
        .setRiskConfidence(RISK_INFO, CONFIDENCE_MEDIUM)
        .setName("Information Disclosure - Suspicious Comments in XML via WebSocket")
        .setDescription("The response appears to contain suspicious comments which may help an attacker.")
        .setSolution("Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.")
        .setEvidence(evidence)
        .setCweId(200) //CWE Id 200 - Information Exposure
        .setWascId(13); //WASC Id 13 - Info Leakage
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
