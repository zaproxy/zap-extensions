// This script scans for the presence of Personally Information Identifiable in incoming WebSocket Messages.
// More specifically, it passively scans messages for credit card numbers

// * This script is based on org.zaproxy.zap.extension.pscanrulesAlpha.Piicanner

// * Regex: https://regex101.com/r/RBY77J/3

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_HIGH 	= 3;
CONFIDENCE_HIGH = 3;

SEQUENCE_NUM = 3;

var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');
var ScanRuleMetadata = Java.type(
    "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
  id: 110005
  name: Personally Identifiable Information via WebSocket
  description: >
    The response contains Personally Identifiable Information, such as CC number.
  risk: high
  confidence: high
  cweId: 359
  wascId: 13 
  status: release
  codeLink: https://github.com/zaproxy/zap-extensions/blob/main/addOns/websocket/src/main/zapHomeFiles/scripts/templates/websocketpassive/PII%20Disclosure.js
  `);
}

creditCards = {
    'American Express' : /\b(?:3[47][0-9]{13})\b/gm,
    'Diners Club' :  /\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\b/gm,
    'Discover' : /\b(?:6(?:011|5[0-9]{2})(?:[0-9]{12}))\b/gm,
    'Jcb' : /\b(?:(?:2131|1800|35\d{3})\d{11})\b/gm,
    'Maestro' : /\b(?:(?:5[0678]\d\d|6304|6390|67\d\d)\d{8,15})\b/gm,
    'Master Card' : /\b(?:(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12})\b/gm,
    'Visa' : /\b(?:4[0-9]{12})(?:[0-9]{3})?\b/gm
};

function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()){
        return;
    }
    var message = String(msg.getReadablePayload());
    var numberSequences = getNumberOfSequence(message,SEQUENCE_NUM);
    var matches;
    var foundMatches = [];  

    numberSequences.forEach(function(sequence){
        Object.keys(creditCards).forEach(function(creditCardType){

            if((matches = sequence.match(creditCards[creditCardType])) != null){
                matches.forEach(function(match){
                    if(validateLuhnCheckSum(match)){
                        foundMatches.push(match);  
                    }
                });
            }
        });
    });

    if (foundMatches.length > 0) {
        const otherInfo = foundMatches.length > 1 ? `Other instances: ${foundMatches.slice(1).toString()}` : "";
        createAlertBuilder(helper, foundMatches[0], otherInfo, msg).raise();
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

function getNumberOfSequence(inputString, seqNum){
    var numSeqRegex = new RegExp("(?:\\d{" + seqNum + ",}[\\s]*)+",'g'); // Return any sequence of numbers equal or greater than seqNum
    var whitespaces = /\s+/g;
    var newNumSeq = [];
    var matches;

    if( (matches = inputString.match(numSeqRegex)) != null){
        matches.forEach(function(seq){
            newNumSeq.push(seq.replace(whitespaces, "", "Example")); // Replace any whitespace with empty string
        });
    }
    return newNumSeq;
}

function validateLuhnCheckSum(match){
    var sum = 0;
    var parity = match.length % 2;

    for(var i = 0; i < match.length; i++){
        var digit = parseInt(match[i]);

        if(i % 2 == parity){
            digit *= 2;
            if(digit > 9){
                digit -= 9;
            }
        }
        sum += digit;
    }
    return (sum % 2) == 0;
}


function getName(){
    return "Credit Card Disclosure script";
}

function getId(){
    return 110005;
}
