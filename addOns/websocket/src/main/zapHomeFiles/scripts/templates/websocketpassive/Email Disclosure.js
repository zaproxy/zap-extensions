// This script scans incoming WebSocket messages for email address.

// * Author: Manos Kirtas (Manos Kirtas)
// * Based on: community-scripts/passive/Find Emails.js

OPCODE_TEXT = 0x1;
RISK_INFO = 0;
CONFIDENCE_HIGH = 3;

var emailRegex = new RegExp("([a-z0-9_.+-]+@[a-z0-9]+[a-z0-9-]*\.[a-z0-9-.]*[a-z0-9]{2,})", 'gmi');

function scan(helper,msg) {

    if(msg.opcode != OPCODE_TEXT || msg.isOutgoing){
        return;
    }
    var message = String(msg.getReadablePayload());
    var matches;

    if((matches = message.match(emailRegex)) != null) {
        matches.forEach(function(evidence){
            helper.newAlert()
                .setRiskConfidence(RISK_INFO, CONFIDENCE_HIGH)
                .setName("Email address found in WebSocket message (script).")
                .setDescription("An email address was found in a WebSocket Message.")
                .setSolution("Remove emails that are not public.")
                .setEvidence(evidence)
                .setCweId(200) //Information Exposure
                .setWascId(13) // Information Leakage
                .raise();
        });
    }
}

function getName(){
    return "Email Disclosure script";
}

function getId(){
    return 110004;
}
