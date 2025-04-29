// This script passively scans the incoming WebSocket messages for usernames.
// Finds usernames which are hashed with one of the following encoding methods {MD2, MD5
// SHA1, SHA256, SHA384, SHA512}. The usernames have to be defined in any context.

// Based on: org.zaproxy.zap.extension.pscanrulesBeta.UsernameIdorScanner

// Author: Manos Kirtas (manolis.kirt@gmail.com)

var ExtensionUserManagement = Java.type("org.zaproxy.zap.extension.users.ExtensionUserManagement");
var DigestUtils = Java.type("org.apache.commons.codec.digest.DigestUtils");
var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');
var ScanRuleMetadata = Java.type(
    "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
  id: 110007
  name: Username Hash Found in WebSocket message
  description: >
    A hash of a user identifier and context was found in the incoming WebSocket message.
    This may indicate that the application is subject to an Insecure Direct Object Reference (IDOR) vulnerability.
    Manual testing will be required to see if this discovery can be abused. 
  solution: >
    Use per-user or session indirect object references by creating a temporary mapping at the time of use, 
    or ensure that each use of a direct object reference is tied to an authorization check 
    to verify that the user is authorized for the requested object.
  risk: informational
  confidence: high
  cweId: 284
  wascId: 2
  status: release
  references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
  - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
  codeLink: https://github.com/zaproxy/zap-extensions/blob/main/addOns/websocket/src/main/zapHomeFiles/scripts/templates/websocketpassive/Username%20Idor%20Scanner.js
  `);
}
OPCODE_TEXT = 0x1;
RISK_INFO 	= 0;
CONFIDENCE_HIGH = 3;

var extUserManagement = null;
var usersList = null;

function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing() || (usersList = getUsers()) == null){
        return;
    }
    var message = String(msg.getReadablePayload());
    var found = [];

    usersList.forEach(function(user){

        var usernameHashes = getHashes(user.getName());
        var matches;

        Object.keys(usernameHashes).forEach(function(hashType){
            if((matches = message.match(usernameHashes[hashType])) != null) {
                matches.forEach(function(evidence){
                    found.push({evidence});
                });
            }
        });
    });

    if (found.length > 0) {
        const otherInfo = found.length > 1 ? `Other instances: ${found.slice(1).map(f => f.evidence).toString()}` : "";
        createAlertBuilder(helper, found[0].evidence, otherInfo, msg).raise();
    }
}

function createAlertBuilder(helper, evidence, otherInfo, msg){
    return helper.newAlert()
        .setEvidence(evidence)
        .setOtherInfo(otherInfo)
        .setMessage(msg)
}

function getExampleAlerts(){
    return [createAlertBuilder(WebSocketPassiveScript.getExampleHelper(), "", "Example", "Example", "Example").build().getAlert()];
}

function getDescription(username, contextname, hashType){
    return "A " + hashType + " hash of {" + username + " / context: " + contextname + "} was found in incoming WebSocket message."
        +" This may indicate that the application is subject to an Insecure Direct Object"
        +" Reference (IDOR) vulnerability. Manual testing will be required to see if this"
        +" discovery can be abused.";
}

function getHashes(username){
    var usernameHashes = {};
    usernameHashes['MD2'] = new RegExp(DigestUtils.md2Hex(username), 'gmi');
    usernameHashes['MD5'] = new RegExp(DigestUtils.md5Hex(username), 'gmi');
    usernameHashes['SHA1'] = new RegExp(DigestUtils.sha1Hex(username), 'gmi');
    usernameHashes['SHA256'] = new RegExp(DigestUtils.sha256Hex(username), 'gmi');
    usernameHashes['SHA384'] = new RegExp(DigestUtils.sha384Hex(username), 'gmi');
    usernameHashes['SHA512'] = new RegExp(DigestUtils.sha512Hex(username), 'gmi');

    return usernameHashes;
}

function getUsers(){
    if(( extUserManagement = getExtensionUserManagement()) != null){
        usersList  = [];
        var contexts = model.getSession().getContexts();
        var context;

        for(var i = 0; i < contexts.size(); i++){
            context = contexts.get(i);
            var contextUsers = extUserManagement.getContextUserAuthManager(context.getIndex()).getUsers();
            if(contextUsers.size() > 0){
                for(var j = 0; j < contextUsers.size(); j++ ){
                    usersList.push(contextUsers.get(j));
                }
            }
        }
    }
    return usersList;
}

function getExtensionUserManagement(){
    if(extUserManagement == null){
        extUserManagement = control.getExtensionLoader().getExtension(ExtensionUserManagement.class);
    }
    return extUserManagement;
}

function getName(){
    return "Username Disclosure script";
}

function getId(){
    return 110007;
}
