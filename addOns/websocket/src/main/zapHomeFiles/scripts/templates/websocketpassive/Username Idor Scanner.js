// This script passively scans the incoming WebSocket messages for usernames.
// Finds usernames which are hashed with one of the following encoding methods {MD2, MD5
// SHA1, SHA256, SHA384, SHA512}. The usernames have to be defined in any context.

// Based on: org.zaproxy.zap.extension.pscanrulesBeta.UsernameIdorScanner

// Author: Manos Kirtas (manolis.kirt@gmail.com)

var Model = Java.type("org.parosproxy.paros.model.Model");
var Control = Java.type("org.parosproxy.paros.control.Control");
var ExtensionUserManagement = Java.type("org.zaproxy.zap.extension.users.ExtensionUserManagement");
var DigestUtils = Java.type("org.apache.commons.codec.digest.DigestUtils");
var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');

OPCODE_TEXT = 0x1;
RISK_INFO 	= 0;
CONFIDENCE_HIGH = 3;

var extUserManagment = null;
var usersList = null;

function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing() || (usersList = getUsers()) == null){
        return;
    }
    var message = String(msg.getReadablePayload());

    usersList.forEach(function(user){

        var username = user.getName();
        var usernameHashes = getHashes(username);
        var matches;

        Object.keys(usernameHashes).forEach(function(hashType){
            if((matches = message.match(usernameHashes[hashType]))!= null) {
                var contextname = Model.getSingleton().getSession().getContext(parseInt(user.getContextId())).getName();
                matches.forEach(function(evidence){
                	raiseAlert(helper, evidence, username, contextname, hashType);
                });
            }
        });
    });
}

function raiseAlert(helper, evidence, username, contextname, hashType){
    createAlertBuilder(helper, evidence, username, contextname, hashType).raise();
}

function createAlertBuilder(helper, evidence, username, contextname, hashType){
    return helper.newAlert()
        .setPluginId(getId())
        .setRiskConfidence(RISK_INFO, CONFIDENCE_HIGH)
        .setName("Username Hash Found in WebSocket message")
        .setDescription(getDescription(username, contextname, hashType))
        .setSolution("Use per user or session indirect object references (create a temporary mapping at time of use)."
                     + " Or, ensure that each use of a direct object reference is tied to an authorization check to ensure the"
                     + " user is authorized for the requested object.")
        .setReference("https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html\n"
                      + "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References")
        .setEvidence(evidence)
        .setCweId(284) // CWE-284: Improper Access Control
        .setWascId(2); // WASC-2: Insufficient Authorization
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
    if(( extUserManagment = getExtensionUserManagment()) != null){
        usersList  = [];
        var contexts = Model.getSingleton().getSession().getContexts();
        var context;

        for(var i = 0; i < contexts.size(); i++){
            context = contexts.get(i);
            var contextUsers = extUserManagment.getContextUserAuthManager(context.getIndex()).getUsers();
            if(contextUsers.size() > 0){
                for(var j = 0; j < contextUsers.size(); j++ ){
                    usersList.push(contextUsers.get(j));
                }
            }
        }
    }
    return usersList;
}

function getExtensionUserManagment(){
    if(extUserManagment == null){
        extUserManagment = Control.getSingleton()
            .getExtensionLoader()
            .getExtension(ExtensionUserManagement.class);
    }
    return extUserManagment;
}

function getName(){
    return "Username Disclosure script";
}

function getId(){
    return 110007;
}
