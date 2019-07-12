// This script passively scans the incoming WebSocket messages for usernames.
// Finds usernames which are hashed with one of the following encoding methods {MD2, MD5
// SHA1, SHA256, SHA384, SHA512}. The usernames have to be defined in any context.

// Based on: org.zaproxy.zap.extension.pscanrulesBeta.UsernameIdorScanner

// Author: Manos Kirtas (manolis.kirt@gmail.com)

var Model = Java.type("org.parosproxy.paros.model.Model");
var Control = Java.type("org.parosproxy.paros.control.Control");
var ExtensionUserManagement = Java.type("org.zaproxy.zap.extension.users.ExtensionUserManagement");
var DigestUtils = Java.type("org.apache.commons.codec.digest.DigestUtils");

OPCODE_TEXT = 0x1;
RISK_INFO 	= 0;
CONFIDENCE_HIGH = 3;

var extUserManagment = null;
var usersList = null;

function scan(helper,msg) {

    if(msg.opcode != OPCODE_TEXT || msg.isOutgoing || (usersList = getUsers()) == null){
        return;
    }
    var message = String(msg.getReadablePayload());

    usersList.forEach(function(user){

        var username = user.getName();
        var usernameHashes = getHashes(username);
        var matches;

        Object.keys(usernameHashes).forEach(function(hashType){
            if((matches = message.match(usernameHashes[hashType]))!= null) {
                matches.forEach(function(evidence){
                    helper.newAlert()
                        .setRiskConfidence(RISK_INFO, CONFIDENCE_HIGH)
                        .setName("Username Hash Found in WebSocket message (script)")
                        .setDescription(getDescription(user, hashType))
                        .setSolution("Use per user or session indirect object references (create a temporary mapping at time of use)."
                                     + " Or, ensure that each use of a direct object reference is tied to an authorization check to ensure the"
                                     + " user is authorized for the requested object.")
                        .setReference("https://www.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References\n"
                                      + "https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004)")
                        .setEvidence(evidence)
                        .setCweId(284) // CWE-284: Improper Access Control
                        .setWascId(2) // WASC-2: Insufficient Authorization
                        .raise();
                });
            }
        });
    });
}

function getDescription(user, hashType){
    var username = user.getName();
    var context = Model.getSingleton().getSession().getContext(parseInt(user.getContextId())).getName();
    return "A " + hashType + " hash of {" + username + " / context: " + context + "} was found in incoming WebSocket message."
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
