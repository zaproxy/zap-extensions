// * This Script analyzes incoming websocket messages for error debug messages

// * Based on org.zaproxy.zap.extension.pscanrules.InformationDisclosureDebugErrors
// * Debug Error messages are equal to:
// * * https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/zapHomeFiles/xml/debug-error-messages.txt

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;

var WebSocketPassiveScript = Java.type(
  "org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript",
);
var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata",
);
var CommonAlertTag = Java.type("org.zaproxy.addon.commonlib.CommonAlertTag");
var PolicyTag = Java.type("org.zaproxy.addon.commonlib.PolicyTag");

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 110003
name: Information Disclosure - Debug Error Messages via WebSocket
description: >-
  The response appeared to contain common error messages returned by platforms such as ASP.NET,
  and Web-servers such as IIS and Apache. You can configure the list of common debug messages.
solution: Disable debugging messages before pushing to production.
category: info_gather
risk: low
confidence: medium
cweId: 209
wascId: 13
alertTags:
  ${CommonAlertTag.OWASP_2025_A01_BROKEN_AC.getTag()}: ${CommonAlertTag.OWASP_2025_A01_BROKEN_AC.getValue()}
  ${CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()}: ${CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue()}
  ${CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()}: ${CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue()}
  ${CommonAlertTag.WSTG_V42_ERRH_01_ERR.getTag()}: ${CommonAlertTag.WSTG_V42_ERRH_01_ERR.getValue()}
  ${CommonAlertTag.WSTG_V42_CLNT_10_WEBSOCKETS.getTag()}: ${CommonAlertTag.WSTG_V42_CLNT_10_WEBSOCKETS.getValue()}
  ${PolicyTag.PENTEST.getTag()}: ""
status: beta
codeLink: https://github.com/zaproxy/zap-extensions/tree/main/addOns/websocket/src/main/zapHomeFiles/scripts/templates/websocketpassive/Debug%20Error%20Disclosure.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/websockets/pscanrules/#id-110003
`);
}

var debug_messages = [
  /Error Occurred While Processing Request/gim,
  /Internal Server Error/gim,
  /test page for apache/gim,
  /failed to open stream: HTTP request failed!/gim,
  /Parse error: parse error, unexpected T_VARIABLE/gim,
  /The script whose uid is/gim,
  /PHP Parse error/gim,
  /PHP Warning/gim,
  /PHP Error/gim,
  /Warning: Cannot modify header information - headers already sent/gim,
  /mysqli error is/gim,
  /mysql error is/gim,
  /404 SC_NOT_FOUND/gim,
  /ASP.NET_SessionId/gim,
  /servlet error:/gim,
  /Under construction/gim,
  /Welcome to Windows 2000 Internet Services/gim,
  /welcome to iis 4.0/gim,
  /Warning: Supplied argument is not a valid File-Handle resource/gim,
  /Warning: Division by zero in/gim,
  /Warning: SAFE MODE Restriction in effect./gim,
  /Error Message : Error loading required libraries./gim,
  /Fatal error: Call to undefined function/gim,
  /access denied for user/gim,
  /incorrect syntax near/gim,
  /Unclosed quotation mark before the character string/gim,
  /There seems to have been a problem with the/gim,
  /customErrors mode/gim,
  /This error page might contain sensitive information because ASP.NET/gim,
];

function scan(helper, msg) {
  if (msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()) {
    return;
  }
  var message = String(msg.getReadablePayload());
  var matches;

  debug_messages.forEach(function (pattern) {
    if ((matches = message.match(pattern)) != null) {
      matches.forEach(function (evidence) {
        raiseAlert(helper, evidence);
      });
    }
  });
}

function raiseAlert(helper, evidence) {
  createAlertBuilder(helper, evidence).raise();
}

function createAlertBuilder(helper, evidence) {
  return helper.newAlert().setEvidence(evidence);
}

function getExampleAlerts() {
  return [
    createAlertBuilder(
      WebSocketPassiveScript.getExampleHelper(getMetadata()),
      "",
    )
      .build()
      .getAlert(),
  ];
}
