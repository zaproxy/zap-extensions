// This script scans incoming WebSocket messages for email address.

// * Author: Manos Kirtas (Manos Kirtas)
// * Based on: community-scripts/passive/Find Emails.js

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
id: 110004
name: Email address found in WebSocket message
description: An email address was found in a WebSocket Message.
solution: Remove emails that are not public.
category: info_gather
risk: info
confidence: high
cweId: 359
wascId: 13
alertTags:
  ${CommonAlertTag.OWASP_2025_A01_BROKEN_AC.getTag()}: ${CommonAlertTag.OWASP_2025_A01_BROKEN_AC.getValue()}
  ${CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()}: ${CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue()}
  ${CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()}: ${CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue()}
  ${CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK.getTag()}: ${CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK.getValue()}
  ${CommonAlertTag.WSTG_V42_CLNT_10_WEBSOCKETS.getTag()}: ${CommonAlertTag.WSTG_V42_CLNT_10_WEBSOCKETS.getValue()}
  ${PolicyTag.PENTEST.getTag()}: ""
  ${PolicyTag.QA_STD.getTag()}: ""
status: beta
codeLink: https://github.com/zaproxy/zap-extensions/tree/main/addOns/websocket/src/main/zapHomeFiles/scripts/templates/websocketpassive/Email%20Disclosure.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/websockets/pscanrules/#id-110004
`);
}

var emailRegex = new RegExp(
  "([a-z0-9_.+-]+@[a-z0-9]+[a-z0-9-]*\.[a-z0-9-.]*[a-z0-9]{2,})",
  "gmi",
);

function scan(helper, msg) {
  if (msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()) {
    return;
  }
  var message = String(msg.getReadablePayload());
  var matches;

  if ((matches = message.match(emailRegex)) != null) {
    matches.forEach(function (evidence) {
      raiseAlert(helper, evidence);
    });
  }
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
