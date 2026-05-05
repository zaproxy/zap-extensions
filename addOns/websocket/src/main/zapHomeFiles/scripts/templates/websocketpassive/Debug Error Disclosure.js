// * This Script analyzes incoming websocket messages for error debug messages

// * Based on org.zaproxy.zap.extension.pscanrules.InformationDisclosureDebugErrors
// * Debug Error messages are equal to:
// * * https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/zapHomeFiles/xml/debug-error-messages.txt

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_LOW = 1;
CONFIDENCE_MEDIUM = 2;

var WebSocketPassiveScript = Java.type(
  "org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript",
);

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
  return helper
    .newAlert()
    .setPluginId(getId())
    .setName("Information Disclosure - Debug Error Messages via WebSocket")
    .setRiskConfidence(RISK_LOW, CONFIDENCE_MEDIUM)
    .setDescription(
      "The response appeared to contain common error messages returned" +
        " by platforms such as ASP.NET, and Web-servers such as IIS and Apache. You can configure" +
        " the list of common debug messages.",
    )
    .setSolution("Disable debugging messages before pushing to production.")
    .setEvidence(evidence)
    .setCweId(209) // Information Exposure Through an Error Message
    .setWascId(13); // WASC Id 13 - Info leakage
}

function getExampleAlerts() {
  return [
    createAlertBuilder(WebSocketPassiveScript.getExampleHelper(), "")
      .build()
      .getAlert(),
  ];
}

function getName() {
  return "Debug Error Disclosure script";
}

function getId() {
  return 110003;
}
