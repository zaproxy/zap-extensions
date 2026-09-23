// * This Script analyzes incoming websocket messages for error messages

// * Based on org.zaproxy.zap.extension.pscanrules.ApplicationErrorScanner
// * Application error strings are equal to:
// ** https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/resources/org/zaproxy/zap/extension/pscanrules/resources/application_errors.xml

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_MEDIUM = 2;
CONFIDENCE_MEDIUM = 2;

var WebSocketPassiveScript = Java.type(
  "org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript",
);

var microsoftDbErrors = [
  /Microsoft OLE DB Provider for ODBC Drivers/gim,
  /Microsoft OLE DB Provider for SQL Server/gim,
  /ODBC Microsoft Access Driver/gim,
  /ODBC SQL Server Driver/gim,
];

var mySqlDbErrors = [
  /supplied argument is not a valid MySQL result/gim,
  /Invalid parameter type/gim,
  /You have an error in your SQL syntax/gim,
  /Incorrect column name/gim,
  /Can't find record in/gim,
  /Unknown table/gim,
  /Incorrect column specifier for column/gim,
  /Column count doesn't match value count at row/gim,
  /Unclosed quotation mark before the character string/gim,
  /java\.lang\.NumberFormatException: For input string:/gim,
  /\): encountered SQLException \[/gim,
  /Unexpected end of command in statement \[/gim,
  /Invalid SQL:/gim,
  /ERROR: parser: parse error at or near/gim,
  /\[ODBC Informix driver\]\[Informix\]/gim,
  /\[Microsoft\]\[ODBC Microsoft Access 97 Driver\]/gim,
  /\[SQL Server Driver\]\[SQL Server\]Line 1: Incorrect syntax near/gim,
  /SQL command not properly ended/gim,
  /unexpected end of SQL command/gim,
  /Supplied argument is not a valid PostgreSQL result/gim,
  /internal error \[IBM\]\[CLI Driver\]\[DB2\/6000\]/gim,
  /Error Occurred While Processing Request/gim,
  /internal error/gim,
  /A syntax error has occurred/gim,
  /ADODB\.Field error/gim,
  /ASP\.NET is configured to show verbose error messages/gim,
  /ASP\.NET_SessionId/gim,
  /Active Server Pages error/gim,
  /An illegal character has been found in the statement/gim,
  /An unexpected token "END-OF-STATEMENT" was found/gim,
  /Can't connect to local/gim,
  /Custom Error Message/gim,
  /DB2 Driver/gim,
  /DB2 Error/gim,
  /DB2 ODBC/gim,
  /Disallowed Parent Path/gim,
  /Error Diagnostic Information/gim,
  /Error Message : Error loading required libraries\./gim,
  /Error Report/gim,
  /Error converting data type varchar to numeric/gim,
  /Internal Server Error/gim,
  /Invalid Path Character/gim,
  /Invalid procedure call or argument/gim,
  /Invision Power Board Database Error/gim,
  /JDBC Driver/gim,
  /JDBC Error/gim,
  /JDBC MySQL/gim,
  /JDBC Oracle/gim,
  /JDBC SQL/gim,
  /Microsoft VBScript compilation error/gim,
  /Microsoft VBScript error/gim,
  /MySQL Driver/gim,
  /MySQL Error/gim,
  /MySQL ODBC/gim,
  /ODBC DB2/gim,
  /ODBC Driver/gim,
  /ODBC Error/gim,
  /ODBC Oracle/gim,
  /OLE\/DB provider returned message/gim,
  /Oracle DB2/gim,
  /Oracle Driver/gim,
  /Oracle Error/gim,
  /Oracle ODBC/gim,
  /PHP Error/gim,
  /PHP Parse error/gim,
  /PHP Warning/gim,
  /Parent Directory/gim,
  /Permission denied: 'GetObject'/gim,
  /PostgreSQL query failed: ERROR: parser: parse error/gim,
  /The script whose uid is/gim,
  /Type mismatch/gim,
  /Unable to jump to row/gim,
  /Unterminated string constant/gim,
  /Warning: Cannot modify header information - headers already sent/gim,
  /Warning: Supplied argument is not a valid File-Handle resource in/gim,
  /Warning: mysql_query\(\)/gim,
  /Warning: pg_connect\(\): Unable to connect to PostgreSQL server: FATAL/gim,
  /data source=/gim,
  /invalid query/gim,
  /is not allowed to access/gim,
  /mySQL error with query/gim,
  /on MySQL result index/gim,
  /server object error/gim,
];

var regexErrors = [
  "(?i)Line\\s\\d+:\\sIncorrect\\ssyntax\\snear\\s'[^']*'",
  "(?i)pg_query\\(\\)[:]*\\squery\\sfailed:\\serror:\\s",
  "(?i)'[^']*'\\sis\\snull\\sor\\snot\\san\\sobject",
  "(?i)ORA\\-\\d{4,5}:\\s",
  "(?i)Microsoft\\sJET\\sDatabase\\sEngine\\s\\([^\\)]*\\)&lt;br&gt;Syntax\\serror(.*)\\sin\\squery\\sexpression\\s'.*\\.&lt;br&gt;&lt;b&gt;.*,\\sline\\s\\d+&lt;/b&gt;&lt;br&gt;",
  "(?i)&lt;h2&gt;\\s&lt;i&gt;Syntax\\serror\\s(\\([^\\)]*\\))?(in\\sstring)?\\sin\\squery\\sexpression\\s'[^\\.]*\\.&lt;/i&gt;\\s&lt;/h2&gt;&lt;/span&gt;",
  '(?i)&lt;font\\sface="Arial"\\ssize=2&gt;Syntax\\serror\\s(.*)?in\\squery\\sexpression\\s\'(.*)\\.&lt;/font&gt;',
  "(?i)&lt;b&gt;Warning&lt;/b&gt;:\\s\\spg_exec\\(\\)\\s\\[\\&lt;a\\shref='function.pg\\-exec\\'\\&gt;function\\.pg-exec\\&lt;/a&gt;\\]\\:\\sQuery failed:\\sERROR:\\s\\ssyntax error at or near \\&amp;quot\\;\\\\\\&amp;quot; at character \\d+ in\\s&lt;b&gt;.*&lt;/b&gt;",
  "(?i)System\\.Data\\.OleDb\\.OleDbException\\:\\sSyntax\\serror\\s\\([^)]*?\\)\\sin\\squery\\sexpression\\s.*",
  "(?i)System\\.Data\\.OleDb\\.OleDbException\\:\\sSyntax\\serror\\sin\\sstring\\sin\\squery\\sexpression\\s",
  '&lt;font style="COLOR: black; FONT: 8pt/11pt verdana"&gt;\\s+(\\[Macromedia\\]\\[SQLServer\\sJDBC\\sDriver\\]\\[SQLServer\\]|Syntax\\serror\\sin\\sstring\\sin\\squery\\sexpression\\s)',
  "(?i)The Error Occurred in &lt;b&gt;(.*): line.*&lt;\/b&gt;&lt;br&gt;",
  "(?i)The error occurred while processing.*Template: (.*) &lt;br&gt;.",
  "(?i)The error occurred while processing.*in the template file (.*)\\.&lt;\/p&gt;&lt;br&gt;",
  "(?i)&lt;span&gt;&lt;H1&gt;Server\\sError\\sin\\s'[^']*'\\sApplication\\.&lt;hr\\swidth=100%\\ssize=1\\scolor=silver&gt;&lt;/H1&gt;",
  "(?i)&lt;title&gt;Invalid\\sfile\\sname\\sfor\\smonitoring:\\s'([^']*)'\\.\\sFile\\snames\\sfor\\smonitoring\\smust\\shave\\sabsolute\\spaths\\,\\sand\\sno\\swildcards\\.&lt;/title&gt;",
  "(?i)&lt;b&gt;(Warning|Fatal\\serror|Parse\\serror)&lt;/b&gt;:\\s+.*?\\sin\\s&lt;b&gt;.*?&lt;/b&gt;\\son\\sline\\s&lt;b&gt;\\d*?&lt;/b&gt;&lt;br\\s/&gt;",
  "(?:Unknown database '.*?')|(?:No database selected)|(?:Table '.*?' doesn't exist)|(?:You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '.*?' at line .*?)",
  "Exception report.*message.*description.*exception.*note.*",
  "(?i)&lt;head&gt;&lt;title&gt;JRun Servlet Error&lt;/title&gt;&lt;/head&gt;",
  "(?i)&lt;h1&gt;Servlet\\sError:\\s\\w+?&lt;/h1&gt;",
  "(?i)Servlet\\sError&lt;/title&gt;",
];

var dbErrors = microsoftDbErrors.concat(mySqlDbErrors);

var javaRegexErrors = [];
regexErrors.forEach(function (pattern) {
  javaRegexErrors.push(java.util.regex.Pattern.compile(pattern));
});

function scan(helper, msg) {
  if (msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()) {
    return;
  }
  var message = String(msg.getReadablePayload());

  var matches;
  dbErrors.forEach(function (pattern) {
    if ((matches = message.match(pattern)) != null) {
      matches.forEach(function (evidence) {
        raiseAlert(helper, evidence);
      });
    }
  });

  javaRegexErrors.forEach(function (pattern) {
    var matcher = pattern.matcher(message);
    while (matcher.find()) {
      raiseAlert(helper, String(matcher.group()));
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
    .setRiskConfidence(RISK_MEDIUM, CONFIDENCE_MEDIUM)
    .setName("Application Error Disclosure via WebSockets")
    .setDescription(
      "This payload contains an error/warning message that\
 may disclose sensitive information like the location of the file\
 that produced the unhandled exception. This information can be used\
 to launch further attacks against the web application.",
    )
    .setSolution(
      "Review the error payloads which are piped directly to WebSockets.\
 Handle the related exceptions.\
 Consider implementing a mechanism to provide a unique\
 error reference/identifier to the client (browser) while logging the\
 details on the server side and not exposing them to the user.",
    )
    .setEvidence(evidence)
    .setCweId(209) // Information Exposure Through an Error Message
    .setWascId(13); // Information Leakage
}

function getExampleAlerts() {
  return [
    createAlertBuilder(WebSocketPassiveScript.getExampleHelper(), "")
      .build()
      .getAlert(),
  ];
}

function getName() {
  return "Application Error Disclosure script";
}

function getId() {
  return 110001;
}
