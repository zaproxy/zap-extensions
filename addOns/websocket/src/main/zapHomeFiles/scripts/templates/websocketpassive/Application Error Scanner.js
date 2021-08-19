// * This Script analyzes incoming websocket messages for error messages

// * Based on org.zaproxy.zap.extension.pscanrules.ApplicationErrorScanner
// * Application error strings are equal to:
// ** https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/resources/org/zaproxy/zap/extension/pscanrules/resources/application_errors.xml

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_MEDIUM = 2;
CONFIDENCE_MEDIUM = 2;

var WebSocketPassiveScript = Java.type('org.zaproxy.zap.extension.websocket.pscan.scripts.WebSocketPassiveScript');

var microsoftDbErrors = [/Microsoft OLE DB Provider for ODBC Drivers/igm,
                                           /Microsoft OLE DB Provider for SQL Server/igm,
                                           /ODBC Microsoft Access Driver/igm,
                                           /ODBC SQL Server Driver/igm];

var mySqlDbErrors = [/supplied argument is not a valid MySQL result/igm,
                          /Invalid parameter type/igm,
                          /You have an error in your SQL syntax/igm,
                          /Incorrect column name/igm,
                          /Can't find record in/igm,
                          /Unknown table/igm,
                          /Incorrect column specifier for column/igm,
                          /Column count doesn't match value count at row/igm,
                          /Unclosed quotation mark before the character string/igm,
                          /java\.lang\.NumberFormatException: For input string:/igm,
                          /\): encountered SQLException \[/igm,
                          /Unexpected end of command in statement \[/igm,
                          /Invalid SQL:/igm,
                          /ERROR: parser: parse error at or near/igm,
                          /\[ODBC Informix driver\]\[Informix\]/igm,
                          /\[Microsoft\]\[ODBC Microsoft Access 97 Driver\]/igm,
                          /\[SQL Server Driver\]\[SQL Server\]Line 1: Incorrect syntax near/igm,
                          /SQL command not properly ended/igm,
                          /unexpected end of SQL command/igm,
                          /Supplied argument is not a valid PostgreSQL result/igm,
                          /internal error \[IBM\]\[CLI Driver\]\[DB2\/6000\]/igm,
                          /Error Occurred While Processing Request/igm,
                          /internal error/igm,
                          /A syntax error has occurred/igm,
                          /ADODB\.Field error/igm,
                          /ASP\.NET is configured to show verbose error messages/igm,
                          /ASP\.NET_SessionId/igm,
                          /Active Server Pages error/igm,
                          /An illegal character has been found in the statement/igm,
                          /An unexpected token "END-OF-STATEMENT" was found/igm,
                          /Can't connect to local/igm,
                          /Custom Error Message/igm,
                          /DB2 Driver/igm,
                          /DB2 Error/igm,
                          /DB2 ODBC/igm,
                          /Disallowed Parent Path/igm,
                          /Error Diagnostic Information/igm,
                          /Error Message : Error loading required libraries\./igm,
                          /Error Report/igm,
                          /Error converting data type varchar to numeric/igm,
                          /Internal Server Error/igm,
                          /Invalid Path Character/igm,
                          /Invalid procedure call or argument/igm,
                          /Invision Power Board Database Error/igm,
                          /JDBC Driver/igm,
                          /JDBC Error/igm,
                          /JDBC MySQL/igm,
                          /JDBC Oracle/igm,
                          /JDBC SQL/igm,
                          /Microsoft VBScript compilation error/igm,
                          /Microsoft VBScript error/igm,
                          /MySQL Driver/igm,
                          /MySQL Error/igm,
                          /MySQL ODBC/igm,
                          /ODBC DB2/igm,
                          /ODBC Driver/igm,
                          /ODBC Error/igm,
                          /ODBC Oracle/igm,
                          /OLE\/DB provider returned message/igm,
                          /Oracle DB2/igm,
                          /Oracle Driver/igm,
                          /Oracle Error/igm,
                          /Oracle ODBC/igm,
                          /PHP Error/igm,
                          /PHP Parse error/igm,
                          /PHP Warning/igm,
                          /Parent Directory/igm,
                          /Permission denied: 'GetObject'/igm,
                          /PostgreSQL query failed: ERROR: parser: parse error/igm,
                          /The script whose uid is/igm,
                          /Type mismatch/igm,
                          /Unable to jump to row/igm,
                          /Unterminated string constant/igm,
                          /Warning: Cannot modify header information - headers already sent/igm,
                          /Warning: Supplied argument is not a valid File-Handle resource in/igm,
                          /Warning: mysql_query\(\)/igm,
                          /Warning: pg_connect\(\): Unable to connect to PostgreSQL server: FATAL/igm,
                          /data source=/igm,
                          /invalid query/igm,
                          /is not allowed to access/igm,
                          /mySQL error with query/igm,
                          /on MySQL result index/igm,
                          /server object error/igm];

var regexErrors = ["(?i)Line\\s\\d+:\\sIncorrect\\ssyntax\\snear\\s'[^']*'",
            "(?i)pg_query\\(\\)[:]*\\squery\\sfailed:\\serror:\\s",
            "(?i)'[^']*'\\sis\\snull\\sor\\snot\\san\\sobject",
            "(?i)ORA\\-\\d{4,5}:\\s",
            "(?i)Microsoft\\sJET\\sDatabase\\sEngine\\s\\([^\\)]*\\)&lt;br&gt;Syntax\\serror(.*)\\sin\\squery\\sexpression\\s'.*\\.&lt;br&gt;&lt;b&gt;.*,\\sline\\s\\d+&lt;/b&gt;&lt;br&gt;",
            "(?i)&lt;h2&gt;\\s&lt;i&gt;Syntax\\serror\\s(\\([^\\)]*\\))?(in\\sstring)?\\sin\\squery\\sexpression\\s'[^\\.]*\\.&lt;/i&gt;\\s&lt;/h2&gt;&lt;/span&gt;",
            "(?i)&lt;font\\sface=\"Arial\"\\ssize=2&gt;Syntax\\serror\\s(.*)?in\\squery\\sexpression\\s'(.*)\\.&lt;/font&gt;",
            "(?i)&lt;b&gt;Warning&lt;/b&gt;:\\s\\spg_exec\\(\\)\\s\\[\\&lt;a\\shref='function.pg\\-exec\\'\\&gt;function\\.pg-exec\\&lt;/a&gt;\\]\\:\\sQuery failed:\\sERROR:\\s\\ssyntax error at or near \\&amp;quot\\;\\\\\\&amp;quot; at character \\d+ in\\s&lt;b&gt;.*&lt;/b&gt;",
            "(?i)System\\.Data\\.OleDb\\.OleDbException\\:\\sSyntax\\serror\\s\\([^)]*?\\)\\sin\\squery\\sexpression\\s.*",
            "(?i)System\\.Data\\.OleDb\\.OleDbException\\:\\sSyntax\\serror\\sin\\sstring\\sin\\squery\\sexpression\\s",
            "&lt;font style=\"COLOR: black; FONT: 8pt/11pt verdana\"&gt;\\s+(\\[Macromedia\\]\\[SQLServer\\sJDBC\\sDriver\\]\\[SQLServer\\]|Syntax\\serror\\sin\\sstring\\sin\\squery\\sexpression\\s)",
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
            "(?i)Servlet\\sError&lt;/title&gt;"];

var dbErrors = microsoftDbErrors.concat(mySqlDbErrors);

var javaRegexErrors = [];
regexErrors.forEach(function(pattern){
    javaRegexErrors.push(java.util.regex.Pattern.compile(pattern));
});

function scan(helper,msg) {

    if(msg.getOpcode() != OPCODE_TEXT || msg.isOutgoing()){
        return;
    }
    var message = String(msg.getReadablePayload());

    var matches;
    dbErrors.forEach(function(pattern){
        if((matches = message.match(pattern)) != null){
            matches.forEach(function(evidence){
                raiseAlert(helper, evidence);
            });
        }
    });

    javaRegexErrors.forEach(function(pattern){
        var matcher = pattern.matcher(message);
        while(matcher.find()){
            raiseAlert(helper, String(matcher.group()));
        }
    });
}

function raiseAlert(helper, evidence){
    createAlertBuilder(helper, evidence).raise();
}

function createAlertBuilder(helper, evidence){
    return helper.newAlert()
        .setPluginId(getId())
        .setRiskConfidence(RISK_MEDIUM, CONFIDENCE_MEDIUM)
        .setName("Application Error Disclosure via WebSockets")
        .setDescription("This payload contains an error/warning message that\
 may disclose sensitive information like the location of the file\
 that produced the unhandled exception. This information can be used\
 to launch further attacks against the web application.")
        .setSolution("Review the error payloads which are piped directly to WebSockets.\
 Handle the related exceptions.\
 Consider implementing a mechanism to provide a unique\
 error reference/identifier to the client (browser) while logging the\
 details on the server side and not exposing them to the user.")
        .setEvidence(evidence)
        .setCweId(209) // Information Exposure Through an Error Message
        .setWascId(13); // Information Leakage
}

function getExampleAlerts(){
    return [createAlertBuilder(WebSocketPassiveScript.getExampleHelper(), "").build().getAlert()];
}

function getName(){
    return "Application Error Disclosure script";
}

function getId(){
    return 110001;
}
