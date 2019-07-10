// * This Script analyzes incoming websocket messages for error messages with a set of regular expressions

// * Based on org.zaproxy.zap.extension.pscanrules.ApplicationErrorScanner
// * Application error strings are equal to (characters '\' is escaped -> '\\'):
// ** https://github.com/zaproxy/zap-extensions/blob/master/addOns/pscanrules/src/main/resources/org/zaproxy/zap/extension/pscanrules/resources/application_errors.xml

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_MEDIUM = 2;
CONFIDENCE_MEDIUM = 2;

patterns = ["(?i)Line\\s\\d+:\\sIncorrect\\ssyntax\\snear\\s'[^']*'",
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

var errorPatterns = [];
patterns.forEach(function(pattern){
    errorPatterns.push(java.util.regex.Pattern.compile(pattern));
});

function scan(helper,msg) {

    if(msg.opcode != OPCODE_TEXT || msg.isOutgoing){
        return;
    }
    var message = String(msg.getReadablePayload());

    errorPatterns.forEach(function(pattern){
        var matcher = pattern.matcher(message);
        while(matcher.find()){
            helper.newAlert()
                .setRiskConfidence(RISK_MEDIUM, CONFIDENCE_MEDIUM)
                .setName("Application Error Disclosure via WebSockets (regex-script)")
                .setDescription("This payload contains an error/warning message that\
 may disclose sensitive information like the location of the file\
 that produced the unhandled exception. This information can be used\
 to launch further attacks against the web application.")
                .setSolution("Review the error payloads which are piped directly to WebSockets.\
 Handle the related exceptions.\
 Consider implementing a mechanism to provide a unique\
 error reference/identifier to the client (browser) while logging the\
 details on the server side and not exposing them to the user.")
                .setEvidence(String(matcher.group()))
                .setCweId(209) // Information Exposure Through an Error Message
                .setWascId(13) //Information Leakage
                .raise();
        }
    });
}
