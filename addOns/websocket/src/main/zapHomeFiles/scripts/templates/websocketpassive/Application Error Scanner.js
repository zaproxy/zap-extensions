// * This Script analyzes incoming websocket messages for error messages

// * Based on org.zaproxy.zap.extension.pscanrules.ApplicationErrorScanner
// * Application error strings are equal to:
// ** https://github.com/zaproxy/zap-extensions/blob/master/addOns/pscanrules/src/main/resources/org/zaproxy/zap/extension/pscanrules/resources/application_errors.xml

// Author: Manos Kirtas (manolis.kirt@gmail.com)

OPCODE_TEXT = 0x1;
RISK_MEDIUM = 2;
CONFIDENCE_MEDIUM = 2;

var strings_microsoft_db_error = [/Microsoft OLE DB Provider for ODBC Drivers/igm,
                                           /Microsoft OLE DB Provider for SQL Server/igm,
                                           /ODBC Microsoft Access Driver/igm,
                                           /ODBC SQL Server Driver/igm];

var strings_msql_error = [/supplied argument is not a valid MySQL result/igm,
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

function scan(helper,msg) {

    if(msg.opcode != OPCODE_TEXT || msg.isOutgoing){
        return;
    }
    var message = String(msg.getReadablePayload());
    var matches;

    strings_msql_error.forEach(function(pattern){
        if((matches = message.match(pattern)) != null){
            matches.forEach(function(evidence){

                helper.newAlert()
                    .setRiskConfidence(RISK_MEDIUM, CONFIDENCE_MEDIUM)
                    .setName("Application Error Disclosure via WebSockets (script)")
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
                    .setWascId(13) // Information Leakage
                    .raise();
            });
        }
    });
}
