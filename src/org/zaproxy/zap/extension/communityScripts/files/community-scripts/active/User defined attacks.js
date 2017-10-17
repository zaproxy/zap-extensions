// An example active scan rule script which uses a set of attack payloads and a set of regexes
// in order to find potential issues.
// Replace or extend the attacks and evidence regexes with you own values.

// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// The following handles differences in printing between Java 7's Rhino JS engine
// and Java 8's Nashorn JS engine
if (typeof println == 'undefined') this.println = print;

// Replace or extend these with your own attacks
// put the attacks you most want to run higher, unless you disable the attack strength check
var attacks = [
	'<>"\'%;)(&+', 
	'\'', 
	'\' --',  
	'|', 
	'!', 
	'?', 
	'/', 
	'//', 
	'//*', 
	'(', 
	')', 
	'*|', 
	'*/*', 
	'{', 
	'}', 
]

// Replace or extend these with your own evidence - regexes that indicate potential issues
// The default ones are a subset of https://github.com/fuzzdb-project/fuzzdb/blob/master/regex/errors.txt
var evidence = [
	"A syntax error has occurred",
	"Active Server Pages error",
	"ADODB.Field error",
	"An illegal character has been found in the statement",
	"An unexpected token .* was found",
	"ASP\.NET is configured to show verbose error messages",
	"ASP\.NET_SessionId",
	"Custom Error Message",
	"database error",
	"DB2 Driver",
	"DB2 Error",
	"DB2 ODBC",
	"detected an internal error",
	"Error converting data type varchar to numeric",
	"Error Diagnostic Information",
	"Error Report",
	"Fatal error",
	"Incorrect syntax near",
	"Index of",
	"Internal Server Error",
	"Invalid Path Character",
	"Invalid procedure call or argument",
	"invalid query",
	"Invision Power Board Database Error",
	"is not allowed to access",
	"JDBC Driver",
	"JDBC Error",
	"JDBC MySQL",
	"JDBC Oracle",
	"JDBC SQL",
	"Microsoft OLE DB Provider for ODBC Drivers",
	"Microsoft VBScript compilation error",
	"Microsoft VBScript error",
	"MySQL Driver",
	"mysql error",
	"MySQL Error",
	"mySQL error with query",
	"MySQL ODBC",
	"ODBC DB2",
	"ODBC Driver",
	"ODBC Error",
	"ODBC Microsoft Access",
	"ODBC Oracle",
	"ODBC SQL",
	"OLE/DB provider returned message",
	"on line",
	"on MySQL result index",
	"Oracle DB2",
	"Oracle Driver",
	"Oracle Error",
	"Oracle ODBC",
	"Parent Directory",
	"PHP Error",
	"PHP Parse error",
	"PHP Warning",
	"PostgreSQL query failed",
	"server object error",
	"SQL command not properly ended",
	"SQL Server Driver",
	"SQLException",
	"supplied argument is not a valid",
	"Syntax error in query expression",
	"The error occurred in",
	"The script whose uid is",
	"Type mismatch",
	"Unable to jump to row",
	"Unclosed quotation mark before the character string",
	"unexpected end of SQL command",
	"unexpected error",
	"Unterminated string constant",
	"Warning: mysql_query",
	"Warning: pg_connect",
	"You have an error in your SQL syntax near",
]

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
function scanNode(as, msg) {
	// Do nothing here - this script just attacks parameters rather than nodes
}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {
	// Debugging can be done using println like this
	//println('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
	//	' param=' + param + ' value=' + value);
	
	var max_attacks = attacks.length	// No limit for the "INSANE" level ;)
	
	if (as.getAttackStrength() == "LOW") {
		max_attacks = 6
	} else if (as.getAttackStrength() == "MEDIUM") {
		max_attacks = 12
	} else if (as.getAttackStrength() == "HIGH") {
		max_attacks = 24
	}

	for (i in attacks) {
		// Dont exceed recommended number of attacks for strength
		// feel free to disable this locally ;)
		if (i > max_attacks) {
			return
		}
		// Copy requests before reusing them
		msg = msg.cloneRequest();

		// setParam (message, parameterName, newValue)
		as.setParam(msg, param, attacks[i]);
		
		// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
		as.sendAndReceive(msg, false, false);

		// Add any generic checks here, eg
		var code = msg.getResponseHeader().getStatusCode()
		if (code >= 500 && code < 600) {
			raiseAlert(as, msg, param, attacks[i], code)
			// Only raise one alert per param
			return
		}

		var body = msg.getResponseBody().toString()
		var re = new RegExp(evidence.join("|"), "i")
		found = body.match(re)
		if (found) {	// Change to a test which detects the vulnerability
			raiseAlert(as, msg, param, attacks[i], found)
			// Only raise one alert per param
			return
		}
	
		// Check if the scan was stopped before performing lengthy tasks
		if (as.isStop()) {
			return
		}
	}
}

function raiseAlert(as, msg, param, attack, evidence) {
	// Replace with more suitable information
	// raiseAlert(risk, int confidence, String name, String description, String uri, 
	//		String param, String attack, String otherInfo, String solution, String evidence, 
	//		int cweId, int wascId, HttpMessage msg)
	// risk: 0: info, 1: low, 2: medium, 3: high
	// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
	as.raiseAlert(1, 1, 'Active Vulnerability Title', 'Full description', 
		msg.getRequestHeader().getURI().toString(), 
		param, attack, 'Any other info', 'The solution ', evidence, 0, 0, msg);
}

