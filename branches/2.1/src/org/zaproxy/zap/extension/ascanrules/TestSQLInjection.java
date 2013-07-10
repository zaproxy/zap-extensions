/**
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.ascanrules;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.auth.ExtensionAuth;
import org.zaproxy.zap.model.Context;

import difflib.Delta;
import difflib.DiffUtils;
import difflib.Patch;


/**
 * TODO: implement stacked query check, since it is actually supported on more RDBMS drivers / frameworks than not (MySQL on PHP/ASP does not by default, but can).
 *        PostgreSQL and MSSQL on ASP, ASP.NET, and PHP *do* support it, for instance.  It's better to put the code here and try it for all RDBMSs as a result.
 *        Use the following variables: doStackedBased, doStackedMaxRequests, countStackedBasedRequests
 * TODO: implement checks in Header fields (currently does Cookie values, form fields, and url parameters)
 * TODO: change the Alert Titles.
 * TODO: if the argument is reflected back in the HTML output, the boolean based logic will not detect an alert 
 *        (because the HTML results of argument values "id=1" will not be the same as for "id=1 and 1=1")
 * TODO: add "<param>*2/2" check to the Logic based ones (for integer parameter values).. if the result is the same, it might be a SQL Injection
 * TODO: implement mode checks (Mode.standard, Mode.safe, Mode.protected) for 2.* using "implements SessionChangedListener"
 * 
 * The SQLInjection plugin identifies SQL Injection vulnerabilities
 * note the ordering of checks, for efficiency is : 
 * 1) Error based
 * 2) Boolean Based
 * 3) UNION based
 * 4) Stacked (TODO: implement stacked based)
 * 5) Blind/Time Based (RDBMS specific, so not done here right now)
 * 
 *  @author Colm O'Flaherty, Encription Ireland Ltd
 */
public class TestSQLInjection extends AbstractAppParamPlugin  {

	//what do we do at each attack strength?
	//(some SQL Injection vulns would be picked up by multiple types of checks, and we skip out after the first alert for a URL)
	private boolean doErrorBased = false;  
	private boolean doBooleanBased=false; 
	private boolean doUnionBased = false;	
	private boolean doExpressionBased = false;
	private boolean doOrderByBased = false;
	private boolean doStackedBased = false;  //TODO: use in the stacked based implementation

	//how many requests can we fire for each method? will be set depending on the attack strength
	private int doErrorMaxRequests = 0;
	private int doBooleanMaxRequests = 0;
	private int doUnionMaxRequests = 0;
	private int doExpressionMaxRequests=0;
	private int doOrderByMaxRequests = 0;
	private int doStackedMaxRequests = 0;	//TODO: use in the stacked based implementation

	/**
	 * generic one-line comment.  Various RDBMS Documentation suggests that this syntax works with almost every single RDBMS considered here
	 */
	public static final String SQL_ONE_LINE_COMMENT = " -- ";

	/**
	 * used to inject to check for SQL errors: some basic SQL metacharacters ordered so as to maximise SQL errors
	 * Note that we do separate runs for each family of characters, in case one family are filtered out, the others might still
	 * get past
	 */
	private static final String [] SQL_CHECK_ERR = {"'", "\"", ")", "(", "NULL", "'\""};

	/**
	 * create a map of SQL related error message fragments, and map them back to the RDBMS that they are associated with
	 * keep the ordering the same as the order in which the values are inserted, to allow the more (subjectively judged) common cases to be tested first
	 * Note: these should represent actual (driver level) error messages for things like syntax error, 
	 * otherwise we are simply guessing that the string should/might occur.
	 */
	private static final Map<String, String> SQL_ERROR_TO_DBMS = new LinkedHashMap<>();
	static {
		//DONE: we have implemented a MySQL specific scanner. See SQLInjectionMySQL
		SQL_ERROR_TO_DBMS.put("com.mysql.jdbc.exceptions", "MySQL");
		SQL_ERROR_TO_DBMS.put("org.gjt.mm.mysql", "MySQL");

		//TODO: implement a plugin that uses Microsoft SQL specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("com.microsoft.sqlserver.jdbc", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("com.microsoft.jdbc", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("com.inet.tds", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("com.microsoft.sqlserver.jdbc", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("com.ashna.jturbo", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("weblogic.jdbc.mssqlserver", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("[Microsoft]", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("[SQLServer]", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("[SQLServer 2000 Driver for JDBC]", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("net.sourceforge.jtds.jdbc", "Microsoft SQL Server"); 		//see also be Sybase. could be either!
		SQL_ERROR_TO_DBMS.put("80040e14", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("800a0bcd", "Microsoft SQL Server");
		SQL_ERROR_TO_DBMS.put("80040e57", "Microsoft SQL Server");

		//DONE: we have implemented an Oracle specific scanner. See SQLInjectionOracle
		SQL_ERROR_TO_DBMS.put("oracle.jdbc", "Oracle");
		SQL_ERROR_TO_DBMS.put("SQLSTATE[HY", "Oracle");
		SQL_ERROR_TO_DBMS.put("ORA-00933", "Oracle");
		SQL_ERROR_TO_DBMS.put("ORA-06512", "Oracle");  //indicates the line number of an error
		SQL_ERROR_TO_DBMS.put("SQL command not properly ended", "Oracle");
		SQL_ERROR_TO_DBMS.put("ORA-00942", "Oracle");  //table or view does not exist
		SQL_ERROR_TO_DBMS.put("ORA-29257", "Oracle");  //host unknown
		SQL_ERROR_TO_DBMS.put("ORA-00932", "Oracle");  //inconsistent datatypes

		//TODO: implement a plugin that uses DB2 specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("com.ibm.db2.jcc", "IBM DB2");
		SQL_ERROR_TO_DBMS.put("COM.ibm.db2.jdbc", "IBM DB2");

		//DONE: we have implemented a PostgreSQL specific scanner. See SQLInjectionPostgresql
		SQL_ERROR_TO_DBMS.put("org.postgresql.util.PSQLException", "PostgreSQL");
		SQL_ERROR_TO_DBMS.put("org.postgresql", "PostgreSQL");

		//TODO: implement a plugin that uses Sybase specific functionality to detect SQL Injection vulnerabilities
		//Note: this plugin would also detect Microsoft SQL Server vulnerabilities, due to common syntax. 
		SQL_ERROR_TO_DBMS.put("com.sybase.jdbc", "Sybase");
		SQL_ERROR_TO_DBMS.put("com.sybase.jdbc2.jdbc", "Sybase");
		SQL_ERROR_TO_DBMS.put("com.sybase.jdbc3.jdbc", "Sybase");
		SQL_ERROR_TO_DBMS.put("net.sourceforge.jtds.jdbc", "Sybase");  //see also Microsoft SQL Server. could be either!

		//TODO: implement a plugin that uses Informix specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("com.informix.jdbc", "Informix");

		//TODO: implement a plugin that uses Firebird specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("org.firebirdsql.jdbc", "Firebird");

		//TODO: implement a plugin that uses IDS Server specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("ids.sql", "IDS Server");

		//TODO: implement a plugin that uses InstantDB specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("org.enhydra.instantdb.jdbc", "InstantDB");
		SQL_ERROR_TO_DBMS.put("jdbc.idb", "InstantDB");

		//TODO: implement a plugin that uses Interbase specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("interbase.interclient", "Interbase");

		//DONE: we have implemented a Hypersonic specific scanner. See SQLInjectionHypersonic
		SQL_ERROR_TO_DBMS.put("org.hsql", "Hypersonic SQL");  
		SQL_ERROR_TO_DBMS.put("hSql.", "Hypersonic SQL");
		SQL_ERROR_TO_DBMS.put("Unexpected token , requires FROM in statement", "Hypersonic SQL");
		SQL_ERROR_TO_DBMS.put("Unexpected end of command in statement", "Hypersonic SQL");
		SQL_ERROR_TO_DBMS.put("Column count does not match in statement", "Hypersonic SQL");  //TODO: too generic to leave in???
		SQL_ERROR_TO_DBMS.put("Table not found in statement", "Hypersonic SQL"); //TODO: too generic to leave in???
		SQL_ERROR_TO_DBMS.put("Unexpected token:", "Hypersonic SQL"); //TODO: too generic to leave in??? Works very nicely in Hypersonic cases, however

		//TODO: implement a plugin that uses Sybase SQL Anywhere specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("sybase.jdbc.sqlanywhere", "Sybase SQL Anywhere");

		//TODO: implement a plugin that uses PointBase specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("com.pointbase.jdbc", "Pointbase");

		//TODO: implement a plugin that uses Cloudbase specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("db2j.","Cloudscape");
		SQL_ERROR_TO_DBMS.put("COM.cloudscape","Cloudscape");
		SQL_ERROR_TO_DBMS.put("RmiJdbc.RJDriver","Cloudscape");

		//TODO: implement a plugin that uses Ingres specific functionality to detect SQL Injection vulnerabilities
		SQL_ERROR_TO_DBMS.put("com.ingres.jdbc", "Ingres");

		//generic error message fragments that do not fingerprint the RDBMS, but that may indicate SQL Injection, nonetheless
		SQL_ERROR_TO_DBMS.put("com.ibatis.common.jdbc", "Generic SQL RDBMS");
		SQL_ERROR_TO_DBMS.put("org.hibernate", "Generic SQL RDBMS");
		SQL_ERROR_TO_DBMS.put("sun.jdbc.odbc", "Generic SQL RDBMS");
		SQL_ERROR_TO_DBMS.put("[ODBC Driver Manager]", "Generic SQL RDBMS");
		SQL_ERROR_TO_DBMS.put("System.Data.OleDb", "Generic SQL RDBMS");   //System.Data.OleDb.OleDbException
		SQL_ERROR_TO_DBMS.put("java.sql.SQLException", "Generic SQL RDBMS");  //in case more specific messages were not detected!
	}


	/**
	 * always true statement for comparison in boolean based SQL injection check
	 * try the commented versions first, because the law of averages says that the column being queried is more likely *not* in the last where clause in a SQL query
	 * so as a result, the rest of the query needs to be closed off with the comment.
	 */	
	private static final String[] SQL_LOGIC_AND_TRUE = {
		" AND 1=1" + SQL_ONE_LINE_COMMENT,
		"' AND '1'='1'" + SQL_ONE_LINE_COMMENT,
		"\" AND \"1\"=\"1\"" + SQL_ONE_LINE_COMMENT,
		" AND 1=1",
		"' AND '1'='1",
		"\" AND \"1\"=\"1",	
		"%",								//attack for SQL LIKE statements
		"%' " + SQL_ONE_LINE_COMMENT,		//attack for SQL LIKE statements
		"%\" " + SQL_ONE_LINE_COMMENT,		//attack for SQL LIKE statements
	};  

	/**
	 * always false statement for comparison in boolean based SQL injection check
	 */
	private static final String[] SQL_LOGIC_AND_FALSE = {
		" AND 1=2" + SQL_ONE_LINE_COMMENT,
		"' AND '1'='2'" + SQL_ONE_LINE_COMMENT,
		"\" AND \"1\"=\"2\"" + SQL_ONE_LINE_COMMENT,
		" AND 1=2",
		"' AND '1'='2",
		"\" AND \"1\"=\"2",
		"XYZABCDEFGHIJ",							//attack for SQL LIKE statements
		"XYZABCDEFGHIJ' " + SQL_ONE_LINE_COMMENT,	//attack for SQL LIKE statements
		"XYZABCDEFGHIJ\" " + SQL_ONE_LINE_COMMENT,	//attack for SQL LIKE statements
	};

	/**
	 * always true statement for comparison if no output is returned from AND in boolean based SQL injection check
	 * Note that, if necessary, the code also tries a variant with the one-line comment " -- " appended to the end.
	 */
	private static final String[] SQL_LOGIC_OR_TRUE = {
		" OR 1=1" + SQL_ONE_LINE_COMMENT,
		"' OR '1'='1'" + SQL_ONE_LINE_COMMENT,
		"\" OR \"1\"=\"1\"" + SQL_ONE_LINE_COMMENT,
		" OR 1=1",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"%",								//attack for SQL LIKE statements
		"%' " + SQL_ONE_LINE_COMMENT,		//attack for SQL LIKE statements
		"%\" " + SQL_ONE_LINE_COMMENT,		//attack for SQL LIKE statements
	};

	/**
	 * generic UNION statements. Hoping these will cause a specific error message that we will recognise
	 */	
	private static String [] SQL_UNION_APPENDAGES = {
		" UNION ALL select NULL" + SQL_ONE_LINE_COMMENT,
		"' UNION ALL select NULL" + SQL_ONE_LINE_COMMENT,
		"\" UNION ALL select NULL" + SQL_ONE_LINE_COMMENT,
		") UNION ALL select NULL" + SQL_ONE_LINE_COMMENT,
		"') UNION ALL select NULL" + SQL_ONE_LINE_COMMENT,
		"\") UNION ALL select NULL" + SQL_ONE_LINE_COMMENT,
	};


	/*
    SQL UNION error messages for various RDBMSs. The more, the merrier.
	 */
	private static final Map<String, String> SQL_UNION_ERROR_TO_DBMS = new LinkedHashMap<>();
	static {
		SQL_UNION_ERROR_TO_DBMS.put("The used SELECT statements have a different number of columns", "MySQL");
		SQL_UNION_ERROR_TO_DBMS.put("each UNION query must have the same number of columns", "PostgreSQL");
		SQL_UNION_ERROR_TO_DBMS.put("All queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists", "Microsoft SQL Server");
		SQL_UNION_ERROR_TO_DBMS.put("All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists", "Microsoft SQL Server");
		SQL_UNION_ERROR_TO_DBMS.put("query block has incorrect number of result columns", "Oracle");
		SQL_UNION_ERROR_TO_DBMS.put("ORA-01789", "Oracle");
		SQL_UNION_ERROR_TO_DBMS.put("Unexpected end of command in statement", "Hypersonic SQL");  //needs a table name in a UNION query. Like Oracle?
		SQL_UNION_ERROR_TO_DBMS.put("Column count does not match in statement", "Hypersonic SQL");
		//TODO: add other specific UNION based error messages for Union here: PostgreSQL, Sybase, DB2, Informix, etc
	}

	/**
	 * plugin dependencies
	 */
	private static final String[] dependency = {};    	

	/**
	 * for logging.
	 */
	private static Logger log = Logger.getLogger(TestSQLInjection.class);

	/**
	 * determines if we should output Debug level logging
	 */
	private boolean debugEnabled = log.isDebugEnabled();

	@Override
	public int getId() {
		return 40018;
	}

	@Override
	public String getName() {
		return Constant.messages.getString("ascanrules.sqlinjection.name");
	}

	@Override
	public String[] getDependency() {        
		return dependency;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("ascanrules.sqlinjection.desc");
	}

	@Override
	public int getCategory() {
		return Category.INJECTION;
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString("ascanrules.sqlinjection.soln");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString("ascanrules.sqlinjection.refs");  
	}

	/* initialise
	 * Note that this method gets called each time the scanner is called.
	 */
	@Override
	public void init() {
		if ( this.debugEnabled ) log.debug("Initialising");
		AscanUtils.registerI18N();

		//DEBUG only
		//this.debugEnabled=true;
		//this.setAttackStrength(AttackStrength.LOW);		

		//set up what we are allowed to do, depending on the attack strength that was set.
		if ( this.getAttackStrength() == AttackStrength.LOW ) {
			//do error based (if Threshold allows), and some expression based
			doErrorBased=true; doErrorMaxRequests=4;
			doExpressionBased=true; doExpressionMaxRequests=4;
			doBooleanBased=false; doBooleanMaxRequests=0;			
			doUnionBased=false; doUnionMaxRequests=0;
			doOrderByBased=false; doOrderByMaxRequests=0;
			doStackedBased=false; doStackedMaxRequests=0;
				
		} else if ( this.getAttackStrength() == AttackStrength.MEDIUM) {
			//do some more error based (if Threshold allows), some more expression based, some boolean based, and some Union based
			doErrorBased=true; doErrorMaxRequests=8;
			doExpressionBased=true; doExpressionMaxRequests=8;			
			doBooleanBased=true; doBooleanMaxRequests=6;
			doUnionBased=true; doUnionMaxRequests=5;
			doOrderByBased=false; doOrderByMaxRequests=0;
			doStackedBased=false; doStackedMaxRequests=5;
			
		} else if ( this.getAttackStrength() == AttackStrength.HIGH) {
			//do some more error based (if Threshold allows), some more expression based, some more boolean based, some union based, and some order by based
			doErrorBased=true; doErrorMaxRequests=16;
			doExpressionBased=true; doExpressionMaxRequests=16;
			doBooleanBased=true; doBooleanMaxRequests=20;	//will not run all the LIKE attacks.. these are done at insane..
			doUnionBased=true; doUnionMaxRequests=10;
			doOrderByBased=true; doOrderByMaxRequests=5;
			doStackedBased=false; doStackedMaxRequests=10;			
		} else if ( this.getAttackStrength() == AttackStrength.INSANE) {
			//do some more error based (if Threshold allows), some more expression based, some more boolean based, some more union based, and some more order by based
			doErrorBased=true; doErrorMaxRequests=100;
			doExpressionBased=true; doExpressionMaxRequests=100;
			doBooleanBased=true; doBooleanMaxRequests=100;
			doUnionBased=true; doUnionMaxRequests=100;
			doOrderByBased=true; doOrderByMaxRequests=100;
			doStackedBased=false; doStackedMaxRequests=100;			
		}
		//if a high threshold is in place, turn off the error based, which are more prone to false positives
		if ( this.getAlertThreshold() == AlertThreshold.HIGH) {
			if (this.debugEnabled) log.debug("Disabling the Error Based checking, since the Alert Threshold is set to High, and this type of check is notably prone to false positives");
			doErrorBased=false; doErrorMaxRequests=0;
		}

	}


	/**
	 * scans for SQL Injection vulnerabilities
	 */
	@Override
	public void scan(HttpMessage msg, String param, String origParamValue) {
		//Note: the "value" we are passed here is escaped. we need to unescape it before handling it.
		//as soon as we find a single SQL injection on the url, skip out. Do not look for SQL injection on a subsequent parameter on the same URL
		//for performance reasons.
		boolean sqlInjectionFoundForUrl = false;
		String sqlInjectionAttack = null;
		HttpMessage refreshedmessage=null;
		String mResBodyNormalUnstripped = null;
		String mResBodyNormalStripped = null;


		try {

			//reinitialise the count for each type of request, for each parameter.  We will be sticking to limits defined in the attach strength logic
			int countErrorBasedRequests = 0;
			int countExpressionBasedRequests=0;
			int countBooleanBasedRequests = 0;
			int countUnionBasedRequests = 0;
			int countOrderByBasedRequests=0;
			int countStackedBasedRequests = 0;  //TODO: use in the stacked based queries implementation


			//Check 1: Check for Error Based SQL Injection (actual error messages).
			//for each SQL metacharacter combination to try
			for (int sqlErrorStringIndex = 0; 
					sqlErrorStringIndex < SQL_CHECK_ERR.length && !sqlInjectionFoundForUrl && doErrorBased && countErrorBasedRequests < doErrorMaxRequests ; 
					sqlErrorStringIndex++) {
				
				//work through the attack using each of the following strings as a prefix: the empty string, and the original value
				//Note: this doubles the amount of work done by the scanner, but is necessary in some cases
				String [] prefixStrings;
				if (origParamValue != null) {
					prefixStrings = new String[] {"", TestSQLInjection.getURLDecode(origParamValue)};
				} else {
					prefixStrings = new String[] {""};
				}
				for (int prefixIndex = 0; prefixIndex < prefixStrings.length; prefixIndex++) {
					
					//new message for each value we attack with
					HttpMessage msg1 = getNewMsg();
					String sqlErrValue = prefixStrings[prefixIndex] + SQL_CHECK_ERR[sqlErrorStringIndex];
					setParameter(msg1, param, sqlErrValue);
					
					//System.out.println("Attacking [" + msg + "], parameter [" + param + "] with value ["+ sqlErrValue + "]");

					//send the message with the modified parameters
					sendAndReceive(msg1);
					countErrorBasedRequests++;

					//now check the results against each pattern in turn, to try to identify a database, or even better: a specific database.
					//Note: do NOT check the HTTP error code just yet, as the result could come back with one of various codes.
					Iterator<String> errorPatternIterator =  SQL_ERROR_TO_DBMS.keySet().iterator();

					while (errorPatternIterator.hasNext() && ! sqlInjectionFoundForUrl) {
						String errorPatternKey = errorPatternIterator.next();
						String errorPatternRDBMS =  SQL_ERROR_TO_DBMS.get(errorPatternKey);

						//Note: must escape the strings, in case they contain strings like "[Microsoft], which would be interpreted as regular character class regexps"
						Pattern errorPattern = Pattern.compile("\\Q"+errorPatternKey+"\\E", PATTERN_PARAM);

						//if the "error message" occurs in the result of sending the modified query, but did NOT occur in the original result of the original query
						//then we may may have a SQL Injection vulnerability
						StringBuilder sb = new StringBuilder();
						if (! matchBodyPattern(getBaseMsg(), errorPattern, null) && matchBodyPattern(msg1, errorPattern, sb)) {
							//Likely a SQL Injection. Raise it
							String extraInfo = Constant.messages.getString("ascanrules.sqlinjection.alert.errorbased.extrainfo", errorPatternRDBMS, errorPatternKey);
							//raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
							sqlInjectionAttack=sqlErrValue;
							bingo(Alert.RISK_HIGH, Alert.WARNING, getName() + " - " + errorPatternRDBMS, getDescription(), 
									null,
									param,  sqlInjectionAttack, 
									extraInfo, getSolution(), msg1);

							//log it, as the RDBMS may be useful to know later (in subsequent checks, when we need to determine RDBMS specific behaviour, for instance)
							getKb().add(getBaseMsg().getRequestHeader().getURI(), "sql/"+errorPatternRDBMS, Boolean.TRUE);

							sqlInjectionFoundForUrl = true; 
							continue; 
						}
					} //end of the loop to check for RDBMS specific error messages

				}  //for each of the SQL_CHECK_ERR values (SQL metacharacters)
			}

			//###############################
			//Check 4			
			//New!  I haven't seen this technique documented anywhere else, but it's dead simple. Let me explain.
			//See if the parameter value can simply be changed to one that *evaluates* to be the same value,
			//if evaluated on a database
			//the simple check is to see if parameter "1" gives the same results as for param "2-1", and different results for param "2-2"
			//for now, we try this for integer values only.
			//###############################
			//Since the previous checks are attempting SQL injection, and may have actually succeeded in modifying the database (ask me how I know?!)
			//then we cannot rely on the database contents being the same as when the original query was last run (could be hours ago)
			//so to work around this, simply re-run the query again now at this point.
			//Note that we are not counting this request in our max number of requests to be issued
			refreshedmessage = getNewMsg();	
			sendAndReceive(refreshedmessage);
			
			//String mResBodyNormal = getBaseMsg().getResponseBody().toString();
			mResBodyNormalUnstripped = refreshedmessage.getResponseBody().toString();
			mResBodyNormalStripped = this.stripOff(mResBodyNormalUnstripped, origParamValue);
			
			if (! sqlInjectionFoundForUrl && doExpressionBased && countExpressionBasedRequests < doExpressionMaxRequests ) {
				
				//first figure out the type of the parameter.. 				
				try {
					//is it an integer type?
					int paramAsInt = new Integer (TestSQLInjection.getURLDecode(origParamValue));
					if (this.debugEnabled) log.debug("The parameter value ["+ TestSQLInjection.getURLDecode(origParamValue) + "] is of type Integer");
					
					//get a value 2 sizes bigger
					int paramPlusTwo=paramAsInt+2;
					String modifiedParamValue=String.valueOf(paramPlusTwo)+ "-2";
					
					//and prepare a request to set the parameter value to a string value like "3-2", if the original parameter value was "1"
					//those of you still paying attention will note that if handled as expressions (such as by a database), these represent the same value.
					HttpMessage msg4 = getNewMsg();
					setParameter(msg4, param, modifiedParamValue);
					
					sendAndReceive(msg4);
					countExpressionBasedRequests++;
					
					String modifiedExpressionOutputUnstripped = msg4.getResponseBody().toString();
					String modifiedExpressionOutputStripped = this.stripOff(modifiedExpressionOutputUnstripped, modifiedParamValue);
					
					//set up two little arrays to ease the work of checking the unstripped output, and then the stripped output
					String normalBodyOutput [] = {mResBodyNormalUnstripped, mResBodyNormalStripped};
					String expressionBodyOutput [] = {modifiedExpressionOutputUnstripped, modifiedExpressionOutputStripped};
					boolean strippedOutput [] = {false, true};
					
					for (int booleanStrippedUnstrippedIndex = 0; booleanStrippedUnstrippedIndex < 2; booleanStrippedUnstrippedIndex++) {
						//if the results of the modified request match the original query, we may be onto something. 
						if (expressionBodyOutput[booleanStrippedUnstrippedIndex].compareTo(normalBodyOutput[booleanStrippedUnstrippedIndex]) == 0 ) {
							if (this.debugEnabled) log.debug("Check 4, " + (strippedOutput[booleanStrippedUnstrippedIndex] ? "STRIPPED": "UNSTRIPPED")+ " html output for modified expression parameter ["+modifiedParamValue+"] matched (refreshed) original results for "+ refreshedmessage.getRequestHeader().getURI());
							//confirm that a different parameter value generates different output, to minimise false positives
							
							//get a value 3 sizes bigger this time
							int paramPlusFour=paramAsInt+3;
							String modifiedParamValueConfirm=String.valueOf(paramPlusFour)+ "-2";
							
							//and prepare a request to set the parameter value to a string value like "4-2", if the original parameter value was "1"
							//Note that the two values are NOT equivalent, and the param value is different to the original
							HttpMessage msg4Confirm = getNewMsg();
							setParameter(msg4Confirm, param, modifiedParamValueConfirm);
							
							sendAndReceive(msg4Confirm);
							countExpressionBasedRequests++;
							
							String confirmExpressionOutputUnstripped = msg4Confirm.getResponseBody().toString();
							String confirmExpressionOutputStripped = this.stripOff(confirmExpressionOutputUnstripped, modifiedParamValueConfirm);
							
							//set up two little arrays to ease the work of checking the unstripped output or the stripped output
							String confirmExpressionBodyOutput [] = {confirmExpressionOutputUnstripped, confirmExpressionOutputStripped};
							
							if (confirmExpressionBodyOutput[booleanStrippedUnstrippedIndex].compareTo(normalBodyOutput[booleanStrippedUnstrippedIndex]) != 0 ) {
								//the confirm query did not return the same results.  This means that arbitrary queries are not all producing the same page output.
								//this means the fact we earier reproduced the original page output with a modified parameter was not a coincidence
								
								//Likely a SQL Injection. Raise it
								String extraInfo = null;
								if (strippedOutput [booleanStrippedUnstrippedIndex]) 
									extraInfo=Constant.messages.getString("ascanrules.sqlinjection.alert.expressionbased.extrainfo", modifiedParamValue, "");
								else 
									extraInfo=Constant.messages.getString("ascanrules.sqlinjection.alert.expressionbased.extrainfo", modifiedParamValue, "NOT ");							
								
								//raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
								sqlInjectionAttack=modifiedParamValue;
								bingo(Alert.RISK_HIGH, Alert.WARNING, getName(), getDescription(), 
										null, //url
										param,  sqlInjectionAttack, 
										extraInfo, getSolution(), msg4);

								sqlInjectionFoundForUrl= true; 								
							}
						}
					}
				}
				catch (Exception e) {
					
					if (this.debugEnabled) log.debug("The parameter value ["+ TestSQLInjection.getURLDecode(origParamValue) + "] is NOT of type Integer");
					//TODO: implement a similar check for string types?  This probably need to be RDBMS specific (ie, it should not live in this scanner)
				}
			}				


			
			
			
			//Check 2: boolean based checks.
			//the check goes like so:
			// append " and 1 = 1" to the param.  Send the query.  Check the results. Hopefully they match the original results from the unmodified query,
			// *suggesting* (but not yet definitely) that we have successfully modified the query, (hopefully not gotten an error message), 
			// and have gotten the same results back, which is what you would expect if you added the constraint " and 1 = 1" to most (but not every) SQL query.
			// So was it a fluke that we got the same results back from the modified query? Perhaps the original query returned 0 rows, so adding any number of 
			// constraints would change nothing?  It is still a possibility!
			// check to see if we can change the original parameter again to *restrict* the scope of the query using an AND with an always false condition (AND_ERR)
			// (decreasing the results back to nothing), or to *broaden* the scope of the query using an OR with an always true condition (AND_OR)
			// (increasing the results).  
			// If we can successfully alter the results to our requirements, by one means or another, we have found a SQL Injection vulnerability.
			//Some additional complications: assume there are 2 HTML parameters: username and password, and the SQL constructed is like so:
			// select * from username where user = "$user" and password = "$password"
			// and lets assume we successfully know the type of the user field, via SQL_OR_TRUE value '" OR "1"="1' (single quotes not part of the value)
			// we still have the problem that the actual SQL executed would look like so:
			// select * from username where user = "" OR "1"="1" and password = "whateveritis"
			// Since the password field is still taken into account (by virtue of the AND condition on the password column), and we only inject one parameter at a time, 
			// we are still not in control.
			// the solution is simple: add an end-of-line comment to the field added in (in this example: the user field), so that the SQL becomes:
			// select * from username where user = "" OR "1"="1" -- and password = "whateveritis"
			// the result is that any additional constraints are commented out, and the last condition to have any effect is the one whose
			// HTTP param we are manipulating.
			// Note also that because this comment only needs to be added to the "SQL_OR_TRUE" and not to the equivalent SQL_AND_FALSE, because of the nature of the OR 
			// and AND conditions in SQL.
			// Corollary: If a particular RDBMS does not offer the ability to comment out the remainder of a line, we will not attempt to comment out anything in the query
			//            and we will simply hope that the *last* constraint in the SQL query is constructed from a HTTP parameter under our control.

			if (this.debugEnabled) log.debug("Doing Check 2, since check 1 did not match for "+ getBaseMsg().getRequestHeader().getURI());

			//Since the previous checks are attempting SQL injection, and may have actually succeeded in modifying the database (ask me how I know?!)
			//then we cannot rely on the database contents being the same as when the original query was last run (could be hours ago)
			//so to work around this, simply re-run the query again now at this point.
			//Note that we are not counting this request in our max number of requests to be issued
			refreshedmessage = getNewMsg();	
			sendAndReceive(refreshedmessage);			
			
			//String mResBodyNormal = getBaseMsg().getResponseBody().toString();
			mResBodyNormalUnstripped = refreshedmessage.getResponseBody().toString();
			mResBodyNormalStripped = this.stripOff(mResBodyNormalUnstripped, origParamValue);
			
			//boolean booleanBasedSqlInjectionFoundForParam = false;

			//try each of the AND syntax values in turn. 
			//Which one is successful will depend on the column type of the table/view column into which we are injecting the SQL.
			for (int i=0; 
					i<SQL_LOGIC_AND_TRUE.length && ! sqlInjectionFoundForUrl && doBooleanBased && 
					countBooleanBasedRequests < doBooleanMaxRequests; 
					i++) {
				//needs a new message for each type of AND to be issued
				HttpMessage msg2 = getNewMsg();
				String sqlBooleanAndTrueValue = TestSQLInjection.getURLDecode(origParamValue) + SQL_LOGIC_AND_TRUE[i];
				String sqlBooleanAndFalseValue = TestSQLInjection.getURLDecode(origParamValue) + SQL_LOGIC_AND_FALSE[i];

				setParameter(msg2, param, sqlBooleanAndTrueValue);

				//send the AND with an additional TRUE statement tacked onto the end. Hopefully it will return the same results as the original (to find a vulnerability)
				sendAndReceive(msg2);
				countBooleanBasedRequests++;

				//String resBodyAND = msg2.getResponseBody().toString();
				String resBodyANDTrueUnstripped = msg2.getResponseBody().toString();
				String resBodyANDTrueStripped = this.stripOff(resBodyANDTrueUnstripped, sqlBooleanAndTrueValue);
				
				//set up two little arrays to ease the work of checking the unstripped output, and then the stripped output
				String normalBodyOutput [] = {mResBodyNormalUnstripped, mResBodyNormalStripped};
				String andTrueBodyOutput [] = {resBodyANDTrueUnstripped, resBodyANDTrueStripped};
				boolean strippedOutput [] = {false, true};
				
				for (int booleanStrippedUnstrippedIndex = 0; booleanStrippedUnstrippedIndex < 2; booleanStrippedUnstrippedIndex++) {
					//if the results of the "AND 1=1" match the original query (using either the stipped or unstripped versions), we may be onto something. 
					if (andTrueBodyOutput[booleanStrippedUnstrippedIndex].compareTo(normalBodyOutput[booleanStrippedUnstrippedIndex]) == 0 ) {
						if (this.debugEnabled) log.debug("Check 2, " + (strippedOutput[booleanStrippedUnstrippedIndex] ? "STRIPPED": "UNSTRIPPED")+ " html output for AND TRUE condition ["+sqlBooleanAndTrueValue+"] matched (refreshed) original results for "+ refreshedmessage.getRequestHeader().getURI());
						//so they match. Was it a fluke? See if we get the same result by tacking on "AND 1 = 2" to the original
						HttpMessage msg2_and_false = getNewMsg();  

						setParameter(msg2_and_false, param, sqlBooleanAndFalseValue);

						sendAndReceive(msg2_and_false);
						countBooleanBasedRequests++;

						//String resBodyANDFalse = stripOff(msg2_and_false.getResponseBody().toString(), SQL_LOGIC_AND_FALSE[i]);
						//String resBodyANDFalse = msg2_and_false.getResponseBody().toString();
						String resBodyANDFalseUnstripped = msg2_and_false.getResponseBody().toString();
						String resBodyANDFalseStripped = this.stripOff(resBodyANDFalseUnstripped, sqlBooleanAndFalseValue);
						
						String andFalseBodyOutput [] = {resBodyANDFalseUnstripped, resBodyANDFalseStripped};
						
						//which AND False output should we compare? the stripped or the unstripped version?
						//depends on which one we used to get to here.. use the same as that..						
						
						// build an always false AND query.  Result should be different to prove the SQL works.
						if (andFalseBodyOutput[booleanStrippedUnstrippedIndex].compareTo(normalBodyOutput[booleanStrippedUnstrippedIndex]) != 0) {
							if (this.debugEnabled) log.debug("Check 2, " + (strippedOutput[booleanStrippedUnstrippedIndex] ? "STRIPPED": "UNSTRIPPED")+ " html output for AND FALSE condition ["+sqlBooleanAndFalseValue+"] differed from (refreshed) original results for "+ refreshedmessage.getRequestHeader().getURI());

							//it's different (suggesting that the "AND 1 = 2" appended on gave different results because it restricted the data set to nothing
							//Likely a SQL Injection. Raise it
							String extraInfo = null;
							if (strippedOutput [booleanStrippedUnstrippedIndex]) 
								extraInfo=Constant.messages.getString("ascanrules.sqlinjection.alert.booleanbased.extrainfo", sqlBooleanAndTrueValue, sqlBooleanAndFalseValue, "");
							else 
								extraInfo=Constant.messages.getString("ascanrules.sqlinjection.alert.booleanbased.extrainfo", sqlBooleanAndTrueValue, sqlBooleanAndFalseValue, "NOT ");							
							extraInfo=extraInfo + "\n"+ Constant.messages.getString("ascanrules.sqlinjection.alert.booleanbased.extrainfo.dataexists");
							
							//raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
							sqlInjectionAttack=sqlBooleanAndTrueValue;
							bingo(Alert.RISK_HIGH, Alert.WARNING, getName(), getDescription(), 
									null, //url
									param,  sqlInjectionAttack, 
									extraInfo, getSolution(), msg2);

							sqlInjectionFoundForUrl= true; 
						
							continue; //to the next entry in SQL_AND
						} else {
							//the results of the always false condition are the same as for the original unmodified parameter
							//this could be because there was *no* data returned for the original unmodified parameter
							//so consider the effect of adding comments to both the always true condition, and the always false condition
							//the first value to try..
							String orValue = TestSQLInjection.getURLDecode(origParamValue) + SQL_LOGIC_OR_TRUE[i];

							//this is where that comment comes in handy: if the RDBMS supports one-line comments, add one in to attempt to ensure that the 
							//condition becomes one that is effectively always true, returning ALL data (or as much as possible), allowing us to pinpoint the SQL Injection
							if (this.debugEnabled) log.debug("Check 2 , " + (strippedOutput[booleanStrippedUnstrippedIndex] ? "STRIPPED": "UNSTRIPPED")+ " html output for AND FALSE condition ["+sqlBooleanAndFalseValue+"] SAME as (refreshed) original results for "+ refreshedmessage.getRequestHeader().getURI() + " ### (forcing OR TRUE check) ");
							HttpMessage msg2_or_true = getNewMsg();  
							setParameter(msg2_or_true, param, orValue);
							sendAndReceive(msg2_or_true);
							countBooleanBasedRequests++;

							//String resBodyORTrue = stripOff(msg2_or_true.getResponseBody().toString(), orValue);
							//String resBodyORTrue = msg2_or_true.getResponseBody().toString();
							String resBodyORTrueUnstripped = msg2_or_true.getResponseBody().toString();
							String resBodyORTrueStripped = this.stripOff(resBodyORTrueUnstripped, orValue);
							
							String orTrueBodyOutput [] = {resBodyORTrueUnstripped, resBodyORTrueStripped};
							
							int compareOrToOriginal = orTrueBodyOutput[booleanStrippedUnstrippedIndex].compareTo(normalBodyOutput[booleanStrippedUnstrippedIndex]);
							if (compareOrToOriginal != 0) {

								if (this.debugEnabled) log.debug("Check 2, " + (strippedOutput[booleanStrippedUnstrippedIndex] ? "STRIPPED": "UNSTRIPPED")+ " html output for OR TRUE condition ["+orValue+"] different to (refreshed) original results for "+ refreshedmessage.getRequestHeader().getURI());

								//it's different (suggesting that the "OR 1 = 1" appended on gave different results because it broadened the data set from nothing to something
								//Likely a SQL Injection. Raise it
								String extraInfo = null;
								if (strippedOutput [booleanStrippedUnstrippedIndex]) 
									extraInfo=Constant.messages.getString("ascanrules.sqlinjection.alert.booleanbased.extrainfo", sqlBooleanAndTrueValue, orValue, "");
								else 
									extraInfo=Constant.messages.getString("ascanrules.sqlinjection.alert.booleanbased.extrainfo", sqlBooleanAndTrueValue, orValue, "NOT ");							
								extraInfo=extraInfo + "\n"+ Constant.messages.getString("ascanrules.sqlinjection.alert.booleanbased.extrainfo.datanotexists");
								
								//raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
								sqlInjectionAttack=orValue;
								bingo(Alert.RISK_HIGH, Alert.WARNING, getName(), getDescription(), 
										null, //url
										param,  sqlInjectionAttack, 
										extraInfo, getSolution(), msg2);

								sqlInjectionFoundForUrl = true; 
								//booleanBasedSqlInjectionFoundForParam = true;  //causes us to skip past the other entries in SQL_AND.  Only one will expose a vuln for a given param, since the database column is of only 1 type

								continue;
							}
						}
					}  //if the results of the "AND 1=1" match the original query, we may be onto something.
					else {
						//andTrueBodyOutput[booleanStrippedUnstrippedIndex].compareTo(normalBodyOutput[booleanStrippedUnstrippedIndex])
						//the results of the "AND 1=1" do NOT match the original query, for whatever reason (no sql injection, or the web page is not stable)
						if (this.debugEnabled) {
							log.debug("Check 2, " + (strippedOutput[booleanStrippedUnstrippedIndex] ? "STRIPPED": "UNSTRIPPED")+ " html output for AND condition ["+sqlBooleanAndTrueValue+"] does NOT match the (refreshed) original results for "+ refreshedmessage.getRequestHeader().getURI());
							Patch diffpatch = DiffUtils.diff( 
									new LinkedList<String> (Arrays.asList(normalBodyOutput[booleanStrippedUnstrippedIndex].split("\\n"))), 
									new LinkedList<String> (Arrays.asList(andTrueBodyOutput[booleanStrippedUnstrippedIndex].split("\\n"))));
							
							//int numberofDifferences = diffpatch.getDeltas().size();
							
							//and convert the list of patches to a String, joining using a newline
							StringBuilder tempDiff = new StringBuilder(250);
							for (Delta delta: diffpatch.getDeltas()) {
								String changeType = null;
								if ( delta.getType() == Delta.TYPE.CHANGE ) changeType = "Changed Text";
								else if ( delta.getType() == Delta.TYPE.DELETE ) changeType = "Deleted Text";
								else if ( delta.getType() == Delta.TYPE.INSERT ) changeType = "Inserted text";
								else changeType = "Unknown change type ["+delta.getType()+"]";
								
								tempDiff.append("\n("+changeType + ")\n");  //blank line before
								tempDiff.append("Output for Unmodified parameter: "+ delta.getOriginal()+"\n");
								tempDiff.append("Output for   modified parameter: "+ delta.getRevised()+"\n");
			                }
							log.debug("DIFFS: "+ tempDiff);
						}
					}

				}  //end of boolean logic output index (unstripped + stripped)
			}
			//end of check 2

			

			//Check 3: UNION based
			//for each SQL UNION combination to try
			for (int sqlUnionStringIndex = 0; 
					sqlUnionStringIndex <  SQL_UNION_APPENDAGES.length && !sqlInjectionFoundForUrl && doUnionBased && countUnionBasedRequests < doUnionMaxRequests; 
					sqlUnionStringIndex++) {

				//new message for each value we attack with
				HttpMessage msg3 = getNewMsg();
				String sqlUnionValue = origParamValue+ SQL_UNION_APPENDAGES[sqlUnionStringIndex];
				setParameter(msg3, param, sqlUnionValue);
				//send the message with the modified parameters
				sendAndReceive(msg3);
				countUnionBasedRequests++;

				//now check the results.. look first for UNION specific error messages in the output that were not there in the original output
				//and failing that, look for generic RDBMS specific error messages
				//TODO: maybe also try looking at a differentiation based approach?? Prone to false positives though.
				Iterator<String> errorPatternUnionIterator =  SQL_UNION_ERROR_TO_DBMS.keySet().iterator();

				while (errorPatternUnionIterator.hasNext() && ! sqlInjectionFoundForUrl) {
					String errorPatternKey = errorPatternUnionIterator.next();
					String errorPatternRDBMS =  SQL_UNION_ERROR_TO_DBMS.get(errorPatternKey);

					//Note: must escape the strings, in case they contain strings like "[Microsoft], which would be interpreted as regular character class regexps"
					Pattern errorPattern = Pattern.compile("\\Q"+errorPatternKey+"\\E", PATTERN_PARAM);

					//if the "error message" occurs in the result of sending the modified query, but did NOT occur in the original result of the original query
					//then we may may have a SQL Injection vulnerability
					StringBuilder sb = new StringBuilder();
					String sqlUnionBodyUnstripped = msg3.getResponseBody().toString();
					String sqlUnionBodyStripped = this.stripOff(sqlUnionBodyUnstripped, sqlUnionValue);
					
					Matcher matcherOrig = errorPattern.matcher(mResBodyNormalStripped);
					Matcher matcherSQLUnion = errorPattern.matcher(sqlUnionBodyStripped);
					boolean patternInOrig = matcherOrig.find();
					boolean patternInSQLUnion = matcherSQLUnion.find();
					
					//if (! matchBodyPattern(getBaseMsg(), errorPattern, null) && matchBodyPattern(msg3, errorPattern, sb)) {				
					if (! patternInOrig && patternInSQLUnion) {
						//Likely a UNION Based SQL Injection (by error message). Raise it
						String extraInfo = Constant.messages.getString("ascanrules.sqlinjection.alert.unionbased.extrainfo", errorPatternRDBMS, errorPatternKey);
						
						//raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
						sqlInjectionAttack=sqlUnionValue;
						bingo(Alert.RISK_HIGH, Alert.WARNING, getName() + " - " + errorPatternRDBMS, getDescription(), 
								refreshedmessage.getRequestHeader().getURI().getURI(), //url
								param,  sqlInjectionAttack, 
								extraInfo, getSolution(), msg3);

						//log it, as the RDBMS may be useful to know later (in subsequent checks, when we need to determine RDBMS specific behaviour, for instance)
						getKb().add(refreshedmessage.getRequestHeader().getURI(), "sql/"+errorPatternRDBMS, Boolean.TRUE);

						sqlInjectionFoundForUrl = true; 
						continue; 
					}
				} //end of the loop to check for RDBMS specific UNION error messages				
			} ////for each SQL UNION combination to try
			//end of check 3

		
			//###############################
			
			//check for columns used in the "order by" clause of a SQL statement. earlier tests will likely not catch these
			
			//append on " ASC -- " to the end of the original parameter. Grab the results.
			//if the results are different to the original (unmodified parameter) results, then bale
			//if the results are the same as for the original parameter value, then the parameter *might* be influencing the order by
			//	try again for "DESC": append on " DESC -- " to the end of the original parameter. Grab the results.
			//	if the results are the same as the original (unmodified parameter) results, then bale 
			//	(the results are not under our control, or there is no difference in the ordering, for some reason: 0 or 1 rows only, or ordering 
			//	by the first column alone is not sufficient to change the ordering of the data.)
			//	if the results were different to the original (unmodified parameter) results, then
			//		SQL injection!!
			
			//Since the previous checks are attempting SQL injection, and may have actually succeeded in modifying the database (ask me how I know?!)
			//then we cannot rely on the database contents being the same as when the original query was last run (could be hours ago)
			//so to work around this, simply re-run the query again now at this point.
			//Note that we are not counting this request in our max number of requests to be issued
			refreshedmessage = getNewMsg();	
			sendAndReceive(refreshedmessage);
			
			//String mResBodyNormal = getBaseMsg().getResponseBody().toString();
			mResBodyNormalUnstripped = refreshedmessage.getResponseBody().toString();
			mResBodyNormalStripped = this.stripOff(mResBodyNormalUnstripped, origParamValue);
			
			if (! sqlInjectionFoundForUrl && doOrderByBased && countOrderByBasedRequests < doOrderByMaxRequests ) {
				
					String modifiedParamValue=TestSQLInjection.getURLDecode(origParamValue) + " ASC "+ SQL_ONE_LINE_COMMENT;
					
					HttpMessage msg5 = getNewMsg();
					setParameter(msg5, param, modifiedParamValue);
					
					sendAndReceive(msg5);
					countOrderByBasedRequests++;
					
					String modifiedAscendingOutputUnstripped = msg5.getResponseBody().toString();
					String modifiedAscendingOutputStripped = this.stripOff(modifiedAscendingOutputUnstripped, modifiedParamValue);
					
					//set up two little arrays to ease the work of checking the unstripped output, and then the stripped output
					String normalBodyOutput [] = {mResBodyNormalUnstripped, mResBodyNormalStripped};
					String ascendingBodyOutput [] = {modifiedAscendingOutputUnstripped, modifiedAscendingOutputStripped};
					boolean strippedOutput [] = {false, true};
					
					for (int booleanStrippedUnstrippedIndex = 0; booleanStrippedUnstrippedIndex < 2; booleanStrippedUnstrippedIndex++) {
						//if the results of the modified request match the original query, we may be onto something. 
						if (ascendingBodyOutput[booleanStrippedUnstrippedIndex].compareTo(normalBodyOutput[booleanStrippedUnstrippedIndex]) == 0 ) {
							if (this.debugEnabled) log.debug("Check X, " + (strippedOutput[booleanStrippedUnstrippedIndex] ? "STRIPPED": "UNSTRIPPED")+ " html output for modified Order By parameter ["+modifiedParamValue+"] matched (refreshed) original results for "+ refreshedmessage.getRequestHeader().getURI());
							//confirm that a different parameter value generates different output, to minimise false positives
							
							//use the descending order this time
							String modifiedParamValueConfirm=TestSQLInjection.getURLDecode(origParamValue) + " DESC "+ SQL_ONE_LINE_COMMENT;
							
							HttpMessage msg5Confirm = getNewMsg();
							setParameter(msg5Confirm, param, modifiedParamValueConfirm);
							
							sendAndReceive(msg5Confirm);
							countOrderByBasedRequests++;
							
							String confirmOrderByOutputUnstripped = msg5Confirm.getResponseBody().toString();
							String confirmOrderByOutputStripped = this.stripOff(confirmOrderByOutputUnstripped, modifiedParamValueConfirm);
							
							//set up two little arrays to ease the work of checking the unstripped output or the stripped output
							String confirmOrderByBodyOutput [] = {confirmOrderByOutputUnstripped, confirmOrderByOutputStripped};
							
							if (confirmOrderByBodyOutput[booleanStrippedUnstrippedIndex].compareTo(normalBodyOutput[booleanStrippedUnstrippedIndex]) != 0 ) {
								//the confirm query did not return the same results.  This means that arbitrary queries are not all producing the same page output.
								//this means the fact we earlier reproduced the original page output with a modified parameter was not a coincidence
								
								//Likely a SQL Injection. Raise it
								String extraInfo = null;
								if (strippedOutput [booleanStrippedUnstrippedIndex]) 
									extraInfo=Constant.messages.getString("ascanrules.sqlinjection.alert.orderbybased.extrainfo", modifiedParamValue, "");
								else 
									extraInfo=Constant.messages.getString("ascanrules.sqlinjection.alert.orderbybased.extrainfo", modifiedParamValue, "NOT ");							
								
								//raise the alert, and save the attack string for the "Authentication Bypass" alert, if necessary
								sqlInjectionAttack=modifiedParamValue;
								bingo(Alert.RISK_HIGH, Alert.WARNING, getName(), getDescription(), 
										null, //url
										param,  sqlInjectionAttack, 
										extraInfo, getSolution(), msg5);

								sqlInjectionFoundForUrl= true; 								
							}
						}
					}
				
				
			}				

			
			//###############################
			
			//if a sql injection was found, we should check if the page is flagged as a login page
			//in any of the contexts.  if it is, raise an "SQL Injection - Authentication Bypass" alert in addition to the alerts already raised
			if (sqlInjectionFoundForUrl) {
				boolean loginUrl = false;
				//log.debug("### A SQL Injection may lead to auth bypass..");
	
				//are we dealing with a login url in any of the contexts? 
				ExtensionAuth extAuth = (ExtensionAuth) Control.getSingleton().getExtensionLoader().getExtension(ExtensionAuth.NAME);				
				URI requestUri = getBaseMsg().getRequestHeader().getURI();
				
				//using the session, get the list of contexts for the url
				List<Context> contextList = extAuth.getModel().getSession().getContextsForUrl(requestUri.getURI());
				
				//now loop, and see if the url is a login url in each of the contexts in turn..
				for (Context context: contextList) {
					HttpMessage loginRequest = extAuth.getApi().getLoginRequest(context.getIndex());
					if ( loginRequest != null) {
						URI loginUri = loginRequest.getRequestHeader().getURI();
						if (	requestUri.getScheme().equals(loginUri.getScheme()) && 
								requestUri.getHost().equals(loginUri.getHost()) &&
								requestUri.getPort() == loginUri.getPort() &&
								requestUri.getPath().equals(loginUri.getPath()) ) {
							//we got this far.. only the method (GET/POST), user details, query params, fragment, and POST params 
							//are possibly different from the login page.
							loginUrl = true;
							//DEBUG only
							//log.debug("##### The right login page was found");
							break;
						} else {
							//log.debug("#### This is not the login page you're looking for");
						}
					} else {
						//log.debug("### This context has no login page set");
					}
				}
				if (loginUrl) {
					//log.debug("##### Raising auth bypass");
					//raise the alert, using the custom name and description
					String vulnname=Constant.messages.getString("ascanrules.sqlinjection.authbypass.name");
        			String vulndesc=Constant.messages.getString("ascanrules.sqlinjection.authbypass.desc");
        			
        			//raise the alert, using the attack string stored earlier for this purpose					
					bingo(Alert.RISK_HIGH, Alert.WARNING, vulnname, vulndesc, 
							refreshedmessage.getRequestHeader().getURI().getURI(), //url
							param,  sqlInjectionAttack, 
							"", getSolution(), getBaseMsg());

				} //not a login page
			} //no sql Injection Found For Url

		} catch (Exception e) {
			//Do not try to internationalise this.. we need an error message in any event.. 
			//if it's in English, it's still better than not having it at all. 
			log.error("An error occurred checking a url for SQL Injection vulnerabilities", e);
		}
	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}
		
	/**
	 * Replace body by stripping of pattern string.  The URLencoded
	 * pattern will also be stripped off.  The URL decoded pattern will not be stripped off, 
	 * as this is not necessary of rour purposes, and causes issues when attempting to decode parameter values such as '%' (a single percent character)
	 * This is mainly used for stripping off a testing string in HTTP response
	 * for comparison against the original response.
	 * Reference: TestInjectionSQL
	 * @param body
	 * @param pattern
	 * @return
	 */
	protected String stripOff(String body, String pattern) {
	    String urlEncodePattern = getURLEncode(pattern);
	    String htmlEncodePattern1 = getHTMLEncode(pattern);
	    String htmlEncodePattern2 = getHTMLEncode(urlEncodePattern);
	    String result = body.replaceAll("\\Q" + pattern + "\\E", "").replaceAll("\\Q" + urlEncodePattern + "\\E", "");
	    result = result.replaceAll("\\Q" + htmlEncodePattern1 + "\\E", "").replaceAll("\\Q" + htmlEncodePattern2 + "\\E", "");
	    return result;
	}

	/**
	 * decode method that is aware of %, and will decode it as simply %, if it occurs
	 * @param msg
	 * @return
	 */
	public static String getURLDecode(String msg) {
	    String result = "";
        try {
            result = URLDecoder.decode(msg, "UTF8");
        } catch (Exception e) {
        	//if it can't decode it, return the original string!
        	return msg;
        }
        return result;
	}
	
}


