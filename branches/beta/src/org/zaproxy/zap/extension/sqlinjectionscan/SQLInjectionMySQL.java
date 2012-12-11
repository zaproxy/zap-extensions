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
package org.zaproxy.zap.extension.sqlinjectionscan;

import java.text.MessageFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.TreeSet;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;


/**
 * TODO: do not do dangerous operations unless the Mode is right!
 * TODO: implement checks in Header fields (currently does Cookie values, form fields, and url parameters)
 * TODO: change the Alert Titles.
 * 
 * The SQLInjectionMySQL plugin identifies MySQL specific SQL Injection vulnerabilities
 * using MySQL specific syntax.  If it doesn't use MySQL specific syntax, it belongs in the generic SQLInjection class! 
 * Note the ordering of checks, for efficiency is : 
 * 1) Error based (N/A)
 * 2) Boolean Based (N/A - uses standard syntax)
 * 3) UNION based (N/A - uses standard syntax)
 * 4) Stacked (N/A - uses standard syntax)
 * 5) Blind/Time Based (Yes - uses specific syntax)
 * 
 * See the following for some great MySQL specific tricks which could be integrated here
 * http://www.websec.ca/kb/sql_injection#MySQL_Stacked_Queries
 * http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
 * 
 *  @author Colm O'Flaherty, Encription Ireland Ltd
 */
public class SQLInjectionMySQL extends AbstractAppPlugin {
	
	private boolean doTimeBased = false;
	
	private int doTimeMaxRequests = 0;
	

	/**
	 * MySQL one-line comment
	 */
	public static final String SQL_ONE_LINE_COMMENT = " -- ";

	/**
	 * create a map of SQL related error message fragments, and map them back to the RDBMS that they are associated with
	 * keep the ordering the same as the order in which the values are inserted, to allow the more (subjectively judged) common cases to be tested first
	 * Note: these should represent actual (driver level) error messages for things like syntax error, 
	 * otherwise we are simply guessing that the string should/might occur.
	 */
	private static final Map<String, String> SQL_ERROR_TO_DBMS = new LinkedHashMap<>();
	static {
		SQL_ERROR_TO_DBMS.put("com.mysql.jdbc.exceptions", "MySQL");
		SQL_ERROR_TO_DBMS.put("org.gjt.mm.mysql", "MySQL");
		//Note: only MYSQL mappings here.
	}
	
	
	/**
	 * MySQL specific time based injection strings. each for 5 seconds
	 */
	
	//issue with "+" symbols in here: 
	//we cannot encode them here as %2B, as then the database gets them double encoded as %252B
	//we cannot leave them as unencoded '+' characters either, as then they are NOT encoded by the HttpMessage.setGetParams (x) or by AbstractPlugin.sendAndReceive (HttpMessage)
	//and are seen by the database as spaces :(
	//in short, we cannot use the "+" character in parameters, unless we mean to use it as a space character!!!! Particularly Nasty.
	//Workaround: use RDBMS specific functions like "CONCAT(a,b,c)" which mean parsing the original value into the middle of the parameter value to be passed, 
	//rather than just appending to it
	//Issue: this technique does not close the open ' or " in the query.. so do not use it..
	//Note: <<<<ORIGINALVALUE>>>> is replaced with the original parameter value at runtime in these examples below (see * comment)
	//TODO: maybe add support for ')' after the original value, before the sleeps
	private static String[] SQL_MYSQL_TIME_REPLACEMENTS = {
		"<<<<ORIGINALVALUE>>>> / sleep(5) ",				// MySQL >= 5.0.12. Might work if "SET sql_mode='STRICT_TRANS_TABLES'" is OFF. Try without a comment, to target use of the field in the SELECT clause, but also in the WHERE clauses.
		"<<<<ORIGINALVALUE>>>>' / sleep(5) / '",			// MySQL >= 5.0.12. Might work if "SET sql_mode='STRICT_TRANS_TABLES'" is OFF. Try without a comment, to target use of the field in the SELECT clause, but also in the WHERE clauses.
		"<<<<ORIGINALVALUE>>>>\" / sleep(5) / \"",			// MySQL >= 5.0.12. Might work if "SET sql_mode='STRICT_TRANS_TABLES'" is OFF. Try without a comment, to target use of the field in the SELECT clause, but also in the WHERE clauses.
		"<<<<ORIGINALVALUE>>>> where 0 in (select sleep(5) )" + SQL_ONE_LINE_COMMENT,	// MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE clause.
		"<<<<ORIGINALVALUE>>>>' where 0 in (select sleep(5) )" + SQL_ONE_LINE_COMMENT,	// MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE clause.
		"<<<<ORIGINALVALUE>>>>\" where 0 in (select sleep(5) )" + SQL_ONE_LINE_COMMENT,// MySQL >= 5.0.12. Param in SELECT/UPDATE/DELETE clause.
		"<<<<ORIGINALVALUE>>>> and 0 in (select sleep(5) )" + SQL_ONE_LINE_COMMENT, 	// MySQL >= 5.0.12. Param in WHERE clause.
		"<<<<ORIGINALVALUE>>>>' and 0 in (select sleep(5) )" + SQL_ONE_LINE_COMMENT, 	// MySQL >= 5.0.12. Param in WHERE clause.
		"<<<<ORIGINALVALUE>>>>\" and 0 in (select sleep(5) )" + SQL_ONE_LINE_COMMENT, 	// MySQL >= 5.0.12. Param in WHERE clause.
		"<<<<ORIGINALVALUE>>>> or 0 in (select sleep(5) )" + SQL_ONE_LINE_COMMENT,		// MySQL >= 5.0.12. Param in WHERE clause. 
		"<<<<ORIGINALVALUE>>>>' or 0 in (select sleep(5) )" + SQL_ONE_LINE_COMMENT, 	// MySQL >= 5.0.12. Param in WHERE clause. 
		"<<<<ORIGINALVALUE>>>>\" or 0 in (select sleep(5) )" + SQL_ONE_LINE_COMMENT, 	// MySQL >= 5.0.12. Param in WHERE clause.		
	};
	

	/**
	 * plugin dependencies (none! not even "SQL Injection")
	 */
	private static final String[] dependency = {};    	

	/**
	 * for logging.
	 */
	private static Logger log = Logger.getLogger(SQLInjectionMySQL.class);

	/**
	 * determines if we should output Debug level logging
	 */
	private boolean debugEnabled = log.isDebugEnabled();


	/**
	 * contains the internationalisation (i18n) messages. Must be statically initialised, since messages is accessed before the plugin is initialised (using init)
	 */
	private ResourceBundle messages = ResourceBundle.getBundle(
			this.getClass().getPackage().getName() + ".Messages", Constant.getLocale());

	/**
	 * gets the internationalised message corresponding to the key
	 * @param key the key to look up the internationalised message
	 * @return the internationalised message corresponding to the key
	 */
	public String getString(String key) {
		try {
			return messages.getString(key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	/**
	 * gets the internationalised message corresponding to the key, using the parameters supplied
	 * @param key the key to look up the internationalised message
	 * @param params the parameters used to internationalise the message
	 * @return the internationalised message corresponding to the key, using the parameters supplied
	 */
	public String getString(String key, Object... params  ) {
		try {
			return MessageFormat.format(messages.getString(key), params);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	@Override
	public int getId() {
		return 40019;
	}

	@Override
	public String getName() {
		return getString("sqlinjection.mysql.name");
	}

	@Override
	public String[] getDependency() {        
		return dependency;
	}

	@Override
	public String getDescription() {
		return getString("sqlinjection.desc");
	}

	@Override
	public int getCategory() {
		return Category.INJECTION;
	}

	@Override
	public String getSolution() {
		return getString("sqlinjection.soln");
	}

	@Override
	public String getReference() {
		return getString("sqlinjection.refs");  
	}

	@Override
	public void init() {
		//DEBUG: turn on for debugging
		//TODO: turn this off
		//log.setLevel(org.apache.log4j.Level.DEBUG);
		//this.debugEnabled = true;

		if ( this.debugEnabled ) log.debug("Initialising");
		
		//TODO: debug only
		//this.setAttackStrength(AttackStrength.INSANE);
		
		//set up what we are allowed to do, depending on the attack strength that was set.
		if ( this.getAttackStrength() == AttackStrength.LOW ) {
			doTimeBased=true; doTimeMaxRequests=3;
		} else if ( this.getAttackStrength() == AttackStrength.MEDIUM) {
			doTimeBased=true; doTimeMaxRequests=5;
		} else if ( this.getAttackStrength() == AttackStrength.HIGH) {
			doTimeBased=true; doTimeMaxRequests=10;
		} else if ( this.getAttackStrength() == AttackStrength.INSANE) {
			doTimeBased=true; doTimeMaxRequests=100;
		}
	}


	/**
	 * scans for SQL Injection vulnerabilities, using MySQL specific syntax.  If it doesn't use specifically MySQL syntax, it does not belong in here, but in SQLInjection 
	 */
	@Override
	public void scan() {

		//as soon as we find a single SQL injection on the url, skip out. Do not look for SQL injection on a subsequent parameter on the same URL
		//for performance reasons.
		boolean sqlInjectionFoundForUrl = false;
		
		//DEBUG only
		//log.setLevel(org.apache.log4j.Level.DEBUG);
		//this.debugEnabled = true;

		try {
			//Timing Baseline check: we need to get the time that it took the original query, to know if the time based check is working correctly..
			HttpMessage msgTimeBaseline = getNewMsg();
			long originalTimeStarted = System.currentTimeMillis();
			try {
				sendAndReceive(msgTimeBaseline);
			}
			catch (java.net.SocketTimeoutException e) {
				//to be expected occasionally, if the base query was one that contains some parameters exploiting time based SQL injection?
				if ( this.debugEnabled ) log.debug("The Base Time Check timed out on ["+msgTimeBaseline.getRequestHeader().getMethod()+"] URL ["+msgTimeBaseline.getRequestHeader().getURI().getURI()+"]");
			}
			long originalTimeUsed = System.currentTimeMillis() - originalTimeStarted;
			//end of timing baseline check
			
			
			TreeSet<HtmlParameter> htmlParams = new TreeSet<> (); 
			htmlParams.addAll(getBaseMsg().getFormParams());  //add in the POST params
			htmlParams.addAll(getBaseMsg().getUrlParams()); //add in the GET params

			//for each parameter in turn
			for (Iterator<HtmlParameter> iter = htmlParams.iterator(); iter.hasNext() && ! sqlInjectionFoundForUrl; ) {
				
				int countTimeBasedRequests = 0;		

				HtmlParameter currentHtmlParameter = iter.next();
				if ( this.debugEnabled ) log.debug("Scanning URL ["+ getBaseMsg().getRequestHeader().getMethod()+ "] ["+ getBaseMsg().getRequestHeader().getURI() + "], ["+ currentHtmlParameter.getType()+"] field ["+ currentHtmlParameter.getName() + "] with value ["+currentHtmlParameter.getValue()+"] for SQL Injection");    			
				
				//Check 3: check for time based SQL Injection
				//MySQL specific time based SQL injection checks

				for (int timeBasedSQLindex = 0; 
						timeBasedSQLindex < SQL_MYSQL_TIME_REPLACEMENTS.length && ! sqlInjectionFoundForUrl && doTimeBased && countTimeBasedRequests < doTimeMaxRequests; 
						timeBasedSQLindex ++) {
					HttpMessage msg3 = getNewMsg();
					String newTimeBasedInjectionValue = SQL_MYSQL_TIME_REPLACEMENTS[timeBasedSQLindex].replace ("<<<<ORIGINALVALUE>>>>", currentHtmlParameter.getValue());
					
					if ( currentHtmlParameter.getType().equals (HtmlParameter.Type.url)) {
						TreeSet <HtmlParameter> requestParams = msg3.getUrlParams(); //get parameters
						requestParams.remove(currentHtmlParameter);
						requestParams.add(new HtmlParameter(currentHtmlParameter.getType(), currentHtmlParameter.getName(), newTimeBasedInjectionValue)); 
						msg3.setGetParams(requestParams); //url parameters       		        			        			        		
					}  //end of the URL parameter code
					else if ( currentHtmlParameter.getType().equals (HtmlParameter.Type.form)) {
						TreeSet <HtmlParameter> requestParams = msg3.getFormParams(); //form parameters
						requestParams.remove(currentHtmlParameter);
						//new HtmlParameter ();
						requestParams.add(new HtmlParameter(currentHtmlParameter.getType(), currentHtmlParameter.getName(), newTimeBasedInjectionValue));
						msg3.setFormParams(requestParams); //form parameters       		        			        			        		
					}  //end of the URL parameter code
					else if ( currentHtmlParameter.getType().equals (HtmlParameter.Type.cookie)) {
						TreeSet <HtmlParameter> requestParams = msg3.getCookieParams(); //cookie parameters
						requestParams.remove(currentHtmlParameter);
						requestParams.add(new HtmlParameter(currentHtmlParameter.getType(), currentHtmlParameter.getName(), newTimeBasedInjectionValue));
						msg3.setCookieParams(requestParams); //cookie parameters
					}

					//send it.
					long modifiedTimeStarted = System.currentTimeMillis();
					try {
						sendAndReceive(msg3);
						countTimeBasedRequests++;
					}
					catch (java.net.SocketTimeoutException e) {
						//to be expected occasionally, if the contains some parameters exploiting time based SQL injection
						if ( this.debugEnabled ) log.debug("The time check query timed out on ["+msgTimeBaseline.getRequestHeader().getMethod()+"] URL ["+msgTimeBaseline.getRequestHeader().getURI().getURI()+"] on ["+currentHtmlParameter.getType()+"] field: ["+currentHtmlParameter.getName()+"]");
					}
					long modifiedTimeUsed = System.currentTimeMillis() - modifiedTimeStarted;

					if ( this.debugEnabled ) log.debug ("Time Based SQL Injection test: ["+ newTimeBasedInjectionValue + "] on ["+currentHtmlParameter.getType()+"] field: ["+currentHtmlParameter.getName()+"] with value ["+newTimeBasedInjectionValue+"] took "+ modifiedTimeUsed + "ms, where the original took "+ originalTimeUsed + "ms");

					if (modifiedTimeUsed >= (originalTimeUsed + 5000)) {  
						//takes more than 5 extra seconds => likely time based SQL injection. Raise it 

						//Likely a SQL Injection. Raise it
						String extraInfo = getString("sqlinjection.alert.timebased.extrainfo", newTimeBasedInjectionValue, modifiedTimeUsed, currentHtmlParameter.getValue(), originalTimeUsed);
						String attack = getString("sqlinjection.alert.booleanbased.attack", currentHtmlParameter.getType(), currentHtmlParameter.getName(), newTimeBasedInjectionValue);

						//raise the alert
						bingo(Alert.RISK_HIGH, Alert.WARNING, getName() + " - Time Based", getDescription(), 
								getBaseMsg().getRequestHeader().getURI().getURI(), //url
								"["+currentHtmlParameter.getType()+"] "+ currentHtmlParameter.getName(),  attack, 
								extraInfo, getSolution(), msg3);

						log.info("A likely Time Based SQL Injection Vulnerability has been found with ["+msg3.getRequestHeader().getMethod()+"] URL ["+msg3.getRequestHeader().getURI().getURI()+"] on "+currentHtmlParameter.getType()+" field: ["+currentHtmlParameter.getName()+"]");

						sqlInjectionFoundForUrl = true; 
						continue;
					} //query took longer than the amount of time we attempted to retard it by						
				}  //for each time based SQL index
				//end of Check 3: end of check for time based SQL Injection

			} //end of the for loop around the parameter list

		} catch (Exception e) {
			//Do not try to internationalise this.. we need an error message in any event.. 
			//if it's in English, it's still better than not having it at all. 
			log.error("An error occurred checking a url for MySQL SQL Injection vulnerabilities", e);
		}
	}
	
	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

}


