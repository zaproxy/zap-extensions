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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;


/**
 * The SQLInjectionSQLite plugin identifies SQLite specific SQL Injection vulnerabilities
 * using SQLite specific syntax.  If it doesn't use SQLite specific syntax, it belongs in the generic SQLInjection class! 
 * 
 *  @author 70pointer
 */
public class SQLInjectionSQLite extends AbstractAppParamPlugin {
	
	private boolean doTimeBased = false;
	
	private int doTimeMaxRequests = 0;
	
	/**
	 * SQLite one-line comment
	 */
	public static final String SQL_ONE_LINE_COMMENT = "--";

	/**
	 * create a map of SQL related error message fragments, and map them back to the RDBMS that they are associated with
	 * keep the ordering the same as the order in which the values are inserted, to allow the more (subjectively judged) common cases to be tested first
	 * Note: these should represent actual (driver level) error messages for things like syntax error, 
	 * otherwise we are simply guessing that the string should/might occur.
	 */
	private static final Map<String, String> SQL_ERROR_TO_DBMS = new LinkedHashMap<>();
	static {
		SQL_ERROR_TO_DBMS.put("org.sqlite", "SQLite");
	}
	
	
	/**
	 * SQLite specific time based injection strings, where each tries to delay for 5 seconds
	 */
	
	//Note: <<<<ORIGINALVALUE>>>> is replaced with the original parameter value at runtime in these examples below
	//TODO: maybe add support for ')' after the original value, before the sleeps
	private static String[] SQL_SQLITE_TIME_REPLACEMENTS = {
		//omitting original param
		"case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then 1 else 1 end ",				//integer
		"' | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end | '", 	//character/string (single quote)
		"\" | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end | \"",//character/string (double quote)
		
		"case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then 1 else 1 end " + SQL_ONE_LINE_COMMENT,			//integer
		"' | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end " + SQL_ONE_LINE_COMMENT,	//character/string (single quote)
		"\" | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end " + SQL_ONE_LINE_COMMENT,	//character/string (double quote)				

		//with the original parameter
		"<<<<ORIGINALVALUE>>>> * case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then 1 else 1 end ",				//integer
		"<<<<ORIGINALVALUE>>>>' | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end | '",		//character/string (single quote)
		"<<<<ORIGINALVALUE>>>>\" | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end | \"",	//character/string (double quote)
		
		"<<<<ORIGINALVALUE>>>> * case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then 1 else 1 end " + SQL_ONE_LINE_COMMENT,		//integer
		"<<<<ORIGINALVALUE>>>>' | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end " + SQL_ONE_LINE_COMMENT,	//character/string (single quote)
		"<<<<ORIGINALVALUE>>>>\" | case randomblob(<<<<NUMBLOBBYTES>>>>) when not null then \"\" else \"\" end " + SQL_ONE_LINE_COMMENT,//character/string (double quote)
	};
	
	/**
	 * set depending on the attack strength / threshold
	 */
	private long maxBlobBytes = 0; 
	private long minBlobBytes = 100000;
	private long parseDelayDifference = 0; 
	private long incrementalDelayIncreasesForAlert = 0;
	
	private char[] RANDOM_PARAMETER_CHARS = "abcdefghijklmnopqrstuvwyxz0123456789".toCharArray();
	

	/**
	 * plugin dependencies (none! not even "SQL Injection")
	 */
	private static final String[] dependency = {};    	

	/**
	 * for logging.
	 */
	private static Logger log = Logger.getLogger(SQLInjectionSQLite.class);

	/**
	 * determines if we should output Debug level logging
	 */
	private boolean debugEnabled = log.isDebugEnabled();

	@Override
	public int getId() {
		return 40024;
	}

	@Override
	public String getName() {
		return Constant.messages.getString("ascanalpha.sqlinjection.sqlite.name");
	}

	@Override
	public String[] getDependency() {        
		return dependency;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("ascanalpha.sqlinjection.desc");
	}

	@Override
	public int getCategory() {
		return Category.INJECTION;
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString("ascanalpha.sqlinjection.soln");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString("ascanalpha.sqlinjection.refs");  
	}

	@Override
	public void init() {
		if ( this.debugEnabled ) log.debug("Initialising");
		
		//set up what we are allowed to do, depending on the attack strength that was set.
		if ( this.getAttackStrength() == AttackStrength.LOW ) {
			doTimeBased=true; 
			doTimeMaxRequests=15;
			this.maxBlobBytes = 1000000000;
		} else if ( this.getAttackStrength() == AttackStrength.MEDIUM) {
			doTimeBased=true; 
			doTimeMaxRequests=35; 
			this.maxBlobBytes = 1000000000;
		} else if ( this.getAttackStrength() == AttackStrength.HIGH) {
			doTimeBased=true; 
			doTimeMaxRequests=50;
			this.maxBlobBytes = 1000000000;
		} else if ( this.getAttackStrength() == AttackStrength.INSANE) {
			doTimeBased=true; 
			doTimeMaxRequests=500;
			this.maxBlobBytes = 1000000000;
		}
		
		//the allowable difference between a parse delay and an attack delay is controlled by the threshold
		if ( this.getAlertThreshold() == AlertThreshold.LOW ) {
			parseDelayDifference = 100;
			incrementalDelayIncreasesForAlert=1;
		} else if ( this.getAlertThreshold() == AlertThreshold.MEDIUM ) {
			parseDelayDifference = 200;
			incrementalDelayIncreasesForAlert=2;
		} else if ( this.getAlertThreshold() == AlertThreshold.DEFAULT ) {
			parseDelayDifference = 200;
			incrementalDelayIncreasesForAlert=2;
		} else if ( this.getAlertThreshold() == AlertThreshold.HIGH ) {
			parseDelayDifference = 400;
			incrementalDelayIncreasesForAlert=3;
		}
	}


	/**
	 * scans for SQL Injection vulnerabilities, using SQLite specific syntax.  If it doesn't use specifically SQLite syntax, it does not belong in here, but in TestSQLInjection 
	 */
	@Override
	public void scan(HttpMessage originalMessage, String paramName, String originalParamValue) {

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
			//if the time was very slow (because JSP was being compiled on first call, for instance)
			//then the rest of the time based logic will fail.  Lets double-check for that scenario by requesting the url again.  
			//If it comes back in a more reasonable time, we will use that time instead as our baseline.  If it come out in a slow fashion again, 
			//we will abort the check on this URL, since we will only spend lots of time trying request, when we will (very likely) not get positive results.
			if (originalTimeUsed > 5000) {
				long originalTimeStarted2 = System.currentTimeMillis();
				try {
					sendAndReceive(msgTimeBaseline);
				}
				catch (java.net.SocketTimeoutException e) {
					//to be expected occasionally, if the base query was one that contains some parameters exploiting time based SQL injection?
					if ( this.debugEnabled ) log.debug("Base Time Check 2 timed out on ["+msgTimeBaseline.getRequestHeader().getMethod()+"] URL ["+msgTimeBaseline.getRequestHeader().getURI().getURI()+"]");
				}
				long originalTimeUsed2 = System.currentTimeMillis() - originalTimeStarted2;
				if ( originalTimeUsed2 > 5000 ) {
					//no better the second time around.  we need to bale out.
					if ( this.debugEnabled ) log.debug("Both base time checks 1 and 2 for ["+msgTimeBaseline.getRequestHeader().getMethod()+"] URL ["+msgTimeBaseline.getRequestHeader().getURI().getURI()+"] are way too slow to be usable for the purposes of checking for time based SQL Injection checking.  We are aborting the check on this particular url.");
					return;
				} else {
					//phew.  the second time came in within the limits. use the later timing details as the base time for the checks.
					originalTimeUsed = originalTimeUsed2;
					originalTimeStarted = originalTimeStarted2;
				}
			}		
			//end of timing baseline check
						
			int countTimeBasedRequests = 0;	
			if ( this.debugEnabled ) log.debug("Scanning URL ["+ getBaseMsg().getRequestHeader().getMethod()+ "] ["+ getBaseMsg().getRequestHeader().getURI() + "], ["+ paramName + "] with value ["+originalParamValue+"] for SQL Injection");
			
			//SQLite specific time-based SQL injection checks
			for (int timeBasedSQLindex = 0; 
					timeBasedSQLindex < SQL_SQLITE_TIME_REPLACEMENTS.length && doTimeBased && countTimeBasedRequests < doTimeMaxRequests;
					timeBasedSQLindex ++
					) {
				//since we have no means to create a deterministic delay in SQLite, we need to take a different approach:
				//in each iteration, increase the number of random blobs for SQLite to create.  If we can detect an increasing delay, we know
				//that the payload has been successfully injected.
				int numberOfSequentialIncreases=0;
				String detectableDelayParameter = null;
				long detectableDelay=0;
				String maxDelayParameter = null; 
				long maxDelay=0;
				HttpMessage detectableDelayMessage=null;
				long previousDelay = originalTimeUsed;
				boolean potentialTimeBasedSQLInjection= false;
				boolean timeExceeded = false;
				
				for (long numBlobsToCreate = minBlobBytes; 
						numBlobsToCreate<= this.maxBlobBytes && !timeExceeded && numberOfSequentialIncreases < incrementalDelayIncreasesForAlert; 
						numBlobsToCreate*=10) {
					
					HttpMessage msgDelay = getNewMsg();
					String newTimeBasedInjectionValue = SQL_SQLITE_TIME_REPLACEMENTS[timeBasedSQLindex].replace ("<<<<ORIGINALVALUE>>>>", originalParamValue);
					newTimeBasedInjectionValue = newTimeBasedInjectionValue.replace ("<<<<NUMBLOBBYTES>>>>", new Long(numBlobsToCreate).toString());
					setParameter(msgDelay, paramName, newTimeBasedInjectionValue);
					
					if ( this.debugEnabled ) log.debug("\nTrying '"+newTimeBasedInjectionValue + "'. The number of Sequential Increases already is "+ numberOfSequentialIncreases); 

					//send it.
					long modifiedTimeStarted = System.currentTimeMillis();
					try {
						sendAndReceive(msgDelay);
						countTimeBasedRequests++;
					}
					catch (java.net.SocketTimeoutException e) {
						//to be expected occasionally, if the contains some parameters exploiting time based SQL injection
						if ( this.debugEnabled ) log.debug("The time check query timed out on ["+msgTimeBaseline.getRequestHeader().getMethod()+"] URL ["+msgTimeBaseline.getRequestHeader().getURI().getURI()+"] on field: ["+paramName+"]");
					}
					long modifiedTimeUsed = System.currentTimeMillis() - modifiedTimeStarted;
					
					//cap the time we will delay by to 10 seconds
					if (modifiedTimeUsed > 10000) timeExceeded = true;
					
					boolean parseTimeEquivalent = false;
					if ( modifiedTimeUsed > previousDelay) {						
						if ( this.debugEnabled ) log.debug("The response time "+ modifiedTimeUsed + " is > the previous response time "+ previousDelay);
						//in order to rule out false positives due to the increasing SQL parse time for longer parameter values
						//we send a random (alphanumeric only) string value of the same length as the attack parameter  
						//we expect the response time for the SQLi attack to be greater than or equal to the response time for 
						//the random alphanumeric string parameter
						//if this is not the case, then we assume that the attack parameter is not a potential SQL injection causing payload.
						HttpMessage msgParseDelay = getNewMsg();
						String parseDelayCheckParameter = RandomStringUtils.random(newTimeBasedInjectionValue.length(), RANDOM_PARAMETER_CHARS);
						setParameter(msgParseDelay, paramName, parseDelayCheckParameter);
						long parseDelayTimeStarted = System.currentTimeMillis();
						sendAndReceive(msgParseDelay);
						countTimeBasedRequests++;
						long parseDelayTimeUsed = System.currentTimeMillis() - parseDelayTimeStarted;
						
						//figure out if the attack delay and the (non-sql-injection) parse delay are within X ms of each other..
						parseTimeEquivalent = ( Math.abs(modifiedTimeUsed - parseDelayTimeUsed) < this.parseDelayDifference );
						if ( this.debugEnabled ) log.debug("The parse time a random parameter of the same length is "+ parseDelayTimeUsed + ", so the attack and random parameter are "+ (parseTimeEquivalent?"":"NOT ") + "equivalent (given the user defined attack threshold)");
					}
						
					if ( modifiedTimeUsed > previousDelay && !parseTimeEquivalent) {
						
						maxDelayParameter = newTimeBasedInjectionValue; 
						maxDelay=modifiedTimeUsed;
						
						//potential for SQL injection, detectable with "numBlobsToCreate" random blobs being created..
						numberOfSequentialIncreases++; 
						if (!potentialTimeBasedSQLInjection) {
							if (log.isDebugEnabled()) log.debug("Setting the Detectable Delay parameter to '"+ newTimeBasedInjectionValue + "'");
							detectableDelayParameter = newTimeBasedInjectionValue; 
							detectableDelay=modifiedTimeUsed;
							detectableDelayMessage=msgDelay;
						}
						potentialTimeBasedSQLInjection = true;
					} else {
						//either no SQL injection, invalid SQL syntax, or timing difference is not detectable with "numBlobsToCreate" random blobs being created.
						//keep trying with larger numbers of "numBlobsToCreate", since that's the thing we can most easily control and verify
						//note also: if for some reason, an earlier attack with a smaller number of blobs indicated there might be a vulnerability
						//then this case will rule that out if it was a fluke... 
						//the timing delay must keep increasing, as the number of blobs is increased.   
						potentialTimeBasedSQLInjection=false;
						numberOfSequentialIncreases=0;
						detectableDelayParameter = null; 
						detectableDelay=0;
						detectableDelayMessage=null;
						maxDelayParameter = null; 
						maxDelay=0;
						//do not break at this point, since we may simply need to keep increasing numBlobsToCreate to
						//a point where we can detect the resulting delay
					}
					if ( this.debugEnabled ) log.debug ("Time Based SQL Injection test for "+ numBlobsToCreate + " random blob bytes: ["+ newTimeBasedInjectionValue + "] on field: ["+paramName+"] with value ["+newTimeBasedInjectionValue+"] took "+ modifiedTimeUsed + "ms, where the original took "+ originalTimeUsed + "ms");					
					previousDelay = modifiedTimeUsed;
				}  //end of for loop to increase the number of random blob bytes to create
				
				//the number of times that we could sequentially increase the delay by increasing the "number of random blob bytes to create"
				//is the basis for the threshold of the alert.  In some cases, the user may want to see a solid increase in delay 
				//for say 4 or 5 iterations, in order to be confident the vulnerability exists.  In other cases, the user may be happy with just 2 sequential increases...
				if ( this.debugEnabled ) log.debug ("Number of sequential increases: "+numberOfSequentialIncreases); 
				if (numberOfSequentialIncreases >= this.incrementalDelayIncreasesForAlert) {  
					//Likely a SQL Injection. Raise it
					String extraInfo = Constant.messages.getString("ascanalpha.sqlinjection.sqlite.alert.timebased.extrainfo", 
							detectableDelayParameter, detectableDelay,
							maxDelayParameter, maxDelay,
							originalParamValue, originalTimeUsed);
					
					//raise the alert
					bingo(Alert.RISK_HIGH, Alert.WARNING, getName(), getDescription(), 
							getBaseMsg().getRequestHeader().getURI().getURI(), //url
							paramName,  detectableDelayParameter, 
							extraInfo, getSolution(), detectableDelayMessage);

					if ( this.debugEnabled ) log.debug ("A likely Time Based SQL Injection Vulnerability has been found with ["+detectableDelayMessage.getRequestHeader().getMethod()+"] URL ["+detectableDelayMessage.getRequestHeader().getURI().getURI()+"] on field: ["+paramName+"]");

					return;
				} //the user-define threshold has been exceeded. raise it.
				
				
			//bale out if we were asked nicely
			if (isStop()) { 
				if ( this.debugEnabled ) log.debug("Stopping the scan due to a user request");
				return;
				}
			}  //for each time based SQL index
			//end of check for SQLite time based SQL Injection

		} catch (Exception e) {
			//Do not try to internationalise this.. we need an error message in any event.. 
			//if it's in English, it's still better than not having it at all. 
			log.error("An error occurred checking a url for SQLite SQL Injection vulnerabilities", e);
		}
	}
	
	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

	@Override
	public int getCweId() {
		return 89;
	}

	@Override
	public int getWascId() {
		return 19;
	}
}
