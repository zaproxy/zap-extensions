/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2018 The ZAP Development Team
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

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;

/**
 * The MongoInjection plugin identifies MongoDB injection vulnerabilities
 *
 * @author l.casciaro
 */
public class MongoDbInjection extends AbstractAppParamPlugin {

	// Prefix for internationalised messages used by this rule
	private static final String MESSAGE_PREFIX = "ascanalpha.mongodb.";

	// Constants
	private static final String ALL_DATA_ATTACK = "alldata";
	private static final String JS_ATTACK = "js";
	private static final String CRASH_ATTACK = "crash";
	private static final String SLEEP_ATTACK ="sleep";
	private static final String JSON_ATTACK = "json";
	private static final String AUTH_BYPASS_ATTACK = "authbypass";
	private static final String MONGO_TOKEN ="OWASP_ZAP_TOKEN_INJECTION";

	// Variables
	private boolean isJsonPayload;
	private boolean doUnknownAlert, doAllDataScan, doCrashScan, doJsScan, doTimedScan, doJsonScan, doCounterProof,
					doAuthBypass;
	private static int SLEEP_TIME_SHORT;
	private static int SLEEP_TIME_LONG;
	private static final int DELTA_TIME=100;

	// Packages of attack rules
	private static final String[] ALL_DATA_PARAM_INJECTION = new String[] {"[$ne]", "[$regex]", "[$gt]"};
	private static final String[] ALL_DATA_VALUE_INJECTION = new String[]  {"", ".*", "0"};
	private static String[] CRASH_INJECTION = new String[] {"\"", "'", "//", "});",");"};
	private static final String[] JS_INJECTION = {"'; return (true); var notReaded='",
			"'); print("+MONGO_TOKEN+"); print('",
			"_id);}, function(kv) { return 1; }, { out: 'x'}); print('Injection'); "+
			"return 1; db.noSQL_injection.mapReduce(function() { emit(1,1", "true, $where: '1 == 1'"};
	private static final String[][] SLEEP_INJECTION = {{"\"'); sleep("+SLEEP_TIME_SHORT+"); print('\"",
		"\"'); sleep("+SLEEP_TIME_LONG+"); print('\""}, {"'; sleep("+SLEEP_TIME_SHORT+"); var x='",
			"'; sleep("+SLEEP_TIME_LONG+"); var x='"}};
	private static final String[][] JSON_INJECTION = {{"$ne", "0"}, {"$gt", ""}, {"$regex", ".*"}};

	// Error messages that addressing to a well-known vulnerability
	private  final Pattern[] errorPatterns = {
			Pattern.compile("mongo", Pattern.CASE_INSENSITIVE),
			Pattern.compile("exception: SyntaxError: Unexpected", Pattern.CASE_INSENSITIVE),
			Pattern.compile("exception 'MongoResultException'", Pattern.CASE_INSENSITIVE),
			Pattern.compile(MONGO_TOKEN, Pattern.CASE_INSENSITIVE),
			Pattern.compile("Unexpected string at $group reduce setup", Pattern.CASE_INSENSITIVE)};
	// Log prints
	private static final String JSON_EX_LOG = "try to convert the payload in json format";
	private static final String IO_EX_LOG = "try to send an http message";
	private static final String URI_EX_LOG = "try to get the message's Uri";
	private static final Logger LOG = Logger.getLogger(MongoDbInjection.class);

	@Override
	public int getCweId() {
		return 943;
	}

	@Override
	public int getWascId() {
		return 19;
	}

	public int getId() {
		return 40033;
	}

	public Tech getTech() {
		//TODO change in Tech.MongoDB as soon as available
		return Tech.Db;
	}

	@Override
	public boolean targets(TechSet technologies) {
		//TODO change in Tech.MongoDB as soon as available
		return technologies.includes(Tech.Db);
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	@Override
	public int getCategory() {
		return Category.INJECTION;
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	@Override
	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	@Override
	public String[] getDependency() {
		return new String[] {};
	}

	public String getExtraInfo(String attack) {
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo." + attack);
	}

	@Override
	public void init() {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Initialising MongoDB penertration tests");
		}
		if (this.getAttackStrength() == AttackStrength.LOW) {
			SLEEP_TIME_SHORT = 300;
			SLEEP_TIME_LONG = 600;
			doUnknownAlert = false;
			doCrashScan = false;
			doJsScan = true;
			doAllDataScan = true;
			doTimedScan = true;
			doJsonScan = true;
			doCounterProof = false;
			doAuthBypass = true;
		}
		else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
			SLEEP_TIME_SHORT = 400;
			SLEEP_TIME_LONG = 800;
			doUnknownAlert = false;
			doCrashScan = true;
			doJsScan =true;
			doAllDataScan = true;
			doTimedScan = true;
			doJsonScan = true;
			doCounterProof = true;
			doAuthBypass = true;
		}
		else if (this.getAttackStrength() == AttackStrength.INSANE) {
			SLEEP_TIME_SHORT = 500;
			SLEEP_TIME_LONG = 1500;
			doUnknownAlert = true;
			doCrashScan = true;
			doJsScan = true;
			doAllDataScan = true;
			doTimedScan = true;
			doJsonScan = true;
			doCounterProof = true;
			doAuthBypass = true;
		}
	}

	@Override
	public void scan(HttpMessage msg, NameValuePair originalParam) {
		//TODO add TYPE_JSON control as soon as available
		isJsonPayload = originalParam.getType() == NameValuePair.TYPE_POST_DATA; //& originalParam.getType() == NameValuePair.TYPE_JSON;
		super.scan(msg, originalParam);
	}

	@Override
	public void scan(HttpMessage msg, String param, String value) {
		if(!inScope(getTech())){
			return;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("\nScannning URL ["+msg.getRequestHeader().getMethod()+"] ["+msg.getRequestHeader().getURI()+
					"] on param: ["+param+"] with value: ["+value+"] for MongoDB Injection");
		}
		if(doAllDataScan) {
			urlScan(msg, param, value, ALL_DATA_PARAM_INJECTION, ALL_DATA_VALUE_INJECTION, ALL_DATA_ATTACK);
		}
		if(isStop()) { return; } // any log has already printed
		if(doCrashScan) { urlScan(getNewMsg(), param, value, null, CRASH_INJECTION, CRASH_ATTACK); }
		if(isStop()) { return; }
		if(doJsScan) { urlScan(getNewMsg(), param, value, null, JS_INJECTION, JS_ATTACK); }
		if(isStop()) { return; }
		if(doTimedScan) { sleepScan(getNewMsg(), param, value, SLEEP_INJECTION, SLEEP_ATTACK); }
		if(isStop()) { return; }
		doJsonScan &= isJsonPayload;
		if(doJsonScan) { jsonScan(getNewMsg(), param, value, JSON_INJECTION, JSON_ATTACK); }
	}

	private void urlScan(HttpMessage msg, String param, String value, String[] vectParams, String[] vectValues,
			String typeAttack) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("\nStarting with the \""+typeAttack+"\" package of attack rules:");
		}
		int index = 0;
		for(String vi : vectValues) {
			if(isStop()) {
				if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
				return;
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug("\nTrying with the value: "+vi);
			}
			try {
				if(vectParams!=null) {
					param += vectParams[index++];
				}
				msg = sendNewMsg(param, vi);
				if(isBingo(getBaseMsg(), msg, param, vi, typeAttack)) {
					if(doAuthBypass) {
						String attack = vectParams!=null ? vectParams[index-1] + vi : vi;
						checkAuthBypass(getBaseMsg(), msg, param, attack);
					}
					break;
				}
			}catch(IOException ex) {
				printLogException(ex, IO_EX_LOG);
				return;
			}
		}
	}

	private void sleepScan(HttpMessage msg, String param, String value, String[][] vectSleep, String typeAttack) {
		if(isStop()) {
			if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
			return;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("\nStarting with the \""+typeAttack+"\" package of attack rules:");
		}
		long intervalBaseMessage, intervalInjectedMessage;
		Instant start;
		start = Instant.now();
		try {
			sendNewMsg(param, value);
		} catch (IOException ex) {
			printLogException(ex, IO_EX_LOG);
			return;
		}
		intervalBaseMessage = ChronoUnit.MILLIS.between(start, Instant.now());
		int index = 0;
		while(index<vectSleep.length) {
			if(isStop()) {
				if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
				return;
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug("\nTrying  with the value: "+vectSleep[index][0]);
			}
			try {
				start = Instant.now();
				sendNewMsg(param, vectSleep[index][0]);
				intervalInjectedMessage = ChronoUnit.MILLIS.between(start, Instant.now());
				if(isTimedInjected(intervalBaseMessage,intervalInjectedMessage, SLEEP_TIME_SHORT)) {
					// try for a longer time to exclude transmission delays
					if(isStop()) {
						if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
						return;
					}
					if (LOG.isDebugEnabled()) {
						LOG.debug("\nTrying for a longer time with the value: "+vectSleep[index][1]);
					}
					start = Instant.now();
					msg = sendNewMsg(param, vectSleep[index][1]);
					intervalInjectedMessage = ChronoUnit.MILLIS.between(start, Instant.now());

					if(isTimedInjected(intervalBaseMessage,intervalInjectedMessage, SLEEP_TIME_LONG)) {
						bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null,
								param, vectSleep[index][1], getExtraInfo(typeAttack), getSolution(), msg);
						break;
					}
				}
				//only in case of no SocketTimeoutException exception, otherwise retry with the lowest interval
				index++;
			} catch (SocketTimeoutException ex) {
				printLogException(ex, IO_EX_LOG+"due to a socket timeout, trying with the lowest interval (600 ms)");
				SLEEP_TIME_SHORT = 300;
				SLEEP_TIME_LONG = 600;
			} catch (IOException ex) {
				printLogException(ex, IO_EX_LOG);
				return;
			}
		}
	}

	private void jsonScan(HttpMessage msg, String param, String value, String[][] vectParamValue, String typeAttack) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("\nStarting with the \""+typeAttack+"\" package of attack rules:");
		}
		for(String[] jpv : vectParamValue) {
			try {
				if(isStop()) {
					if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
					return;
				}
				if (LOG.isDebugEnabled()) {
					LOG.debug("\nTrying with the value: "+jpv);
				}
				value = getParamJsonString(param, jpv);
				msg.getRequestHeader().setHeader(HttpRequestHeader.CONTENT_TYPE, "application/json");
				msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
				setParameter(msg, param, value);
				sendAndReceive(msg, false);
				if(isBingo(getBaseMsg(), msg, typeAttack, param, value)) {
					if(doAuthBypass) {
						checkAuthBypass(getBaseMsg(), msg, param, jpv[0]+jpv[1]);
					}
					break;
				}
			} catch (JSONException ex) {
				printLogException(ex, JSON_EX_LOG);
				return;
			} catch (IOException ex) {
				printLogException(ex, IO_EX_LOG);
				return;
			}
		}
	}

	private boolean isBingo(HttpMessage baseMsg, HttpMessage injMsg, String param, String injValue, String typeAttack) {
		String baseBody = baseMsg.getResponseBody().toString();
		String injBody = injMsg.getResponseBody().toString();
		if(baseBody.equals(injBody)) {
			return false;
		}
		else {
			// check if the application has a well-noted MongoDB vulnerability.
			for(Pattern pattern : errorPatterns) {
				Matcher matcher =  pattern.matcher(injMsg.getResponseBody().toString());
				if(matcher.find()) {
					bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param, injValue,
							getExtraInfo(typeAttack), getSolution(), injMsg);
					return true;
				}
			}
			// Obtained potentially sensitive data
			if(isDataReturnAttack(typeAttack)) {
				// If user has stopped, the event is handled in the calling method
				if(isStop()) { return false; }
				// Get more confidence
				if(doCounterProof) {
					try {
						HttpMessage counterP = sendNewMsg(param, MONGO_TOKEN);
						if(!areDifferentForValue(counterP.getRequestBody().toString(), injBody, MONGO_TOKEN, injValue)) {
							bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null, param,
									injValue, getExtraInfo(typeAttack), getSolution(), injMsg);
							return true;
						}
						else {
							if(doUnknownAlert) {
								bingo(Alert.RISK_LOW, Alert.CONFIDENCE_LOW, getName(), getDescription(), null, param,
										injValue, "Unknown vulnerability, it may be a false positive.", getSolution(),
										injMsg);
							}
							// continue with the next rule of the same packet
							return false; 
						}
					} catch(IOException ex) {
						printLogException(ex, IO_EX_LOG + "in the counterProof test");
					}
				}
				bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param,
						injValue, getExtraInfo(typeAttack), getSolution(), injMsg);
				return true;
			}
			return false;
		}
	}

	public void checkAuthBypass(HttpMessage msg, HttpMessage injectedMsg, String param, String valueInj) {
		if(isStop()) {
			if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
			return;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("\nPenetration gone well, check if it's an authentication page");
		}
		ExtensionAuthentication extAuth = (ExtensionAuthentication) Control.getSingleton()
				.getExtensionLoader().getExtension(ExtensionAuthentication.NAME);
		if (extAuth != null) {
			URI requestUri = msg.getRequestHeader().getURI();
			try {
				List<Context> contextList = extAuth.getModel().getSession().getContextsForUrl(requestUri.getURI());
				for (Context context : contextList) {
					URI loginUri = extAuth.getLoginRequestURIForContext(context);
					if (loginUri != null) {
						if (requestUri.getScheme().equals(loginUri.getScheme())
								&& requestUri.getHost().equals(loginUri.getHost())
								&& requestUri.getPort() == loginUri.getPort()
								&& requestUri.getPath().equals(loginUri.getPath())) {

							bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param,
									valueInj, getExtraInfo(AUTH_BYPASS_ATTACK), getSolution(), injectedMsg);
							break;
						}
					}
				}
			} catch(URIException ex) {
				printLogException(ex, URI_EX_LOG);
			}
		}
	}

	private boolean isDataReturnAttack(String typeAttack) {
		return typeAttack == ALL_DATA_ATTACK || typeAttack == JS_ATTACK || typeAttack == JSON_ATTACK;
	}

	static boolean areDifferentForValue(String msg1, String msg2, String value1,String value2) {
		int index = msg2.indexOf(value2);
			return  index>-1 && msg1.length()-value1.length() == msg2.length()-value2.length() &&
					msg1.substring(index, index+value1.length()).equals(value1) && 
					msg2.substring(index+value2.length(), msg2.length()).equals(
					msg1.substring(index+value1.length(), msg1.length()));
	}

	private boolean isTimedInjected(long intervalBaseMessage, long intervalInjectedMessage, int sleep) {
		long diff=intervalInjectedMessage-intervalBaseMessage;
		return diff>=sleep-DELTA_TIME;
	}

	private String getParamJsonString(String param, String[] params) throws JSONException {
		JSONObject internal = new JSONObject(),
				   external = new JSONObject();
    	internal.put(params[0] , params[1]);
    	external.put(param, internal);
		return external.toString();
	}

	private HttpMessage sendNewMsg(String param, String value) throws IOException {
		HttpMessage newMsg = getNewMsg();
		setParameter(newMsg, param, value);
		sendAndReceive(newMsg, false);
		return newMsg;
	}

	private void printLogException(Exception ex, String info) {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() +" when "+info);
		}
	}
}