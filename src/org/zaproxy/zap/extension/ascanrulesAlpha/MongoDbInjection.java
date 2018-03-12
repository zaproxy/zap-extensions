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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
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
 * @author l.casciaro
 */
public class MongoDbInjection extends AbstractAppParamPlugin {

	// Prefix for internationalised messages used by this rule
	private static final String MESSAGE_PREFIX = "ascanalpha.mongodb.";
	private static final String ALL_DATA_ATTACK = "alldata";
	private static final String JS_ATTACK = "js";
	private static final String CRASH_ATTACK = "crash";
	private static final String TIMED_ATTACK ="timed";
	private static final String JSON_ATTACK = "json";
	private static final String AUTH_BYPASS_ATTACK = "authbypass";
	private static final String TOKEN ="OWASP_ZAP_TOKEN_INJECTION";
	private static final int SLEEP_TIME_SHORT=500;
	private static final int SLEEP_TIME_LONG=2000;
	private static final int DELTA_TIME=200;
	private final List<Pattern> errorPatterns = initPattern(BINGO_MATCHING);	
	private static final String[] ALL_DATA_PARAM_INJECTION = new String[] {"[$ne]", "[$regex]", "[$gt]"};
	// Alternatively could be fine only the paramter injection
	private static final String[] ALL_DATA_VALUE_INJECTION = new String[]  {"", ".*", "0"}; 
	private static String[] CRASH_INJECTION = new String[] {"\"", "'", "//", "});",");"};
	private static final String[] JS_INJECTION = {
		"'; return (true); var notReaded='",
		"'); print("+TOKEN+"); print('",
		"_id);}, function(kv) { return 1; }, { out: 'x'}); print('Injection'); "+ 
		"return 1; db.noSQL_injection.mapReduce(function() { emit(1,1",
		"true, $where: '1 == 1'"};
	
	private static final String[][] TIMED_INJECTION = {{"\"'); sleep("+SLEEP_TIME_SHORT+"); print('\"",
		"\"'); sleep("+SLEEP_TIME_LONG+"); print('\""}, {"'; sleep("+SLEEP_TIME_SHORT+"); var x='",
			"'; sleep("+SLEEP_TIME_LONG+"); var x='"}};
	
	private static final String[][] JSON_INJECTION = {{"$ne", "0"}, {"$gt", ""}, {"$regex", ".*"}};
	private static final String[] BINGO_MATCHING =  {"mongoDB", "MongoDB", "exception: SyntaxError: Unexpected", 
			"exception 'MongoResultException'", TOKEN, "Unexpected string at $group reduce setup"};
	
	private static final String JSON_EX_LOG = "try to convert the payload in json format";
	private static final String IO_EX_LOG = "try to send an http message";
	private static final String URI_EX_LOG = "try to get the message's Uri";
	
	private static final Logger LOG = Logger.getLogger(MongoDbInjection.class);
	
	private boolean isJsonPayload;
		   
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
	public void scan(HttpMessage msg, NameValuePair originalParam) {
		if(!inScope(getTech())){
			return;
		}
		//TODO add TYPE_JSON control as soon as available
		isJsonPayload = originalParam.getType() == NameValuePair.TYPE_POST_DATA; //& originalParam.getType() == NameValuePair.TYPE_JSON;
		super.scan(msg, originalParam);
	}
	
	@Override
	public void scan(HttpMessage msg, String param, String value) {
		urlScan(msg, param, value, ALL_DATA_PARAM_INJECTION, ALL_DATA_VALUE_INJECTION, ALL_DATA_ATTACK, false);
		urlScan(getNewMsg(), param, value, null, CRASH_INJECTION, CRASH_ATTACK, true);
		urlScan(getNewMsg(), param, value, null, JS_INJECTION, JS_ATTACK, false);
		timedScan(getNewMsg(), param, value, TIMED_INJECTION, TIMED_ATTACK);
		jsonScan(getNewMsg(), param, value, JSON_INJECTION, ALL_DATA_ATTACK);
	}

	private void urlScan(HttpMessage msg, String param, String value, String[] paramInjection, String[] valueInj, 
			String typeAttack, boolean onlyExactError) {
		int index = 0;
		for(String vi : valueInj) {
			try {
				if(paramInjection!=null) {
					param += paramInjection[index++];
				}
				msg = sendNewMsg(param, vi);
				if(isBingo(getBaseMsg(), msg, param, vi, typeAttack, onlyExactError)) {
					// The onlyExactError flag is true when you insert strings to break the database, the result of this
					// penetration test difficulty will be an authentication bypassing, so it was excluded from the 
					// checkAuthBypass(...) test.
					if(!onlyExactError) {
						checkAuthBypass(getBaseMsg(), msg, param, vi);
					}
					break;
				}
			}catch(IOException ex) {
				printLogException(ex, IO_EX_LOG);
				continue;
			}
		}
	}
	
	private void timedScan(HttpMessage msg, String param, String value, String[][] timedInjection, String timedAttack) {
		long intervalBaseMessage, intervalInjectedMessage; 
		Instant start;
		start = Instant.now();
		try {
			// Here the sendAndrReceive() function could be called directly but in this way the next comparison between 
			// times is more accurate.
			sendNewMsg(param, value);
		} catch (IOException ex) {
			printLogException(ex, IO_EX_LOG);
			return;
		}
		intervalBaseMessage = ChronoUnit.MILLIS.between(start, Instant.now());
			for(String[] tvi:timedInjection) {
				if(isStop()) {
					return;
				}		
				try {
					start = Instant.now();
					sendNewMsg(param, tvi[0]);
					intervalInjectedMessage = ChronoUnit.MILLIS.between(start, Instant.now());
					
					if(isTimedInjected(intervalBaseMessage,intervalInjectedMessage, SLEEP_TIME_SHORT)) {
						// try for a longer time to exclude transmission delays
						start = Instant.now();
						msg = sendNewMsg(param, tvi[1]);
						intervalInjectedMessage = ChronoUnit.MILLIS.between(start, Instant.now());
						
						if(isTimedInjected(intervalBaseMessage,intervalInjectedMessage, SLEEP_TIME_LONG)) {
							bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null, 
									param, tvi[1], getExtraInfo(timedAttack), getSolution(), msg);
							break;
						}
					}
				} catch (IOException ex) {
					printLogException(ex, IO_EX_LOG);
					continue;
			}
		}
	}
	
	private void jsonScan(HttpMessage msg, String param, String value, String[][] allDataInjection,
			String allDataAttack) {	
		if(!isJsonPayload) {
			return;
		}
		for(String[] jpv : allDataInjection) {
			try {
				if(isStop()) {
					return;
				}
				value = getParamJsonString(param, jpv);
				msg.getRequestHeader().setHeader(HttpRequestHeader.CONTENT_TYPE, "application/json");
				msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
				setParameter(msg, param, value);
				sendAndReceive(msg, false);
				isBingo(getBaseMsg(), msg, JSON_ATTACK, param, value, false);
			} catch (JSONException ex) {
				printLogException(ex, JSON_EX_LOG);
				continue;
			} catch (IOException ex) {
				printLogException(ex, IO_EX_LOG);
				continue;
			}
		}
	}

	private boolean isBingo(HttpMessage originalMsg, HttpMessage injectedMsg, String param, String valueInj, 
			String attack, boolean onlyExactMatch) {
		
		String originalText = originalMsg.getResponseBody().toString();
		String injectedText = injectedMsg.getResponseBody().toString();
		if(originalText.equals(injectedText)) {
			return false;
		}
		else {
			/*
			 * The difference between the base response body and the after injecting one is for the only value passed 
			 * as input. So it could be a (uncommon) false positive result. For example the server could be response: 
			 * " @valueInj (or @TOKEN) doesn't exist, make sure you ... ". 
			 */
			if(differOnlyForInput(originalText, injectedText, valueInj, TOKEN)) {
				bingo(Alert.RISK_LOW, Alert.CONFIDENCE_LOW, getName(), getDescription(), null, param, valueInj, 
						getExtraInfo(attack), getSolution(), injectedMsg);
				// continue to scan
				return false;
			}
			StringBuilder sb = new StringBuilder();
			/*
			 * If the response message contains one of the note patterns then it is probable that the application has 
			 * a well-noted vulnerability. 
			 */
			for(Pattern p : errorPatterns) {
				if(matchBodyPattern(injectedMsg, p, sb)) {
					bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param, valueInj, 
							getExtraInfo(attack), getSolution(), injectedMsg);
					return true;
				}
			}
			// Unknown vulnerability.  
			if(!onlyExactMatch) {
				bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param, valueInj, 
					  getExtraInfo(attack), getSolution(), injectedMsg);
				return true;
			}
			else {
				return false;
			}
		}
	}
	
	/**
	 * Checks if the originalMsg and injectedMsg strings differ only for the value passed as input.
	 * 
	 * @param originalMsg the first argument of the comparison
	 * @param injectedMsg the second argument of the comparison
	 * @param valueBase the value to search in originalMsg
	 * @param valueInj the value to search in injectedMsg
	 * @return <code>true</code> if the originalMsg body isn't the same to the injectedMsg one, 
	 * <code>false</code> otherwise.
	 */
	private static boolean differOnlyForInput(String originalMsg, String injectedMsg, String valueBase,
			String valueInj) {
		//this eventuality should not occur
		if(originalMsg == null || injectedMsg ==null) {
			return false;
		}
		String extractString1, extractString2;
		int index = originalMsg.lastIndexOf(injectedMsg);
		if(index> -1) {
			extractString1 = injectedMsg.substring(index, index+valueInj.length());
			extractString2 = injectedMsg.substring(index, index+ valueBase.length());
			if(extractString1.equals(valueInj) && extractString2.equals(valueBase)) {
				return true;
			}
		}
		return false;
	}
	
	public void checkAuthBypass(HttpMessage msg, HttpMessage injectedMsg, String param, String valueInj) {
		ExtensionAuthentication extAuth = (ExtensionAuthentication) Control.getSingleton()
				.getExtensionLoader().getExtension(ExtensionAuthentication.NAME);
		if (extAuth != null) {
			URI requestUri = getBaseMsg().getRequestHeader().getURI();
			try {
				List<Context> contextList = extAuth.getModel().getSession().getContextsForUrl(requestUri.getURI());		
				for (Context context : contextList) {
					URI loginUri = extAuth.getLoginRequestURIForContext(context);
					if (loginUri != null) {
						if (requestUri.getScheme().equals(loginUri.getScheme())
								&& requestUri.getHost().equals(loginUri.getHost())
								&& requestUri.getPort() == loginUri.getPort()
								&& requestUri.getPath().equals(loginUri.getPath())) {
	
							bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, AUTH_BYPASS_ATTACK, getName(), 
									getDescription(), null, param, getExtraInfo(AUTH_BYPASS_ATTACK), getSolution(), 
									injectedMsg);
							break;
						}
					}
				}
			} catch(URIException ex) {
				printLogException(ex, URI_EX_LOG);
			}
		}
	}
	
	private boolean isTimedInjected(long intervalBaseMessage, long intervalInjectedMessage, int sleep) {
		long diff=intervalInjectedMessage-intervalBaseMessage;
		if(diff>=sleep-DELTA_TIME) {
			return true;
		}
		return false;
	}
	
	private static List<Pattern> initPattern(String[] eb) {
		List<Pattern> list =  new ArrayList<>();
		for(String regex: eb) {
			list.add(Pattern.compile(regex, AbstractAppParamPlugin.PATTERN_PARAM));
		}
		return list;
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
			LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
					" when "+info);
		}
	}
}