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
	private boolean isJsonPayload;
	private HttpMessage injectedMsg;
	private final List<Pattern> errorPatterns = initPattern(BINGO_MATCHING);
	//TODO add the string do try the login auth.
	private static final String[] ALL_DATA_PARAM_INJECTION = new String[] {"[$ne]", "[$regex]", "[$gt]"};
	// Alternatively could be fine only the paramter injection
	private static final String[] ALL_DATA_VALUE_INJECTION = new String[]  {"0", ".*", "0"}; 
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
	
	private static final String JSON_EX_LOG = "try to convert the payload in the json format";
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
	public void scan(HttpMessage msg, NameValuePair originalParam) {
		isJsonPayload = originalParam.getType() == NameValuePair.TYPE_POST_DATA;
			//TODO add TYPE_JSON control as soon as available
			//& originalParam.getType() == NameValuePair.TYPE_JSON;
		//for()
		if(inScope(getTech())){
			super.scan(msg, originalParam);
		}
	}
	
	@Override
	public void scan(HttpMessage msg, String param, String value) {
		if(urlScan(msg, param, value, ALL_DATA_PARAM_INJECTION, ALL_DATA_VALUE_INJECTION, ALL_DATA_ATTACK, false)) {
			checkAuthBypass(msg, param, value);
		}
		urlScan(msg, param, value, null, CRASH_INJECTION, CRASH_ATTACK, true);
		urlScan(msg, param, value, null, JS_INJECTION, JS_ATTACK, false);
		timedScan(msg, param, value, TIMED_INJECTION, TIMED_ATTACK);
		if(isJsonPayload) {
			jsonScan(msg, param, value, JSON_INJECTION, ALL_DATA_ATTACK);
		}
	}

	private boolean urlScan(HttpMessage msg, String param, String value, String[] paramInjection, String[] valueInjection, 
			String typeAttack, boolean onlyExactError) {
		int index = 0;
		for(String vi : valueInjection) {
			try {
				if(paramInjection!=null) {
					param += paramInjection[index++];
				}
				injectedMsg = sendNewMsg(param, vi);
				if(isBingo(getBaseMsg(), injectedMsg, param, vi, typeAttack, onlyExactError)) {
					return true;
				}
			}catch(IOException ex) {
				printLogException(ex, IO_EX_LOG);
				continue;
			}
		}
		return false;
	}

	private void timedScan(HttpMessage msg, String param, String value, String[][] timedInjection, String timedAttack) {
		long intervalBaseMessage, intervalInjectedMessage; 
		Instant start;		
		start = Instant.now();
		setParameter(msg, param, TOKEN);
		try {
			sendAndReceive(msg);
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
						sendNewMsg(param, tvi[1]);
						intervalInjectedMessage = ChronoUnit.MILLIS.between(start, Instant.now());
						
						if(isTimedInjected(intervalBaseMessage,intervalInjectedMessage, SLEEP_TIME_LONG)) {
							bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null, 
									param, tvi[1], getExtraInfo(timedAttack), getSolution(), injectedMsg);
							break;
						}
					}
				} catch (IOException ex) {
					printLogException(ex, IO_EX_LOG);
					continue;
			}
		}
	}
	
	private boolean jsonScan(HttpMessage msg, String param, String value, String[][] allDataInjection,
			String allDataAttack) {	
		for(String[] jpv : allDataInjection) {
			try {
				if(isStop()) {
					return false;
				}
				value = getParamJsonString(param, jpv);
				injectedMsg  = getNewMsg();
				injectedMsg.getRequestHeader().setHeader(HttpRequestHeader.CONTENT_TYPE, 
						"application/json");
				injectedMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
				setParameter(injectedMsg, param, value);
				sendAndReceive(injectedMsg, false);
				if(isBingo(getBaseMsg(), injectedMsg, JSON_ATTACK, param, value, false)) {
					return true;
				}
			} catch (JSONException ex) {
				printLogException(ex, JSON_EX_LOG);
				continue;
			} catch (IOException ex) {
				printLogException(ex, IO_EX_LOG);
				continue;
			}
		}
		return false;
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
	
	private boolean isTimedInjected(long intervalBaseMessage, long intervalInjectedMessage, int sleep) {
		long diff=intervalInjectedMessage-intervalBaseMessage;
		if(diff>=sleep-DELTA_TIME) {
			return true;
		}
		return false;
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
	
	public void checkAuthBypass(HttpMessage msg, String param, String valueInj) {
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
	
							//raise the alert, using the attack string stored earlier for this purpose					
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
}