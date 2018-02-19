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
import java.net.SocketException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

import net.sf.json.JSONException;
import net.sf.json.JSONObject;

/**
 * @author l.casciaro
 *
 */
public class TestNoSQLInjection extends AbstractAppParamPlugin {

	// Prefix for internationalised messages used by this rule
	private static final String MESSAGE_PREFIX = "ascanalpha.testnosqlinjection.";
	private static final String JSON_ATTACK = "json";
	private static final String PARVAL_ATTACK = "paramvalue";
	private static final String VALUE_ATTACK = "value";
	private static final String CRASH_ATTACK = "crash";
	private static final String TIMED_ATTACK ="timed";
	private static final String TOKEN ="OWASP_ZAP_TOKEN_INJECTION";
	private static final int SLEEP_TIME_SHORT=500;
	private static final int SLEEP_TIME_LONG=2000;
	private static final int DELTA_TIME=200;
	private boolean isJsonPayload;
	
	private static final int ID = 40033;
	private static final int CWED_ID = 943;
	private static final int WASC_ID = 19;
	
	//START MongoDB	
	private static final String MONGO_INDEX = "mongo";
	private String indexDbSel = MONGO_INDEX;	
	private static final String[] MONGO_URL_ERROR_INJECTION  = {"\"", "'", "//", "});",");"	};
	private static final String[] MONGO_ERROR_MATCHING_STRING =  {
			"retval", "Unexpected token", "mongoDB", "SyntaxError", "ReferenceError", "Illegal", TOKEN };
	
	private static final String[][] MONGO_URL_PARAM_VALUE_INJECTION = new String[][] { { "[$ne]", "0"}, 
		{"[$regex]", ".*"}, {"[$gt]", "0"}
	};
	private static final String[] MONGO_URL_VALUE_INJECTION = {
		"'; return (true); var notReaded='",
		"'); print("+TOKEN+"); print('",
		"_id);}, function(kv) { return 1; }, { out: 'x'}); print('Injection'); "	+ 
		"return 1; db.noSQL_injection.mapReduce(function() { emit(1,1",
		"true, $where: '1 == 1'",		
	};
	private static final String[][] MONGO_TIMED_VALUE_INJECTION = {
			{"\"'); sleep("+SLEEP_TIME_SHORT+"); print('\"", "\"'); sleep("+SLEEP_TIME_LONG+"); print('\""},
			{"'; sleep("+SLEEP_TIME_SHORT+"); var x='", "'; sleep("+SLEEP_TIME_LONG+"); var x='"}
	};
	private static final String[][] MONGO_JSON_PARAM_VALUE_INJECTION = { 
		{"$ne", "0"},
		{"$gt", ""},
		{"$regex", ".*"}
	};
	// END MongoDB

	// The set of all NoSQL DB-Drivers technology pairs to test
	private enum NOSQLDB{

		mongoDB(/* Tech.MongoDB */ Tech.Db, MONGO_URL_VALUE_INJECTION, MONGO_URL_ERROR_INJECTION, 
				MONGO_URL_PARAM_VALUE_INJECTION, MONGO_JSON_PARAM_VALUE_INJECTION, MONGO_TIMED_VALUE_INJECTION, 
				MONGO_ERROR_MATCHING_STRING, MONGO_INDEX);
		
		private final String name;
		private final Tech dbTech;
		private final String[][] urlEncParamValueInjection;
		private final String[] urlEncValueInjection;
		private final String[] urlEncErrorInjection;
		private final String[][] jsonParamValueInjection;
		private final String[][] urlEncTimedValueInjection;
		private final List<Pattern> errorPatterns;
		private final String indexDb;

		/**
		 * @param t the Technology
		 * @param uv url-encoded payload values 
		 * @param ue breaking-db payload values
		 * @param upv arrays of url-encoded parameter-value pair
		 * @param jpv arrays of json payload values
		 * @param tvi arrays of url-encoded payload values 
		 * @param ep arrays of error-checkinig strings
		 * @param p prefix of the @dbTech name
		 */
		private NOSQLDB(Tech t, String[] uv, String[] ej, String[][] upv, String[][] jpv, String[][] tvi, String[] ep, 
				String is) {
			
			name=t.getName();
			dbTech=t;
			urlEncValueInjection=uv;
			urlEncErrorInjection =ej;
			urlEncParamValueInjection=upv;
			jsonParamValueInjection=jpv;
			urlEncTimedValueInjection=tvi;
			errorPatterns =  new ArrayList<>();
			for(String regex:ep) {
				errorPatterns.add(Pattern.compile(regex, AbstractAppParamPlugin.PATTERN_PARAM));
			}
			indexDb=is;
		}

		public String getName() {
			return this.name;
		}
		
		public Tech getDbTech() {
			return this.dbTech;
		}
		
		public List<Pattern> getErrorPatterns() {
			return this.errorPatterns;
		}
		
		public String[] getUrlEncValueInjection() {
			return this.urlEncValueInjection;
		}
		
		public String[] getUrlEncErrorInjection() {
			return this.urlEncErrorInjection;
		}

		public String[][] getUrlEncParamValueInjection() {
			return this.urlEncParamValueInjection;
		}
		
		public String[][] getJsonParamValueInjection() {
			return jsonParamValueInjection;
		}

		public String[][] getUrlEncTimedValueInjection() {
			return urlEncTimedValueInjection;
		}
		
		public String getIndexDb() {
			return indexDb;
		}
	};

   private static final Logger LOG = Logger.getLogger(TestNoSQLInjection.class);

	@Override
	public int getId() {
		return ID;
	}

	 @Override
	 public boolean targets(TechSet technologies) {
		if (technologies.includes(Tech.Db)) {
			return true;
		}

		for (Tech tech : technologies.getIncludeTech()) {
			if (tech.getParent() == Tech.Db) {
				return true;
			}
		}
		return false;	
	 }

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name." + indexDbSel);
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc." + indexDbSel);
	}

	@Override
	public int getCategory() {
		return Category.INJECTION;
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln." + indexDbSel);
	}

	@Override
	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs." + indexDbSel);
	}
	
	@Override
	public String[] getDependency() {
		return new String[] {};
	}
   
	@Override
	public int getCweId() {
		return CWED_ID;
	}

	@Override
	public int getWascId() {
		return WASC_ID;
	}
	
	public String getExtraInfo(String attack) {
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo." + attack + "." + indexDbSel);
	}
	
	@Override
	public void scan(HttpMessage msg, NameValuePair originalParam) {

		isJsonPayload = originalParam.getType() != NameValuePair.TYPE_POST_DATA &
					originalParam.getType() != NameValuePair.TYPE_JSON;
		
		super.scan(msg, originalParam);
	}
	
	@Override
	public void scan(HttpMessage msg, String param, String value) {

		try {			
			for(NOSQLDB nosql: NOSQLDB.values()) {
				
				indexDbSel = nosql.getIndexDb();
				
				if(inScope(nosql.getDbTech())){
					startUrlEncodedScan(nosql, msg, param, value);
					if(isJsonPayload) {
						startJsonScan(nosql, msg, param, value);
					}
				}
			}
		} catch (SocketException ex) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
						" when accessing: " + msg.getRequestHeader().getURI().toString());
			}
		} catch (IOException ex) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
						" when accessing: " + msg.getRequestHeader().getURI().toString());
			}
		} catch(JSONException ex) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
						" when try to convert the payload in the json format");
			}
		}
	}

	private void startUrlEncodedScan(NOSQLDB nosql, HttpMessage msg, String param, String value) throws IOException {
		
		HttpMessage injectedMsg;
		long intervalBaseMessage, intervalInjectedMessage; 
		Instant start;
		setParameter(msg, param, TOKEN);
		start = Instant.now();
		sendAndReceive(msg);
		intervalBaseMessage = ChronoUnit.MILLIS.between(start, Instant.now());
		
		for(String[] pv : nosql.getUrlEncParamValueInjection()) {
			if(isStop()) {
				return;
			}
			if(isBingo(msg, getNewMsg(), false, PARVAL_ATTACK, param+pv[0], pv[1], nosql)) {
				break;
			}
		}

		for(String v : nosql.getUrlEncValueInjection()) {
			if(isStop()) {
				return;
			}
			if(isBingo(msg, getNewMsg(), false, VALUE_ATTACK, param, v, nosql)) {
				break;
			}
		}
		
		for (String ej:nosql.getUrlEncErrorInjection()) {
			if(isStop()) {
				return;
			}
			if(isBingo(msg, getNewMsg(), true, CRASH_ATTACK, param, ej, nosql)) {
				break;
			}
		}

		for(String[] tvi:nosql.getUrlEncTimedValueInjection()) {
			if(isStop()) {
				return;
			}
			String attackType = TIMED_ATTACK;
			injectedMsg = getNewMsg();
			setParameter(injectedMsg, param, tvi[0]);
			start = Instant.now();
			sendAndReceive(injectedMsg, false);
			intervalInjectedMessage = ChronoUnit.MILLIS.between(start, Instant.now());
			
			if(isTimedInjected(intervalBaseMessage,intervalInjectedMessage, SLEEP_TIME_SHORT)) {
				// try for a longer time to exclude transmission delays
				injectedMsg = getNewMsg();
				setParameter(injectedMsg, param, tvi[1]);
				start = Instant.now();
				sendAndReceive(injectedMsg, false);
				intervalInjectedMessage = ChronoUnit.MILLIS.between(start, Instant.now());
				
				if(isTimedInjected(intervalBaseMessage,intervalInjectedMessage, SLEEP_TIME_LONG)) {
					bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null, 
							param, tvi[1], getExtraInfo(attackType), getSolution(), injectedMsg);
					break;
				}
			}
		}
	}
	
	private void startJsonScan(NOSQLDB nosql, HttpMessage msg, String param, String value) throws IOException {
				
		for(String[] jpv : nosql.getJsonParamValueInjection()) {
			if(isStop()) {
				return;
			}
			String valueInjected = getParamJsonString(param, jpv);
			HttpMessage injectedMsg  = getNewMsg();
			injectedMsg.getRequestHeader().setHeader(HttpRequestHeader.CONTENT_TYPE, 
					"application/json");
			injectedMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
			if(isBingo(getNewMsg(), injectedMsg, false, JSON_ATTACK, param, valueInjected, nosql)) {
				break;
			}
		}
	}

	private boolean isBingo(HttpMessage baseMsg, HttpMessage injectedMsg, boolean onlyExactMatch, String attackType, 
			String param, String value, NOSQLDB nosql) throws IOException {
		setParameter(injectedMsg, param, value);
		sendAndReceive(injectedMsg, false);
		return isBingoInner(baseMsg, injectedMsg, param, value, attackType, nosql, onlyExactMatch);
	}
	
	private boolean isBingoInner(HttpMessage originalMsg, HttpMessage injectedMsg, String param, String valueInj, 
			String attack, NOSQLDB nosql, boolean onlyExactMatch) {
		
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
			 * 
			 */
			if(differingOnlyString(originalText, injectedText, valueInj, TOKEN)) {
				bingo(Alert.RISK_LOW, Alert.CONFIDENCE_LOW, getName(), getDescription(), null, param, valueInj, 
						getExtraInfo(attack), getSolution(), injectedMsg);
				return true;
			}

			StringBuilder sb = new StringBuilder();
			
			/*
			 * If the response message contains one of the note patterns then it is probable that the application has 
			 * a well-noted vulnerability. 
			 * 
			 */
			for(Pattern p:nosql.getErrorPatterns()) {
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
	 * Checks if the @originalMsg and @injectedMsg bodies differ only for the value passed as input.
	 * 
	 * @param originalMsg
	 * @param injectedMsg
	 * @param valueInj
	 * @return true if the @originalMsg body isn't the same of the {@injectedMsg} one, false otherwise.
	 * 
	 */
	private static boolean differingOnlyString(String originalMsg, String injectedMsg, String valueBase,
			String valueInj) {

		int lengthBase = originalMsg.length();
		int lengthInjected = injectedMsg.length();
		int lengthValueBase = valueBase.length();
		int lengthValueInj = valueInj.length();
		
		if(lengthBase-lengthInjected!=lengthValueBase-lengthValueInj) {
			return false;
		}
		char cursOriginal, cursInjected;
		String extractString;	
		
		for(int index=0; index<lengthInjected; index++) {
			cursOriginal = originalMsg.charAt(index);
			cursInjected = injectedMsg.charAt(index);
			if(cursInjected!=cursOriginal) {
				extractString = injectedMsg.substring(index, index+lengthValueInj);
				if(extractString.equals(valueInj))
					return true;
				else return false;
			}
		}
		return false;
	}

	private String getParamJsonString(String param, String[] params) throws JSONException {
		JSONObject internal = new JSONObject(),
				   external = new JSONObject();
    	internal.put(params[0] , params[1]);
    	external.put(param, internal);
		return external.toString();
	}
}