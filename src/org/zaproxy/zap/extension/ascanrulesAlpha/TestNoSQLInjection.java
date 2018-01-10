/*
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

import java.io.IOException;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
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
	
	
	/**
	 * Prefix for internationalised messages used by this rule
	 * 
	 */
	private static final String MESSAGE_PREFIX = "ascanalpha.testnosqlinjection.";
	private static final String EXTRAINFO_PREFIX = MESSAGE_PREFIX + "alert.extrainfo."; 
	private static final String MONGO_PREFIX = "mongo.";
	private static final String JSON_ATTACK = "json";
	private static final String PARVAL_ATTACK = "paramvalue";
	private static final String VALUE_ATTACK = "value";
	private static final String CRASH_ATTACK = "crash";
	private static final String FALSE_POSITIVE = "falsepositive";
	private static final String TOKEN ="OWASP_ZAP_TOKEN";
	
	private static final int ID = 40033;
	
	private static final int CWED_ID = 943;
	private static final int WASC_ID = 100000; //??
	
	private String[] dependency = {};
	public boolean logEnable; 

	
	private static final String[] MONGO_MATCHING_STRING = 
			new String[] { 
					"retval", "Unexpected token", "Exception",
					"Error", "mongoDB", "syntax" 		
			};

	
	private static final String[][] MONGO_URL_PARAM_VALUE_INJECTION = new String[][] {
		{ "[$ne]", "0"}, {"[$regex]", ".*"}, {"[$gt]", "0"}};
		
	private static final String[] MONGO_URL_ERROR_INJECTION = 	{
		"/",
		"\"",
		"'",
		")",
		"//",
	};
	
	private static final String[] MONGO_URL_VALUE_INJECTION = {
		
		"Injection\", \"$or\": [ {}, {\"a\":\"a",

		"'; return (true); var notReaded='",
		"_id); print(",
		
		"_id);}, function(kv) { return 1; },"	+
		"{ out: 'x'}); print('Injection'); "	+ 
		"return 1; db.noSQL_injection.mapReduce(function()" + 
		"{ emit(1,1",
		"true, $where: '1 == 1'",		
	};

	
	private static final String[][] MONGO_JSON_PARAM_VALUE_INJECTION = { 
			
		{"$ne", "0"},
		{"$gt", ""},
		{"$regex", ".*"}
	};

	
	private static final String[][] EMPTY_PARAM_VALUE = new String[0][0];
	private static final String[] EMPTY_VALUE = new String[0];	
	
	
	/**
	 * The set of all NoSQL DB-Drivers technology pairs to test
	 * @author l.casciaro
	 *
	 */
	private enum NOSQLDB{
		
		/**
		 * TODO: Insert any other variants of NoSQL DB-Drivers technology pairs
		 * 
		 */
		
		mongoDB_URL(Tech.MongoDB, MONGO_URL_VALUE_INJECTION, MONGO_URL_ERROR_INJECTION, MONGO_URL_PARAM_VALUE_INJECTION, 
				MONGO_JSON_PARAM_VALUE_INJECTION, MONGO_MATCHING_STRING, MONGO_PREFIX);

		private final String name;
		private final Tech dbTech;
		private final String[][] urlEncParamValueInjection;
		private final String[] urlEncValueInjection;
		private final String[] urlEncErrorInjection;
		private final String[][] jsonParamValueInjection;
		private final List<Pattern> errorPatterns;
		private final String prefix;

		/**
		 * 
		 * @param n
		 * @param t
		 * @param st
		 * @param v
		 * @param pv
		 * @param em
		 * @param ct
		 * @param p
		 */
		private NOSQLDB(Tech t, String[] uv, String[] ue, String[][] upv, String[][] jpv, String[] ep, String p) {
			name=t.getName();
			dbTech=t;
			urlEncValueInjection=uv;
			urlEncErrorInjection=ue;
			urlEncParamValueInjection=upv;
			jsonParamValueInjection=jpv;
			errorPatterns =  new ArrayList<>();
			for(String regex:ep) {
				errorPatterns.add(Pattern.compile(regex, AbstractAppParamPlugin.PATTERN_PARAM));
			}
			prefix=p;
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
		
		public String getPrefix() {
			return prefix;
		}
		
	};

   private static final Logger log = Logger.getLogger(TestNoSQLInjection.class);

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
		return Constant.messages.getString(MESSAGE_PREFIX+ "name");
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
		return dependency;
	}
   
	@Override
	public int getCweId() {
		return CWED_ID;
	}

	@Override
	public int getWascId() {
		return WASC_ID;
	}
	
	
    /**
     * Scan for NoSQL injection vulnerabilities
     * @inheritDoc
     *
     */
	public void scan(HttpMessage msg, String param, String value) {

		String paramInjected, valueInjected, attackType;
		HttpMessage injectedMsg, baseMsg;
		
		try {
			
			baseMsg = sendEmptyMessage(param, TOKEN);
			
			for(NOSQLDB nosql: NOSQLDB.values()) {

				if(inScope(nosql.getDbTech())){

					
					/**
					 * TODO check for the URL_ENCEODED format
					 * 
					 */
					if (true) { 

						for(String[] pv : nosql.getUrlEncParamValueInjection()) {
							
							attackType = PARVAL_ATTACK;
							injectedMsg = getNewMsg();
							paramInjected = param+pv[0];
							valueInjected = pv[1];
							
							setParameter(injectedMsg, paramInjected, valueInjected);
		
							try {
								sendAndReceive(injectedMsg, false);
								
								if(isBingo(baseMsg, injectedMsg, paramInjected, valueInjected, attackType, nosql)) {
									break;
								}
		
							} catch (SocketException ex) {
		
								if (log.isDebugEnabled()) 
									log.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
											" when accessing: " + msg.getRequestHeader().getURI().toString());
								continue;
							}
							finally {
								if(isStop())
									return;
							}
							
						}
						
						
						for(String v : nosql.getUrlEncValueInjection()) {
							attackType = VALUE_ATTACK;
							injectedMsg = getNewMsg();
							valueInjected = v;
							setParameter(injectedMsg, param, valueInjected);
							
							try {
								sendAndReceive(injectedMsg, false);
								
								if(isBingo(baseMsg, injectedMsg, param, valueInjected, attackType, nosql)) {
									break;
								}
		
							} catch (SocketException ex) {
		
								log.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
										" when accessing: " + msg.getRequestHeader().getURI().toString());
								continue;
							}
							finally {
								if(isStop())
									return;
							}
						}
					
						for (String e:nosql.getUrlEncErrorInjection()) {

							attackType = CRASH_ATTACK;
							injectedMsg = getNewMsg();
							valueInjected = e;
							setParameter(injectedMsg, param, valueInjected);
							
							try {
								sendAndReceive(injectedMsg, false);
								
								if(isBingo(baseMsg, injectedMsg, param, valueInjected, attackType, nosql)) {
									break;
								}
		
							} catch (SocketException ex) {
		
								log.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
										" when accessing: " + msg.getRequestHeader().getURI().toString());
								continue;
							}
							finally {
								if(isStop())
									return;
							}
						}
						
					}
					
					
					/**
					 * TODO check for the json format?
					 * 
					 */
					boolean jsonEnable = false;
					if (jsonEnable) {
						
						for(String[] jpv : nosql.getJsonParamValueInjection()) {
							
							attackType = JSON_ATTACK;
							injectedMsg = getNewMsg();
							
							
							/**
							 * TODO  set post request with json content-type
							 * 
							 */
							injectedMsg.getRequestHeader().setHeader(HttpRequestHeader.CONTENT_TYPE, 
									"application/json");
							injectedMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
							
							try {
								valueInjected = getParamJsonString(param, jpv);
								setParameter(injectedMsg, param, valueInjected);
								sendAndReceive(injectedMsg, false);
								if(isBingo(baseMsg, injectedMsg, param, valueInjected, attackType, nosql)) {
									break;
								}
							}catch(SocketException e) {
								log.debug("Caught " + e.getClass().getName() + " " + e.getMessage() + 
								" when accessing: " + msg.getRequestHeader().getURI().toString());
								continue;
							}catch(JSONException e) {
								log.debug("Caught " + e.getClass().getName() + " " + e.getMessage() + 
								" when try to convert to json the value: " + jpv);
								continue;
							}
							finally {
								if(isStop())
									return;
							}
						}
					}
	    		}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	/**
	 * 
	 * @param param
	 * @param token
	 * @return
	 */
	private HttpMessage sendEmptyMessage(String param, String token) {
		
		HttpMessage baseMsg = getNewMsg();
		setParameter(baseMsg, param, token);
		try {
			sendAndReceive(baseMsg);
		} catch (IOException e) {
			// TODO log exception
			e.printStackTrace();
			return getBaseMsg();
		}
		return baseMsg;
	}


	/**
	 * 
	 * @param originalMsg
	 * @param injectedMsg
	 * @param param
	 * @param valueInj
	 * @param attack
	 * @param nosql
	 * @return true if is discovered a vulnerability, false otherwise.
	 */
	private boolean isBingo(HttpMessage originalMsg, HttpMessage injectedMsg, String param, String valueInj, 
			String attack, NOSQLDB nosql) {
		
		String originalText = originalMsg.getResponseBody().toString();
		String injectedText = injectedMsg.getResponseBody().toString();
		String name = getName() + " - " + nosql.getName();
		String extraInfo = null;
		

		if(originalText.equals(injectedText)) 
			return false;

		
		else {
			
			
			/**
			 * The difference between the base response body and the after injecting one is for the only value passed 
			 * as input. So it could be a (uncommon) false positive result. For example the server could be response: 
			 * " @valueInj (or @TOKEN) doesn't exist, make sure you ... ". 
			 * 
			 */
			
			if(differingOnlyString(originalText, injectedText, valueInj, TOKEN)) {
	
				extraInfo = Constant.messages.getString(EXTRAINFO_PREFIX + nosql.prefix + FALSE_POSITIVE);
				
				bingo(Alert.RISK_LOW, Alert.CONFIDENCE_LOW, name, getDescription(), null, param, valueInj, 
						  extraInfo,  getSolution(), injectedMsg);

				return true;
			}

			StringBuilder sb = new StringBuilder();
		
			
			/**
			 * If the response message contains one of the note patterns then it is probable that the application has 
			 * a well-noted vulnerability. 
			 * 
			 */
			
			for(Pattern p:nosql.getErrorPatterns()) {
				if(matchBodyPattern(injectedMsg, p, sb)) {
					extraInfo = Constant.messages.getString(EXTRAINFO_PREFIX + nosql.prefix + attack);
					
					bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, name, getDescription(), null, param, valueInj, 
						  extraInfo,  getSolution(), injectedMsg);

					return true;
				}
			}
			
			
			/**
			 * Unknown vulnerability.  
			 * 
			 */
			
			bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, name, getDescription(), null, param, valueInj, 
					  extraInfo,  getSolution(), injectedMsg);

			return true;
		}
	}
	

	/**
	 * Checks if the two text string differing only for the {@valueInjected} value.
	 * 
	 * @param originalMsg
	 * @param injectedMsg
	 * @param valueInjected
	 * @return true if the @originalMsg body isn't the same of the @injectedMsg one, false otherwise.
	 * 
	 */
	private boolean differingOnlyString(String originalMsg, String injectedMsg, String token, String valueInjected) {

		int lengthOriginal = originalMsg.length();
		int lengthInjected = injectedMsg.length();
		int lengthValue = valueInjected.length();
		int lengthToken = token.length();
		
		if(lengthOriginal-lengthInjected!=lengthValue-lengthToken)
			return false;
		
		char cursOriginal, cursInjected;
		String extractString;
		
		for(int index=0; index<lengthInjected; index++) {
			cursOriginal = originalMsg.charAt(index);
			cursInjected = injectedMsg.charAt(index);
			if(cursInjected!=cursOriginal) {
				extractString = injectedMsg.substring(index, index+lengthValue);
				if(extractString.equals(injectedMsg))
					return true;
				else return false;
			}
		}
		return false;
	}

	
	/**
	 * Build a json string starting with the values passed as parameter: @param and its children @params[1] and 
	 * @params[2].
	 * 
	 * @param param
	 * @param params
	 * @return
	 * @throws JSONException
	 */
	private String getParamJsonString(String param, String[] params) throws JSONException {
		JSONObject internal = new JSONObject(),
				   external = new JSONObject();
    	internal.put(params[0] , params[1]);
    	external.put(param, internal);
    	
		return external.toString();
	}
}