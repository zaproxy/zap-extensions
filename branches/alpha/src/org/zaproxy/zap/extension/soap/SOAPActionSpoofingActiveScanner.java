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
package org.zaproxy.zap.extension.soap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;

/**
 * SOAP Action Spoofing Active Scanner
 * @author Albertov91
 */
public class SOAPActionSpoofingActiveScanner extends AbstractAppPlugin {

	private static final String MESSAGE_PREFIX = "soap.soapactionspoofing.";

	private static Logger log = Logger.getLogger(SOAPActionSpoofingActiveScanner.class);
	

	
	
	@Override
	public int getId() {
		/*
		 * This should be unique across all active and passive rules.
		 * The master list is http://code.google.com/p/zaproxy/source/browse/trunk/src/doc/alerts.xml
		 */
		return 90026;
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	public String getDescription() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	public String getSolution() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	public String getReference() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}
	
	@Override
	public String[] getDependency() {
		return null;
	}

	@Override
	public int getCategory() {
		return Category.MISC;
	}

	@Override
	public void init() {

	}

	/*
	 * This method is called by the active scanner for each GET and POST parameter for every page 
	 * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
	 */
	@Override
	public void scan() {
		try {
			/* Retrieves the original request-response pair. */			
			final HttpMessage originalMsg = getBaseMsg();
			/* This scan is only applied to SOAP 1.1 messages. */
			String currentHeader = originalMsg.getRequestHeader().getHeader("SOAPAction");
			if(currentHeader != null && originalMsg.getRequestBody().length() > 0){
				currentHeader = currentHeader.trim();				
				/* Retrieves available actions to try attacks. */
				String[] soapActions = ImportWSDL.getInstance().getSourceSoapActions(originalMsg);
				
				boolean endScan = false;
				for(int j = 0; j < soapActions.length && !endScan; j++){
					HttpMessage msg = getNewMsg();
					/* Skips the original case. */
					if(!currentHeader.equals(soapActions[j])){
						HttpRequestHeader header = msg.getRequestHeader();
						/* Available actions should be known here from the imported WSDL file. */				
						header.setHeader("SOAPAction", soapActions[j]);
						msg.setRequestHeader(header);
						
						/* Sends the modified request. */
						sendAndReceive(msg);
						
						/* Checks the response. */
						endScan = scanResponse(msg, originalMsg);
					}
				}
			}
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}	
	}

	private boolean scanResponse(HttpMessage msg, HttpMessage originalMsg){
		String responseContent = new String(msg.getResponseBody().getBytes());
		responseContent = responseContent.trim();
		
		if (responseContent.length() <= 0){
			bingo(Alert.RISK_LOW, Alert.WARNING, null, null, "Response is empty.", null, msg);
			return false;
		}
		
  
	    SOAPMessage soapMsg = null;
		try {
			MessageFactory factory = MessageFactory.newInstance();
			soapMsg = factory.createMessage(
			        new MimeHeaders(),
			        new ByteArrayInputStream(responseContent.getBytes(Charset
			                .forName(msg.getResponseBody().getCharset()))));	
			
			/* Looks for fault code. */
			SOAPBody body = soapMsg.getSOAPBody();
			SOAPFault fault = body.getFault();
			if (fault != null){
				/* The web service server has detected something was wrong
				 * with the SOAPAction header so it rejects the request. */
				return false;
			}
			
			// Body child.
			NodeList bodyList = body.getChildNodes();
			if (bodyList.getLength() <= 0) return false;
			
			/* Prepares original request to compare it. */
			String originalContent = originalMsg.getResponseBody().toString();
			SOAPMessage originalSoapMsg = factory.createMessage(
			        new MimeHeaders(),
			        new ByteArrayInputStream(originalContent.getBytes(Charset
			                .forName(originalMsg.getResponseBody().getCharset()))));
			
			/* Comparison between original response body and attack response body. */
			SOAPBody originalBody = originalSoapMsg.getSOAPBody();
			NodeList originalBodyList = originalBody.getChildNodes();
			if(bodyList.getLength() == originalBodyList.getLength()){
				boolean match = true;
				for(int i = 0; i < bodyList.getLength() && match; i++){
					Node node = bodyList.item(i);
					Node oNode = originalBodyList.item(i);
					if (node.getNodeName() != oNode.getNodeName()) match = false;
				}
				if (match){
					/* Both responses have the same content. The SOAPAction header has been ignored.
					 * SOAPAction Spoofing attack cannot be done if this happens. */
					bingo(Alert.RISK_INFO, Alert.WARNING, null, null, "The SOAPAction header has been ignored.", null, msg);
					return true;
				}else{
					/* The SOAPAction header has been processed and an operation which is not the original one has been executed. */
					bingo(Alert.RISK_HIGH, Alert.WARNING, null, null, "The SOAPAction operation has been executed.", null, msg);
					return true;
				}				
			}else{
				/* The SOAPAction header has been processed and an operation which is not the original one has been executed. */
				bingo(Alert.RISK_HIGH, Alert.WARNING, null, null, "The SOAPAction operation has been executed.", null, msg);
				return true;
			}
		} catch (IOException | SOAPException e) {
			bingo(Alert.RISK_LOW, Alert.WARNING, null, null, "Response has an invalid format.", null, msg);
			return false;
		}	
	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

	@Override
	public int getCweId() {
		// The CWE id
		return 0;
	}

	@Override
	public int getWascId() {
		// The WASC ID
		return 0;
	}
}
