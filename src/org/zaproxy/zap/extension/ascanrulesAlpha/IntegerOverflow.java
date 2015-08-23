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

/**
 * Integer Overflow an active scan rule
 * Copyright (C) 2015 Institute for Defense Analyses
 * @author Mark Rader based upon the example active scanner by psiinon
 * 
 */

package org.zaproxy.zap.extension.ascanrulesAlpha;





import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;


public class IntegerOverflow extends AbstractAppParamPlugin  {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "ascanalpha.integeroverflow.";
	private static final int PLUGIN_ID = 30003;
	private static Logger log = Logger.getLogger(IntegerOverflow.class);
	
	@Override
	public int getId() {
		return PLUGIN_ID;
	}

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public String[] getDependency() {
		return null;
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
	
	public String getOther() {
		return Constant.messages.getString(MESSAGE_PREFIX + "other");
	}
	
	private String getError(char c) {
		return Constant.messages.getString(MESSAGE_PREFIX + "error"+c);
	}
	
	@Override
	public void init() {

	}

	/*
	 * This method is called by the active scanner for each GET and POST parameter for every page 
	 * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
	 */
	@Override
	public void scan(HttpMessage msg, String param, String value) {
	
		if (this.isStop()) { // Check if the user stopped things
			if (log.isDebugEnabled()) {
				log.debug("Scanner "+this.getName()+" Stopping.");
			}
			return; // Stop!
		}
		
		try {
			
			msg = getNewMsg();
			String returnAttack = randomIntegerString(4);// The number of full length ints to send.
			setParameter(msg, param, returnAttack);
			sendAndReceive(msg);
			HttpResponseHeader requestReturn = msg.getResponseHeader();			
			// This is where BASE baseResponseBody was you detect potential vulnerabilities in the response
    		String chkerrorheader = requestReturn.getHeadersAsString();
    		log.debug("Header: "+ chkerrorheader);
    		if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.INTERNAL_SERVER_ERROR )
    		{
    			log.debug("Found Header");
    			bingo(getRisk(), 
    					Alert.CONFIDENCE_MEDIUM, 
    					this.getBaseMsg().getRequestHeader().getURI().toString(), 
    					param, 
    					msg.getRequestHeader().toString(), 
    					this.getError('1') ,
    					msg);
    			return;
    		}
    		msg = getNewMsg();
			returnAttack = singleString(4,'0');// The number of full length ints to send.
			setParameter(msg, param, returnAttack);
			sendAndReceive(msg);
			requestReturn = msg.getResponseHeader();			
			// This is where BASE baseResponseBody was you detect potential vulnerabilities in the response
    		chkerrorheader = requestReturn.getHeadersAsString();
    		log.debug("Header: "+ chkerrorheader);
    		if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.INTERNAL_SERVER_ERROR)
    		{
    			log.debug("Found Header");
    			bingo(getRisk(), 
    					Alert.CONFIDENCE_MEDIUM, 
    					this.getBaseMsg().getRequestHeader().getURI().toString(), 
    					param, 
    					msg.getRequestHeader().toString(), 
    					this.getError('2') ,
    					msg);
    			return;
    		}
    		msg = getNewMsg();
			returnAttack = singleString(4,'1');// The number of full length ints to send.
			setParameter(msg, param, returnAttack);
			sendAndReceive(msg);
			requestReturn = msg.getResponseHeader();			
			// This is where BASE baseResponseBody was you detect potential vulnerabilities in the response
    		chkerrorheader = requestReturn.getHeadersAsString();
    		log.debug("Header: "+ chkerrorheader);
    		if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.INTERNAL_SERVER_ERROR)
    		{
    			log.debug("Found Header");
    			bingo(getRisk(), 
    					Alert.CONFIDENCE_MEDIUM, 
    					this.getBaseMsg().getRequestHeader().getURI().toString(), 
    					param, 
    					msg.getRequestHeader().toString(), 
    					this.getError('3') ,
    					msg);
    			return;
    		}
    		msg = getNewMsg();
			returnAttack = singleString(4,'9');// The number of full length ints to send.
			setParameter(msg, param, returnAttack);
			sendAndReceive(msg);
			requestReturn = msg.getResponseHeader();			
			// This is where BASE baseResponseBody was you detect potential vulnerabilities in the response
    		chkerrorheader = requestReturn.getHeadersAsString();
    		log.debug("Header: "+ chkerrorheader);
    		if (msg.getResponseHeader().getStatusCode() == HttpStatusCode.INTERNAL_SERVER_ERROR)
    		{
    			log.debug("Found Header");
    			bingo(getRisk(), 
    					Alert.CONFIDENCE_MEDIUM, 
    					this.getBaseMsg().getRequestHeader().getURI().toString(), 
    					param, 
    					msg.getRequestHeader().toString(), 
    					this.getError('4') ,
    					msg);
    			return;
    		}
    			
				return;	

			
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}	
	}

	@Override
	public int getRisk() {
		return Alert.RISK_MEDIUM;
	}

	@Override
	public int getCweId() {
		// The CWE id
		return 190;
	}

	@Override
	public int getWascId() {
		// The WASC ID
		return 3;
	}
	
	private String randomIntegerString(int length)
	{
		
		int numbercounter = 0;
		int character = 0;
		long charactercounter = 0;
		long maxcharacter = 2147483647;
		StringBuilder sb1 = new StringBuilder();
		while (numbercounter < length)
		{
			charactercounter = 0;
			while (charactercounter < maxcharacter)
			{	
				 character = 48 + (int) (Math.random()*10); 
	
			        while ( character > 57 && character < 48)
			        {
			        	character = 48 + (int) (Math.random()*10); 
			        }
	
					charactercounter++;
					sb1.append((char)character);
			}
			numbercounter++;
		}
		return sb1.toString();
	}
	
	private String singleString(int length, char c)//Single Character String
	{
		
		int numbercounter = 0;
		long charactercounter = 0;
		long maxcharacter = 2147483647;
		StringBuilder sb1 = new StringBuilder();
		while (numbercounter < length)
		{	
			charactercounter = 0;
			while (charactercounter < maxcharacter)
			{	
					charactercounter++;
					sb1.append(c);
			}
			numbercounter++;
		}
		return sb1.toString();
	}
}

