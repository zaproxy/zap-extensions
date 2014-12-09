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




import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;
import org.zaproxy.zap.network.HttpResponseBody;

/**
 * A Buffer Overflow  scan rule, for more details see 
 * Copyright (C) 2014 Institute for Defense Analyses
 * @author Mark Rader based upon the example active scanner by psiinon
 */
public class BufferOverflow extends AbstractAppParamPlugin  {

	// wasc_7 is a buffer overflow ;)
	private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_7");

	

	private static Logger log = Logger.getLogger(BufferOverflow.class);
	
	@Override
	public int getId() {
		/*
		 * This should be unique across all active and passive rules.
		 * The master list is http://code.google.com/p/zaproxy/source/browse/trunk/src/doc/alerts.xml
		 */
		return 30001;
	}

	@Override
	public String getName() {
		// Strip off the "Buffer Overflow Scanner: " part if implementing a real one ;)
		if (vuln != null) {
			return "Buffer overflow: " + vuln.getAlert();
		}
		return "Buffer Overflow: Buffer Overflowed";
	}

	@Override
	public String[] getDependency() {
		return null;
	}

	@Override
	public String getDescription() {
		if (vuln != null) {
			return vuln.getDescription();
		}
		return "Failed to load vulnerability description from file";
	}

	@Override
	public int getCategory() {
		return Category.INJECTION;
	}

	@Override
	public String getSolution() {
		if (vuln != null) {
			return vuln.getSolution();
		}
		return "Failed to load vulnerability solution from file";
	}

	@Override
	public String getReference() {
		if (vuln != null) {
			StringBuilder sb = new StringBuilder();
			for (String ref : vuln.getReferences()) {
				if (sb.length() > 0) {
					sb.append("\n");
				}
				sb.append(ref);
			}
			return sb.toString();
		}
		return "Failed to load vulnerability reference from file";
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
		try {
			// This is where you change the 'good' request to attack the application
			// You can make multiple requests if needed
			String checkStringHeader1 = "Connection: close";  // Un natural close
			String checkStringBody1 = "500 Internal Server Error";  //No response
			String errorBufferOverflowMessage = "Potential Buffer Overflow.  The script closed the connection and threw a 500 Internal Server Error";
			// Always use getNewMsg() for each new request
			msg = getNewMsg();
			String returnAttack = randomCharacterString(2100);
			setParameter(msg, param, returnAttack);
			sendAndReceive(msg);
			HttpResponseHeader requestReturn = msg.getResponseHeader();
			HttpResponseBody responseBody= msg.getResponseBody();
			
			// This is where BASE baseResponseBody was you detect potential vulnerabilities in the response
     
    		String chkerrorheader = requestReturn.getHeadersAsString();
    		String chkerrorbody = responseBody.toString();
    		log.debug("Header: "+ chkerrorheader);
    		if (chkerrorbody.contains(checkStringBody1) && chkerrorheader.contains(checkStringHeader1))
    		{
    			log.debug("Found Header");
    			bingo(getRisk(), Alert.MEDIUM, null, param, returnAttack, errorBufferOverflowMessage ,msg);
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
		return 120;
	}

	@Override
	public int getWascId() {
		// The WASC ID
		return 7;
	}
	
	private String randomCharacterString(int length)
	{
		String returnString = "";
		int counter = 0;
		int character = 0;
		while (counter < length)
		{	
			 character = 65 + (int) (Math.random()*57); 

		        while ( character > 90 && character < 97)
		        {
		        	character = 65 + (int) (Math.random()*57); 
		        }

				counter = counter +1;
				returnString = returnString + (char) character;
		}
		return returnString;
	}

private String randomOddCharacterString(int length)
{
	String returnString = "";
	int counter = 0;
	int character = 0;
	while (counter < length)
	{	
        character = 65 + (int) (Math.random()*57); 
        character |= 0x01;
        log.debug("Character Generator   " + character + "   " + (char) character );
        while ( character > 90 && character < 97)
        {
        	character = 65 + (int) (Math.random()*57); 
            character |= 0x01;
        }
        log.debug("Character Generator   " + character + "   " + (char) character );
		counter = counter +1;
		returnString = returnString + (char) character;
	}
	return returnString;
	}
}

