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
package org.zaproxy.zap.extension.exampleActiveScan;

import java.util.Random;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;


public class ExampleActiveScanner extends AbstractAppParamPlugin {

	// wasc_10 is Denial of Service - well, its just an example ;)
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_10");

	private Random rnd = new Random();

    private static Logger log = Logger.getLogger(ExampleActiveScanner.class);
	
    public int getId() {
        return 20010;
    }

    public String getName() {
		// Strip off the "Example Active Scanner: " part if implementing a real one ;)
    	if (vuln != null) {
    		return "Example Active Scanner: " + vuln.getAlert();
    	}
    	return "Example Active Scanner: Denial of Service";
    }

    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.Test#getDependency()
     */
    public String[] getDependency() {
        return null;
    }

    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.Test#getDescription()
     */
    public String getDescription() {
    	if (vuln != null) {
    		return vuln.getDescription();
    	}
    	return "Failed to load vulnerability description from file";
    }

    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.Test#getCategory()
     */
    public int getCategory() {
        return Category.MISC;
    }

    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.Test#getSolution()
     */
    public String getSolution() {
    	if (vuln != null) {
    		return vuln.getSolution();
    	}
    	return "Failed to load vulnerability solution from file";
    }

    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.Test#getReference()
     */
    public String getReference() {
    	if (vuln != null) {
    		StringBuffer sb = new StringBuffer();
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

    /* (non-Javadoc)
     * @see com.proofsecure.paros.core.scanner.AbstractTest#init()
     */
    public void init() {

    }
    

    /*
     * This method is called by the active scanner for each GET and POST parameter for every page 
     * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
     */
    public void scan(HttpMessage msg, String param, String value) {
		try {
			// This is where you change the 'good' request to attack the application
			// You can make multiple requests if needed
			String attack = "attack";
			setParameter(msg, param, attack);
            sendAndReceive(msg);
            
    		// This is where you detect potential vulnerabilities in the response
    		
    		// For this example we're just going to raise the alert at random!
    		
    		if (rnd.nextInt(10) == 0) {
           		bingo(Alert.RISK_HIGH, Alert.WARNING, null, param, value, null, msg);
    			return;
            }

            
        } catch (Exception e) {
        	log.error(e.getMessage(), e);
        }	

	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

}
