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
package org.zaproxy.zap.extension.examplePassiveScan;

import java.util.Date;
import java.util.Random;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/*
 * An example passive scanner.
 */
public class ExamplePassiveScanner extends PluginPassiveScanner implements PassiveScanner {

	// wasc_10 is Denial of Service - well, its just an example ;)
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_10");
	private PassiveScanThread parent = null;
	private Logger logger = Logger.getLogger(this.getClass());
	
	private Random rnd = new Random();

	@Override
	public void setParent (PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// You can also detect potential vulnerabilities here, with the same caveats as below.
	}

	private int getId() {
		return 90001;	// This is be changed if included in the ZAP code base  
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		Date start = new Date();
		
		// This is where you detect potential vulnerabilities.
		// You can examine the msg or source but should not change anything
		// or make any requests to the server
		
		// For this example we're just going to raise the alert at random!
		
		if (rnd.nextInt(10) == 0) {
		    Alert alert = new Alert(getId(), Alert.RISK_MEDIUM, Alert.WARNING, 
			    	getName());
			    	alert.setDetail(
			    		getDescription(), 
			    		msg.getRequestHeader().getURI().toString(),
			    		"",
			    		"", 
			    		"", 
			    		getSolution(), 
			            getReference(), 
			            msg);

	    	parent.raiseAlert(id, alert);
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("\tScan of record " + id + " took " + ((new Date()).getTime() - start.getTime()) + " ms");
		}
		
	}

	@Override
	public String getName() {
		// Strip off the "Example Passive Scanner: " part if implementing a real one ;)
    	if (vuln != null) {
    		return "Example Passive Scanner: " + vuln.getAlert();
    	}
    	return "Example Passive Scanner: Denial of Service";
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

}
