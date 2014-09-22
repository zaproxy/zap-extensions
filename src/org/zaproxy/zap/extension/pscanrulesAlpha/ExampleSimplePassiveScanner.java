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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.Random;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * An example passive scan rule, for more details see 
 * http://zaproxy.blogspot.co.uk/2014/04/hacking-zap-3-passive-scan-rules.html
 * @author psiinon
 */
public class ExampleSimplePassiveScanner extends PluginPassiveScanner {

	// wasc_10 is Denial of Service - well, its just an example ;)
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_10");
	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(ExampleSimplePassiveScanner.class);
	
	private Random rnd = new Random();

	@Override
	public void setParent (PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// You can also detect potential vulnerabilities here, with the same caveats as below.
	}

	@Override
	public int getPluginId() {
		/*
		 * This should be unique across all active and passive rules.
		 * The master list is http://code.google.com/p/zaproxy/source/browse/trunk/src/doc/alerts.xml
		 */
		return 60000;
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		long start = System.currentTimeMillis();
		
		// This is where you detect potential vulnerabilities.
		// You can examine the msg or source but should not change anything
		// or make any requests to the server
		
		// For this example we're just going to raise the alert at random!
		
		if (rnd.nextInt(10) == 0) {
		    Alert alert = new Alert(getPluginId(), Alert.RISK_MEDIUM, Alert.WARNING, 
			    	getName());
			    	alert.setDetail(
			    		getDescription(), 
			    		msg.getRequestHeader().getURI().toString(),
			    		"",	// Param
			    		"", // Attack
			    		"", // Other info
			    		getSolution(), 
			            getReference(), 
			            "",	// Evidence
			            0,	// CWE Id
			            0,	// WASC Id
			            msg);

	    	parent.raiseAlert(id, alert);
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("\tScan of record " + id + " took " + (System.currentTimeMillis() - start) + " ms");
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
	
    public String getDescription() {
    	if (vuln != null) {
    		return vuln.getDescription();
    	}
    	return "Failed to load vulnerability description from file";
    }

    public int getCategory() {
        return Category.MISC;
    }

    public String getSolution() {
    	if (vuln != null) {
    		return vuln.getSolution();
    	}
    	return "Failed to load vulnerability solution from file";
    }

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

}
