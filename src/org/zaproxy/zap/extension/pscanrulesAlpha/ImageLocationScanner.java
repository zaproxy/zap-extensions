/*
 * The ZAP plug-in wrapper for Veggiespam's Image
 * Location Scanner class. Passively scans a data stream containing 
 * a jpeg and report if the data contains embedded Exif GPS location.
 * 
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / www.veggiespam.com
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

import java.net.URL;
import java.util.Random;

import net.htmlparser.jericho.Source;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

import com.veggiespam.imagelocationscanner.ILS;

/**
 * The ZAP plug-in wrapper for Veggiespam's Image
 * Location Scanner class. Passively scans a data stream containing 
 * a jpeg and reports if the data contains embedded Exif GPS location. 
 * 
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / www.veggiespam.com
 * @license Apache License 2.0
 * @version 0.1
 * @see http://www.veggiespam.com/ils/
 */
public class ImageLocationScanner extends PluginPassiveScanner {
	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(ImageLocationScanner.class);
	
	/** A bunch of static strings that are used by both ZAP and Burp plug-ins.  These
	 * are the default names of the items.  At some point in the future, these will
	 * need to be localized in the ZAP manner, but these will be the embedded defaults. */
    private static final String pluginName = ILS.pluginName;
    private static final String alertTitle = ILS.alertTitle;
    private static final String issueDetailPrefix = ILS.alertDetailPrefix;
    private static final String issueBackground  = ILS.alertBackground;
    private static final String remediationBackground = ILS.remediationBackground;
    //private static final String remediationDetail = ILS.remediationDetail;
    private static final String referenceURL = ILS.referenceURL; 
    private static final String pluginAuthor = ILS.pluginAuthor; 


	
	
	@Override
	public void setParent (PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		return;
	}

	@Override
	public int getPluginId() {
		/*
		 * This should be unique across all active and passive rules.
		 * The master list is http://code.google.com/p/zaproxy/source/browse/trunk/src/doc/alerts.xml
		 */
		return 333292; // FIXME TEMP XXX TODO - get a real ID.
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		long start = 0;
		if (logger.isDebugEnabled()) {
			start = System.currentTimeMillis();
		}
				
        String CT = msg.getResponseHeader().getHeader("Content-Type");
        URI uri = msg.getRequestHeader().getURI();
        String url = uri.toString();
        String fileName;
		try {
			fileName = uri.getName();
		} catch (URIException e) {
			// e.printStackTrace();
			fileName = "";
		}
        String extension = "";
        int i = fileName.lastIndexOf('.');
        if (i > 0) {
            extension = fileName.substring(i+1);
        }

		logger.debug("\tCT: " + CT + " url: " + url + " fileName: " + fileName + " ext: " + extension);

		if (CT.equalsIgnoreCase("image/jpeg") || CT.equalsIgnoreCase("image/jpg") 
				|| extension.equalsIgnoreCase("jpeg")  || extension.equalsIgnoreCase("jpg")  ) {
		
			String hasGPS = ILS.scanForLocationInImage(msg.getResponseBody().getBytes());
			
			if (! hasGPS.isEmpty()) {
				Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM, alertTitle);
				alert.setDetail(
			    		getDescription(), 
			    		url,
			    		"",	// Param
			    		"None, information disclosure warning.", // Attack
			    		"", // Other info
			    		getSolution(), 
			            getReference(), 
			            issueDetailPrefix + hasGPS,	// Evidence
			            0,	// CWE Id
			            0,	// WASC Id
			            msg);
				
		    	parent.raiseAlert(id, alert);
			}
			
		}
		if (logger.isDebugEnabled()) {
			logger.debug("\tScan of record " + id + " took " + (System.currentTimeMillis() - start) + " ms");
		}
	}

	@Override
	public String getName() {
		return pluginName;
	}
	
    public String getDescription() {

    	return issueBackground;
    }

    public int getCategory() {
        return Category.INFO_GATHER;
    }

    public String getSolution() {
    	return remediationBackground;
    }

    public String getReference() {
    	return referenceURL;
    }
    
    public String getAuthor() {
    	return pluginAuthor;
    }


}
