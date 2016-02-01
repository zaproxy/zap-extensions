/*
 * The ZAP plug-in wrapper for Veggiespam's Image
 * Location Scanner class. Passively scans a data stream containing 
 * a jpeg and report if the data contains embedded Exif GPS location.
 * 
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / http://www.veggiespam.com/ils/
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

import net.htmlparser.jericho.Source;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import com.veggiespam.imagelocationscanner.ILS;

/**
 * The ZAP plug-in wrapper for Veggiespam's Image
 * Location Scanner class. Passively scans a data stream containing 
 * a jpeg and reports if the data contains embedded Exif GPS location. 
 * 
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / www.veggiespam.com
 * @license Apache License 2.0
 * @version 0.2
 * @see http://www.veggiespam.com/ils/
 */
public class ImageLocationScanner extends PluginPassiveScanner {
	private PassiveScanThread parent = null;
	private static final Logger logger = Logger.getLogger(ImageLocationScanner.class);
	private static final String MESSAGE_PREFIX = "pscanalpha.imagelocationscanner.";
	private static final int PLUGIN_ID = 10103;
	
	
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
		 * The master list is https://github.com/zaproxy/zaproxy/blob/develop/src/doc/alerts.xml
		 */
		return PLUGIN_ID;
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		long start = 0;
		if (logger.isDebugEnabled()) {
			start = System.currentTimeMillis();
		}
		
        // Mnemonic: CT ==> Content-Type
        String CT = msg.getResponseHeader().getHeader("Content-Type");
        if (null == CT) {
            CT = "";
        } else {
            CT.toLowerCase();
        }

        URI uri = msg.getRequestHeader().getURI();
        String url = uri.toString();
        String fileName;
		try {
			fileName = uri.getName();
			if (fileName == null) {
				fileName = "";
			}
		} catch (URIException e) {
			// e.printStackTrace();
			// If we cannot decode the URL, then just set filename to empty.
			fileName = "";
		}
        String extension = "";
        int i = fileName.lastIndexOf('.');
        if (i > 0) {
            extension = fileName.substring(i+1).toLowerCase();
        }

        if (logger.isDebugEnabled()) {
		    logger.debug("\tCT: " + CT + " url: " + url + " fileName: " + fileName + " ext: " + extension);
        }
        
        // everything is already lowercase
        if (CT.startsWith("image/jpeg") || CT.startsWith("image/jpg") 
                || extension.equals("jpeg") || extension.equals("jpg")  
                || CT.startsWith("image/png")   || extension.equals("png")  
                || CT.startsWith("image/tiff")  || extension.equals("tiff") || extension.equals("tif")
                ) {
		
			String hasGPS = ILS.scanForLocationInImage(msg.getResponseBody().getBytes());
			
			if (! hasGPS.isEmpty()) {
				Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_MEDIUM, getAlertTitle());
				alert.setDetail(
			    		getDescription(), 
			    		url,
			    		"",	// Param
			    		"None, information disclosure warning.", // Attack
			    		"", // Other info
			    		getSolution(), 
			            getReference(), 
                        getAlertDetailPrefix()  + " " + hasGPS,	// Evidence
			            200, // CWE-200: Information Exposure
			            13,	// WASC-13: Information Leakage
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
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}
	
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getAlertTitle() {
        return Constant.messages.getString(MESSAGE_PREFIX + "alerttitle");
    }

    public String getAlertDetailPrefix() {
        return Constant.messages.getString(MESSAGE_PREFIX + "alertDetailPrefix");
    }

    public int getCategory() {
        return Category.INFO_GATHER;
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }
    
    public String getAuthor() {
        return ILS.pluginAuthor;
    }
}
