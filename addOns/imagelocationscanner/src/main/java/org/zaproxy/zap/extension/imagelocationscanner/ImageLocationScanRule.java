/*
 * The ZAP plug-in wrapper for Veggiespam's Image Location and Privacy Scanner
 * class. Passively scans an image data stream (jpg/png/etc) and reports if the
 * image contains embedded location or privacy information, such as Exif GPS,
 * IPTC codes, and some proprietary camera codes which may contain things like
 * serial numbers.
 * 
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / https://www.veggiespam.com/ils/
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
package org.zaproxy.zap.extension.imagelocationscanner;

import net.htmlparser.jericho.Source;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

import com.veggiespam.imagelocationscanner.ILS;

/**
 * The ZAP plug-in wrapper for Veggiespam's Image Location and Privacy Scanner
 * class. Passively scans an image data stream (jpg/png/etc) and reports if the
 * image contains embedded location or privacy information, such as Exif GPS, 
 * IPTC codes, and some proprietary camera codes which may contain things like 
 * serial numbers.
 * 
 * @author  Jay Ball / github: veggiespam / twitter: @veggiespam / www.veggiespam.com
 * @license Apache License 2.0
 * @version 1.1
 * @see https://www.veggiespam.com/ils/
 */
public class ImageLocationScanRule extends PluginPassiveScanner {
	private static final Logger logger = LogManager.getLogger(ImageLocationScanRule.class);
	private static final String MESSAGE_PREFIX = "imagelocationscanner.";
	public static final int PLUGIN_ID = 10103;
	
    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		return;
	}

	@Override
	public int getPluginId() {
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
            CT = CT.toLowerCase();
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
            logger.debug("\tCT: {} url: {} fileName: {} ext: {}", CT, url, fileName, extension);
        }
        
        // everything is already lowercase
        if (CT.startsWith("image/jpeg") || CT.startsWith("image/jpg") 
                || extension.equals("jpeg") || extension.equals("jpg")  
                || CT.startsWith("image/png")   || extension.equals("png")  
                || CT.startsWith("image/tiff")  || extension.equals("tiff") || extension.equals("tif")
                ) {
		
			String hasGPS = ILS.scanForLocationInImage(msg.getResponseBody().getBytes(), false);
			
			if (! hasGPS.isEmpty()) {
			    newAlert()
			    .setName(getAlertTitle())
			    .setRisk(Alert.RISK_INFO)
			    .setConfidence(Alert.CONFIDENCE_MEDIUM)
			    .setDescription(getDescription())
			    .setSolution(getSolution())
			    .setReference(getReference())
			    .setEvidence(getAlertDetailPrefix()  + "\n" + hasGPS)
			    .setCweId(200) // CWE-200: Information Exposure
			    .setWascId(13) // WASC-13: Information Leakage
			    .raise();
			}
			
		}
		if (logger.isDebugEnabled()) {
		    logger.debug("\tScan of record {} took {} ms", id, System.currentTimeMillis() - start);
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

    @Override
    public boolean appliesToHistoryType(int historyType) {
        if (historyType == HistoryReference.TYPE_HIDDEN) {
            // Scan hidden images, if the scanner is enabled it should scan.
            return true;
        }
        return super.appliesToHistoryType(historyType);
    }
}
