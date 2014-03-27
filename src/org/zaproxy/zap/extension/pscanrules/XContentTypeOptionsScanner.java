package org.zaproxy.zap.extension.pscanrules;

import java.util.Vector;

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class XContentTypeOptionsScanner  extends PluginPassiveScanner {

	private PassiveScanThread parent = null;
	
	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		
		
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		if (msg.getResponseBody().length() > 0) {
			Vector<String> xContentTypeOptions = msg.getResponseHeader().getHeaders(HttpHeader.X_CONTENT_TYPE_OPTIONS);
			if (xContentTypeOptions == null) {
				this.raiseAlert(msg, id, "");
			} else {
				for (String xContentTypeOptionsDirective : xContentTypeOptions) {
					//'nosniff' is currently the only defined value for this header, so this logic is ok
					if (xContentTypeOptionsDirective.toLowerCase().indexOf("nosniff") < 0) {
						this.raiseAlert(msg, id, xContentTypeOptionsDirective);
					}
				}
			} 
		}
	}
		
	private void raiseAlert(HttpMessage msg, int id, String xContentTypeOption) {
		Alert alert = new Alert(getPluginId(), Alert.RISK_LOW, Alert.WARNING, 
		    	getName());
		    	alert.setDetail(
		    		"The Anti-MIME-Sniffing header "+HttpHeader.X_CONTENT_TYPE_OPTIONS +" was not set to 'nosniff'.\nThis allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type.\nCurrent (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.",
		    	    msg.getRequestHeader().getURI().toString(),
		    	    xContentTypeOption,
		    	    "", 
		    	    "", 
		    	    "Ensure that the application/web server sets the "+HttpHeader.CONTENT_TYPE +" header appropriately, and that it sets the "+HttpHeader.X_CONTENT_TYPE_OPTIONS + " header to 'nosniff' for all web pages.\nIf possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.", 
		            "", 
		            "", // No evidence
		            0,	// TODO CWE Id
		            0,	// TODO WASC Id
		            msg);
	
    	parent.raiseAlert(id, alert);
	}
		

	@Override
	public void setParent(PassiveScanThread parent) {
			this.parent = parent;
	}

	@Override
	public String getName() {
		return "X-Content-Type-Options header missing";
	}
	
	@Override
	public int getPluginId() {
		return 10021;
	}

}
