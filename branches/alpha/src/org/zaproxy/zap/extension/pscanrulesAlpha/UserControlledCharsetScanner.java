package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTag;
import net.htmlparser.jericho.StartTagType;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Port for the Watcher passive scanner (http://websecuritytool.codeplex.com/)
 * rule {@code CasabaSecurity.Web.Watcher.Checks.CheckPasvUserControlledCharset}
 */
public class UserControlledCharsetScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanalpha.usercontrolledcharset.";

	public UserControlledCharsetScanner() {
		super();
		PscanUtils.registerI18N();
	}
	
	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// do nothing
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {		
		if (msg.getResponseHeader().getStatusCode() != 200) {
			return;
		}
		
    	String responseBody = msg.getRequestBody().toString();
    	if (responseBody == null) {
    		return;
    	}		
		
    	Set<HtmlParameter> params = new TreeSet<HtmlParameter>(msg.getFormParams());
    	params.addAll(msg.getUrlParams());    	
    	if (params.size() == 0) {
    		return;
    	}
    	
    	if (!isResponseHTML(msg, source) && !isResponseXML(msg, source)) {
    		return;
    	}		   	
    	        	
        if (isResponseHTML(msg, source)) {
        	checkMetaContentCharset(msg, source, params);
        } else if (isResponseXML(msg, source)) {
        	checkXmlEncodingCharset(msg, source, params);
        }
            
        checkContentTypeCharset(msg, params);
	}
	
	private void checkMetaContentCharset(HttpMessage msg, Source source,
			Set<HtmlParameter> params) {
		List<Element> metaElements = source.getAllElements(HTMLElementName.META);
		if (metaElements == null || metaElements.size() == 0) {
			return;
		}
		
		
		for (Element metaElement : metaElements) {
			String httpEquiv = metaElement.getAttributeValue("http-equiv");
			String bodyContentType = metaElement.getAttributeValue("content");
			
			// If META element defines HTTP-EQUIV and CONTENT attributes, 
			// compare charset values
			if (httpEquiv == null || bodyContentType == null || 
					!httpEquiv.equalsIgnoreCase("content-type")) {
				continue;				
			}
			
			String bodyContentCharset = getBodyContentCharset(bodyContentType);
	        for (HtmlParameter param: params) {        	        	
	            if (bodyContentCharset.equalsIgnoreCase(param.getValue())) {
	            	raiseAlert(msg, "META", "Content-Type", param, bodyContentCharset);
	            }                
	        }
		}
	}
	
	// TODO: taken from CharsetMismatchScanner. Extract into helper method
	private String getBodyContentCharset(String bodyContentType) {
		// preconditions
		assert bodyContentType != null;
		
		String charset = null;
		
		bodyContentType = bodyContentType.trim();
		
		int charsetIndex;
		if ((charsetIndex = bodyContentType.indexOf("charset=")) != -1) {
			// 8 is a length of "charset="
			charset = bodyContentType.substring(charsetIndex + 8);	 				
		}
		
		return charset;
	}	
	
	private void checkXmlEncodingCharset(HttpMessage msg, Source source,
			Set<HtmlParameter> params) {
		List<StartTag> xmlDeclarationTags = source.getAllStartTags(
				StartTagType.XML_DECLARATION);
		if (xmlDeclarationTags.size() == 0) {
			return;
		}
		
		StartTag xmlDeclarationTag = xmlDeclarationTags.get(0);
		String encoding = xmlDeclarationTag.getAttributeValue("encoding");
		
		if (encoding == null || encoding.equals("")) {
			return;
		}

        for (HtmlParameter param: params) {        	        	
            if (encoding.equalsIgnoreCase(param.getValue())) {
            	raiseAlert(msg, "\\?xml", "encoding", param, encoding);
            }                
        }
	}
	
	private void checkContentTypeCharset(HttpMessage msg, Set<HtmlParameter> params) {
    	String charset = msg.getResponseHeader().getCharset();
        if (charset == null || charset.equals("")) {
            return;
        }		
				
        for (HtmlParameter param: params) {        	        	
            if (charset.equalsIgnoreCase(param.getValue())) {
            	raiseAlert(msg, "Content-Type HTTP header", "charset", param, charset);
            }                
        }
	}
    
	// TODO: Fix up to support other variations of text/html.  
	// FIX: This will match Atom and RSS feeds now, which set text/html but 
	// use &lt;?xml&gt; in content
  	
    // TODO: these methods have been extracted from CharsetMismatchScanner
    // I think we should create helper methods for them
	private boolean isResponseHTML(HttpMessage message, Source source) {
		String contentType = message.getResponseHeader().getHeader(
				HttpHeader.CONTENT_TYPE);
		if (contentType == null) {
			return false;
		}
		
		return contentType.indexOf("text/html") != -1 || 
				contentType.indexOf("application/xhtml+xml") != -1 ||
				contentType.indexOf("application/xhtml") != -1;
	}
	
	private boolean isResponseXML(HttpMessage message, Source source) {
		return source.isXML();
	}    
	
	private void raiseAlert(HttpMessage msg, String tag, String attr, 
			HtmlParameter param, String charset) {
		Alert alert = new Alert(getId(), Alert.RISK_MEDIUM, Alert.WARNING,
				getName());				    

		alert.setDetail(getDescriptionMessage(), msg.getRequestHeader()
				.getURI().toString(), "content-type", getExploitMessage(msg), 
				getExtraInfoMessage(msg, tag, attr, param, charset),
				getSolutionMessage(), getReferenceMessage(), msg);  

		parent.raiseAlert(getId(), alert);
	}

	private int getId() {
		return 90011;
	}

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	/*
	 * Rule-associated messages
	 */

	private String getDescriptionMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	private String getSolutionMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	private String getReferenceMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	private String getExploitMessage(HttpMessage msg) {
        return Constant.messages.getString(MESSAGE_PREFIX + "exploit");
	}

	private String getExtraInfoMessage(HttpMessage msg, String tag, String attr,
			HtmlParameter param, String charset) {        
        return Constant.messages.getString(MESSAGE_PREFIX + "extraInfo", 
        		tag, attr, param.getName(), param.getValue(), charset);        
	}
}