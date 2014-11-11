package org.zaproxy.zap.extension.soap;

import net.htmlparser.jericho.Source;

import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.spider.parser.SpiderParser;

public class WSDLSpider extends SpiderParser{

	private ImportWSDL importer = ImportWSDL.getInstance();
	private WSDLCustomParser parser = new WSDLCustomParser();
	
	private static final Logger log = Logger.getLogger(WSDLSpider.class);
	
	private static boolean isEnabled = false;
	
	@Override
	public boolean parseResource(HttpMessage message, Source source, int depth) {
		return parseResourceWSDL(message, source, depth, true);
	}
	
	public boolean parseResourceWSDL(HttpMessage message, Source source, int depth, boolean sendRequests) {
		if (!isEnabled) return false;
		if (message == null) return false;
		/* Only applied to wsdl files. */
		log.info("WSDL custom spider called.");
		if (!canParseResource(message)) return false;
		if (importer == null){
			importer = ImportWSDL.getInstance();
			if (importer == null) return false;
		}	
		/* New WSDL detected. */
		log.info("WSDL spider has detected a new resource");
		String content = getContentFromMessage(message);	
		/* Calls extension to parse it and to fill the sites tree. */
		parser.extContentWSDLImport(content, sendRequests);
		return true;
	}
	
	public boolean canParseResource(final HttpMessage message){
		try{
			// Get the context (base url)
			String baseURL = getURIfromMessage(message);
			String contentType = message.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
			if(baseURL.endsWith(".wsdl") || contentType.equals("text/xml") || contentType.equals("application/wsdl+xml")){
				String content =  message.getResponseBody().toString();
				if(parser.canBeWSDLparsed(content)) return true;
				log.info("Content is not wsdl: "+content);
			}
		}catch(Exception e){
			return false;
		}
		return false;
	}

	private String getURIfromMessage(final HttpMessage message){
		if (message == null) {
			return "";
		} else {
			try{
				return message.getRequestHeader().getURI().toString();
			}catch(Exception e){
				return "";
			}
		}
	}
	
	private String getContentFromMessage(final HttpMessage message){
		if (message == null) {
			return "";
		} else {
			return message.getResponseBody().toString().trim();
		}
	}

	@Override
	public boolean canParseResource(HttpMessage message, String path,
			boolean wasAlreadyConsumed) {
		// Get the context (base url)
		String baseURL = getURIfromMessage(message);
		if(baseURL.endsWith(".wsdl")) return true;
		else return false;
	}
	
	public static void enable(){
		isEnabled = true;
	}
	
	public static void disable(){
		isEnabled = false;
	}
}
