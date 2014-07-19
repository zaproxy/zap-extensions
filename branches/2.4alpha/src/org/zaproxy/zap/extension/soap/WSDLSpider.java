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
	
	@Override
	public boolean parseResource(HttpMessage message, Source source, int depth) {
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
		parser.extContentWSDLImport(content);
		return true;
	}
	
	public boolean canParseResource(final HttpMessage message){
		// Get the context (base url)
		String baseURL = getURIfromMessage(message);
		if(baseURL.endsWith(".wsdl")) return true;
		log.info("Resource has not wsdl extension.");
		if(message.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE).equals("text/xml")){
			String content =  message.getResponseBody().toString();
			if(parser.canBeWSDLparsed(content)) return true;
			log.info("Content is not wsdl: "+content);
		}
		return false;
	}

	private String getURIfromMessage(final HttpMessage message){
		if (message == null) {
			return "";
		} else {
			return message.getRequestHeader().getURI().toString();
		}
	}
	
	private String getContentFromMessage(final HttpMessage message){
		if (message == null) {
			return "";
		} else {
			return message.getResponseBody().toString();
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
}
