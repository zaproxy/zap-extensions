//package org.zaproxy.zap.extension.soap;
//
//import net.htmlparser.jericho.Source;
//
//import org.apache.log4j.Logger;
//import org.parosproxy.paros.network.HttpMessage;
//import org.zaproxy.zap.spider.parser.SpiderParser;
//
//public class WSDLSpider extends SpiderParser{
//
//	ImportWSDL importer = ImportWSDL.getInstance();
//	
//	private static final Logger log = Logger.getLogger(WSDLSpider.class);
//	
//	@Override
//	public boolean parseResource(HttpMessage message, Source source, int depth) {
//		/* Only applied to wsdl files. */
//		if (!canParseResource(message)) return false;
//		if (importer == null){
//			importer = ImportWSDL.getInstance();
//			if (importer == null) return false;
//		}	
//		/* New WSDL detected. */
//		log.info("WSDL spider has detected a new resource");
//		String baseURL = getURIfromMessage(message);
//		ExtensionImportWSDL extension = importer.getExtensionInstance();
//		/* Calls extension to parse it and to fill the sites tree. */
//		extension.extUrlWSDLImport(baseURL,false);
//		return true;
//	}
//	
//	public boolean canParseResource(final HttpMessage message){
//		// Get the context (base url)
//		String baseURL = getURIfromMessage(message);
//		if(baseURL.endsWith(".wsdl")) return true;
//		else return false;
//	}
//
//	private String getURIfromMessage(final HttpMessage message){
//		if (message == null) {
//			return "";
//		} else {
//			return message.getRequestHeader().getURI().toString();
//		}
//	}
//
//	@Override
//	public boolean canParseResource(HttpMessage message, String path,
//			boolean wasAlreadyConsumed) {
//		// Get the context (base url)
//		String baseURL = getURIfromMessage(message);
//		if(baseURL.endsWith(".wsdl")) return true;
//		else return false;
//	}
//}
