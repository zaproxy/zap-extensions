/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright The ZAP development team
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
package org.zaproxy.zap.extension.soap;

import groovy.xml.MarkupBuilder;

import java.awt.Event;
import java.awt.EventQueue;
import java.awt.event.KeyEvent;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;

import javax.swing.JFileChooser;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.codehaus.groovy.runtime.metaclass.MissingPropertyExceptionNoStack;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.spider.parser.SpiderParser;
import org.zaproxy.zap.view.ZapMenuItem;

import com.predic8.schema.ComplexType;
import com.predic8.schema.Element;
import com.predic8.schema.Schema;
import com.predic8.wsdl.AbstractBinding;
import com.predic8.wsdl.Binding;
import com.predic8.wsdl.BindingOperation;
import com.predic8.wsdl.Definitions;
import com.predic8.wsdl.Operation;
import com.predic8.wsdl.Part;
import com.predic8.wsdl.Port;
import com.predic8.wsdl.PortType;
import com.predic8.wsdl.Service;
import com.predic8.wsdl.WSDLParser;
import com.predic8.wstool.creator.RequestCreator;
import com.predic8.wstool.creator.SOARequestCreator;

public class ExtensionImportWSDL extends ExtensionAdaptor {

	public static final String NAME = "ExtensionImportWSDL";

	private static final String THREAD_PREFIX = "ZAP-Import-WSDL-";

    private ZapMenuItem menuImportLocalWSDL = null;
    private ZapMenuItem menuImportUrlWSDL = null;
    private int threadId = 1;

	private static final Logger log = Logger.getLogger(ExtensionImportWSDL.class);
	private ImportWSDL wsdlImporter= null;
	private static int keyIndex = -1;
	
	public ExtensionImportWSDL() {
		super();
		initialize();
	}

	/**
	 * @param name
	 */
	public ExtensionImportWSDL(String name) {
		super(name);
		initialize();
	}

	/**
	 * This method initializes this
	 */
	private void initialize() {
		this.setName(NAME);
		this.setOrder(157);
		wsdlImporter = ImportWSDL.getInstance();
		wsdlImporter.setExtensionInstance(this);
	}

	@Override
	public void hook(ExtensionHook extensionHook) {
		super.hook(extensionHook);

	    if (getView() != null) {
	        extensionHook.getHookMenu().addToolsMenuItem(getMenuImportLocalWSDL());
	        extensionHook.getHookMenu().addToolsMenuItem(getMenuImportUrlWSDL());
	        
			/* Custom spider is added in order to explore not only WSDL files, but also their WSDL endpoints. */
			ExtensionSpider spider = (ExtensionSpider) Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.NAME);
			SpiderParser customSpider = new WSDLSpider();
			if (spider != null){
				spider.addCustomParser(customSpider);
				log.info("Added custom WSDL spider.");
			}else{
				log.info("Custom WSDL spider could not be added.");
			}
	    }
	}

	@Override
	public void unload() {
		super.unload();
		Control control = Control.getSingleton();
		ExtensionLoader extLoader = control.getExtensionLoader();
	    if (getView() != null) {
	    	extLoader.removeToolsMenuItem(getMenuImportLocalWSDL());
	    	extLoader.removeToolsMenuItem(getMenuImportUrlWSDL());
	    }
	}

	/* Menu option to import a local WSDL file. */
	private ZapMenuItem getMenuImportLocalWSDL() {
        if (menuImportLocalWSDL == null) {
        	menuImportLocalWSDL = new ZapMenuItem("soap.topmenu.tools.importWSDL",
        			KeyStroke.getKeyStroke(KeyEvent.VK_I, Event.CTRL_MASK, false));
        	menuImportLocalWSDL.setToolTipText(Constant.messages.getString("soap.topmenu.tools.importWSDL.tooltip"));

        	menuImportLocalWSDL.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                	// Prompt for a WSDL file.
            		final JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
            		FileNameExtensionFilter filter = new FileNameExtensionFilter("WSDL File", "wsdl", "wsdl");
            		chooser.setFileFilter(filter);
            	    int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
            	    if(rc == JFileChooser.APPROVE_OPTION) {
            	    	
            	    	Thread t = new Thread(){
							@Override
							public void run() {
								this.setName(THREAD_PREFIX + threadId++);
		        	    		parseWSDLFile(chooser.getSelectedFile());
							}
            	    		
            	    	};
            	    	t.start();
            	    }

                }
            });
        }
        return menuImportLocalWSDL;
    }
	
	/* Menu option to import a WSDL file from a given URL. */
	private ZapMenuItem getMenuImportUrlWSDL() {
        if (menuImportUrlWSDL == null) {
        	menuImportUrlWSDL = new ZapMenuItem("soap.topmenu.tools.importRemoteWSDL",
        			KeyStroke.getKeyStroke(KeyEvent.VK_J, Event.CTRL_MASK, false));
        	menuImportUrlWSDL.setToolTipText(Constant.messages.getString("soap.topmenu.tools.importRemoteWSDL.tooltip"));

        	final ExtensionImportWSDL shadowCopy = this;
        	menuImportUrlWSDL.addActionListener(new java.awt.event.ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                	SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            new ImportFromUrlDialog(View.getSingleton().getMainFrame(), shadowCopy);
                        }
                    });
                }
            });
        }
        return menuImportUrlWSDL;
    }
	
	/* Method called from import dialog when import button is pressed. */
	public void extUrlWSDLImport(final String url, boolean threaded){
		if (url == null || url.trim().length() <= 0 ) return;
		//log.debug("Importing WSDL file from URL: "+url);
		if(threaded){
			Thread t = new Thread(){
				@Override
				public void run() {
					this.setName(THREAD_PREFIX + threadId++);
		    		parseWSDLUrl(url);
				}
	    		
	    	};
	    	t.start();
		}else{
			parseWSDLUrl(url);
		}
			
	}
	
	/* Generates WSDL definitions from a WSDL file and then it calls parsing functions. */
	private void parseWSDLFile(File file) {
		if (file == null) return ;
		try {
			if (View.isInitialised()) {
				// Switch to the output panel, if in GUI mode
				View.getSingleton().getOutputPanel().setTabFocus();
			}
			
			// WSDL file parsing.
	        WSDLParser parser = new WSDLParser();
			final String path = file.getAbsolutePath();
	        Definitions wsdl = parser.parse(path);
			parseWSDL(wsdl);
	        
		} catch (Exception e) {
			log.error(e.getMessage(), e);
		} 
	}
	
	/* Generates WSDL definitions from a WSDL string and then it calls parsing functions. */
	private void parseWSDLUrl(String url){
		if (url == null || url.trim().equals("")) return;
		try {
			if (View.isInitialised()) {
				// Switch to the output panel, if in GUI mode
				View.getSingleton().getOutputPanel().setTabFocus();
			}
			/* Sends a request to retrieve remote WSDL file's content. */
			HttpMessage httpRequest = new HttpMessage(new URI(url, false));
	        HttpSender sender = new HttpSender(
					Model.getSingleton().getOptionsParam().getConnectionParam(),
					true,
					HttpSender.MANUAL_REQUEST_INITIATOR);
	        try {
				sender.sendAndReceive(httpRequest, true);
			} catch (IOException e) {
				log.error("Unable to send WSDL request.", e);
				return;
			}
	        
	        /* Checks response content. */
	        if (httpRequest.getResponseBody() != null){      	
		        String content = httpRequest.getResponseBody().toString();	
		        if (content == null || content.trim().length() <= 0){
		        	//log.warn("URL response from WSDL file request has no body content.");
		        }else{
		        	// WSDL parsing.
			        WSDLParser parser = new WSDLParser();
			        InputStream contentI = new ByteArrayInputStream(content.getBytes("UTF-8"));
			        Definitions wsdl = parser.parse(contentI);
			        contentI.close();
					parseWSDL(wsdl);
		        }  
	        }
		} catch (Exception e) {
			log.error("There was an error while parsing WSDL from URL. ", e);
		} 
	}


	/* Parses WSDL definitions and identifies endpoints and operations. */
	private void parseWSDL(Definitions wsdl){
        StringBuilder sb = new StringBuilder();
        List<Service> services = wsdl.getServices();
        keyIndex++;
        
        /* Endpoint identification. */
        for(Service service : services){
        	for(Port port: service.getPorts()){
		        Binding binding = port.getBinding();
		        AbstractBinding innerBinding = binding.getBinding();
		        String soapPrefix = innerBinding.getPrefix();
		        int soapVersion = detectSoapVersion(wsdl, soapPrefix); // SOAP 1.X, where X is represented by this variable.			        
		        /* If the binding is not a SOAP binding, it is ignored. */
		        String style = detectStyle(innerBinding);
		        if(style != null && (style.equals("document") || style.equals("rpc")) ){
		        	
			        List<BindingOperation> operations = binding.getOperations();
			        String endpointLocation = port.getAddress().getLocation().toString();
				    sb.append("\n|-- Port detected: "+port.getName()+" ("+endpointLocation+")\n");
				    
		    	    /* Identifies operations for each endpoint.. */
	    	        for(BindingOperation bindOp : operations){
	    	        	sb.append("|\t|-- SOAP 1."+soapVersion+" Operation: "+bindOp.getName());
	    	        	/* Adds this operation to the global operations chart. */
	    	        	recordOperation(keyIndex, bindOp);	    	        	
	    	        	/* Identifies operation's parameters. */
	    	        	List<Part> requestParts = detectParameters(wsdl, bindOp);    	        			    	        	    	        	   	        			    	        	
	    	        	/* Set values to parameters. */
	    	        	HashMap<String, String> formParams = new HashMap<String, String>();
	    	        	fillParameters(requestParts, formParams);		    	        	        	
	    	        	/* Connection test for each operation. */
	    	        	/* Basic message creation. */
	    	        	HttpMessage requestMessage = createSoapRequest(wsdl, soapVersion, formParams, port, bindOp);
	    	        	sendSoapRequest(keyIndex, requestMessage, sb);	
	    	        } //bindingOperations loop
		        } //Binding check if
        	}// Ports loop
        }        
        printOutput(sb);
	}
	
	private static void persistMessage(final HttpMessage message) {
		// Add the message to the history panel and sites tree
		final HistoryReference historyRef;

		try {
			historyRef = new HistoryReference(Model.getSingleton().getSession(), HistoryReference.TYPE_ZAP_USER, message);			
		} catch (Exception e) {
			log.warn(e.getMessage(), e);
			return;
		}

		final ExtensionHistory extHistory = (ExtensionHistory) Control.getSingleton()
				.getExtensionLoader().getExtension(ExtensionHistory.NAME);
		if (extHistory != null) {
			EventQueue.invokeLater(new Runnable() {
				@Override
				public void run() {
					extHistory.addHistory(historyRef);
					Model.getSingleton().getSession().getSiteTree().addPath(historyRef, message);	
				}
			});
		}
	}
	
	/* Detects SOAP version used in a binding, given the wsdl content and the soap binding prefix. */
	private int detectSoapVersion(Definitions wsdl, String soapPrefix){
        String soapNamespace = wsdl.getNamespace(soapPrefix).toString();
        if(soapNamespace.trim().equals("http://schemas.xmlsoap.org/wsdl/soap12/")){
        	return 2;
        }else{
        	return 1;
        }
	}
	
	private String detectStyle(AbstractBinding binding){
        try{
        	String r = binding.getProperty("style").toString();
        	binding.getProperty("transport");
        	return r.trim();
        }catch (MissingPropertyExceptionNoStack e){
        	// It has no style or transport property, so it is not a SOAP binding.
        	log.info("No style or transport property detected", e);
        	return null;
        }
	}
	
	/* Record the given operation in the global chart. */
	private void recordOperation(int wsdlID, BindingOperation bindOp){
    	String soapActionName = "";
    	try{
    		soapActionName = bindOp.getOperation().getSoapAction();    	        			
    	}catch(NullPointerException e){
    		// SOAP Action not defined for this operation.
    		log.info("No SOAP Action defined for this operation.", e);
    		return;
    	}
    	if(!soapActionName.trim().equals("")){
    		wsdlImporter.putAction(wsdlID,soapActionName);
    	}	
	}
	
	private List<Part> detectParameters(Definitions wsdl, BindingOperation bindOp){
		for(PortType pt : wsdl.getPortTypes()){
    		for(Operation op : pt.getOperations()){
    			if (op.getName().trim().equals(bindOp.getName().trim())){
    				return op.getInput().getMessage().getParts();
    			}
    		}
    	}
		return null;
	}
	
	private void fillParameters(List<Part> requestParts, HashMap<String, String> formParams){
    	for(Part part : requestParts){
    		if (part.getName().equals("parameters")){
    			final String elementName = part.getElement().getName();
        		ComplexType ct = (ComplexType) part.getElement().getEmbeddedType();
        		/* Handles when ComplexType is not embedded but referenced by 'type'. */
        		if (ct == null){
        			Element element = part.getElement();
        			Schema currentSchema = element.getSchema();
        			ct = (ComplexType) currentSchema.getType(element.getType());
        		}			    	        			
        		for (Element e : ct.getSequence().getElements()) {
        			final String paramName = e.getName().trim();
        			final String paramType = e.getType().getQualifiedName().trim();
        			/* Parameter value depends on parameter type. */
        			if(paramType.trim().equals("xsd:string")){
	        			formParams.put("xpath:/"+elementName.trim()+"/"+paramName, "paramValue");
	        			//log.info("[ExtensionImportWSDL] Param: "+"xpath:/"+elementName.trim()+"/"+paramName);
	        		}    
        		}
    		}
    	}
	}

	/* Generates a SOAP request associated to the specified binding operation. */
	private HttpMessage createSoapRequest(Definitions wsdl, int soapVersion, HashMap<String, String> formParams, 
			Port port, BindingOperation bindOp){
		
    	StringWriter writerSOAPReq = new StringWriter();
    	
    	SOARequestCreator creator = new SOARequestCreator(wsdl, new RequestCreator(), new MarkupBuilder(writerSOAPReq));
        creator.setBuilder(new MarkupBuilder(writerSOAPReq));
        creator.setDefinitions(wsdl);
        creator.setFormParams(formParams);
        creator.setCreator(new RequestCreator());
    	
    	try{
    		Binding binding = port.getBinding();
	        creator.createRequest(binding.getPortType().getName(),
	               bindOp.getName(), binding.getName());
	            	        	
	        //log.info("[ExtensionImportWSDL] "+writerSOAPReq);
	        /* HTTP Request. */
	        String endpointLocation = port.getAddress().getLocation().toString();
	        HttpMessage httpRequest = new HttpMessage(new URI(endpointLocation, false));
	        /* Body. */
	        HttpRequestBody httpReqBody = httpRequest.getRequestBody();
	        /* [MARK] Not sure if all servers would handle this encoding type. */
	        httpReqBody.append("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\r\n"+ writerSOAPReq.getBuffer().toString());
	        httpRequest.setRequestBody(httpReqBody);
	        /* Header. */    		       
	        HttpRequestHeader httpReqHeader = httpRequest.getRequestHeader();
	        httpReqHeader.setMethod("POST");
	        if(soapVersion == 1){
		        httpReqHeader.setHeader(HttpHeader.CONTENT_TYPE, "text/xml; charset=UTF-8");
		        httpReqHeader.setHeader("SOAPAction", bindOp.getOperation().getSoapAction());
	        }else if (soapVersion == 2){
	        	String contentType = "application/soap+xml; charset=UTF-8";
	        	String action = bindOp.getOperation().getSoapAction();
	        	if(!action.trim().equals(""))
	        		contentType += "; action="+action;
	        	httpReqHeader.setHeader(HttpHeader.CONTENT_TYPE, contentType);
	        }
	        httpReqHeader.setContentLength(httpReqBody.length());
	        httpRequest.setRequestHeader(httpReqHeader);
	        return httpRequest;
    	}catch (Exception e){
    		log.error("Unable to generate request for operation '"+bindOp.getName()+"'\n"+ e.getMessage(), e);
    		return null;
    	}
	}
	
	/* Sends a given SOAP request. File is needed to record its associated ops, and stringBuilder logs
	 * the output message.
	 */
	private void sendSoapRequest(int wsdlID, HttpMessage httpRequest, StringBuilder sb){
		if (httpRequest == null) return;
        /* Connection. */
        HttpSender sender = new HttpSender(
				Model.getSingleton().getOptionsParam().getConnectionParam(),
				true,
				HttpSender.MANUAL_REQUEST_INITIATOR);
        try {
			sender.sendAndReceive(httpRequest, true);
		} catch (IOException e) {
			log.error("Unable to communicate with SOAP server. Server may be not available.");
			log.debug("Trace:", e);
		}
		wsdlImporter.putRequest(wsdlID, httpRequest);
		persistMessage(httpRequest);
		if (sb != null) sb.append(" (Status code: "+ httpRequest.getResponseHeader().getStatusCode() +")\n");
	}
	
	/* Prints output string in output panel. */
	private void printOutput(StringBuilder sb){
        if (View.isInitialised()) {
			final String str = sb.toString();
			EventQueue.invokeLater(new Runnable() {
				@Override
				public void run() {
					View.getSingleton().getOutputPanel().append(str);
				}}
			);
		}	
	}
	
	@Override
	public boolean canUnload() {
		return true;
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("soap.desc");
	}

	@Override
	public URL getURL() {
		try {
			return new URL(Constant.ZAP_HOMEPAGE);
		} catch (MalformedURLException e) {
			return null;
		}
	}
	
}
