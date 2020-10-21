/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.soap;

import com.predic8.schema.ComplexType;
import com.predic8.schema.Element;
import com.predic8.schema.Schema;
import com.predic8.schema.SimpleType;
import com.predic8.schema.restriction.BaseRestriction;
import com.predic8.schema.restriction.facet.EnumerationFacet;
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
import com.predic8.xml.util.ResourceDownloadException;
import groovy.xml.MarkupBuilder;
import java.awt.EventQueue;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.codehaus.groovy.runtime.metaclass.MissingPropertyExceptionNoStack;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.network.HttpRequestBody;

public class WSDLCustomParser {

    private static final Logger LOG = Logger.getLogger(WSDLCustomParser.class);
    private static int keyIndex = -1;
    private ImportWSDL wsdlSingleton = ImportWSDL.getInstance();
    private SOAPMsgConfig lastConfig; // Only used for unit testing purposes.

    public WSDLCustomParser() {}

    /* Method called from external classes to import a WSDL file from an URL. */
    public void extUrlWSDLImport(final String url, final String threadName) {
        if (url == null || url.trim().length() <= 0) return;
        // LOG.debug("Importing WSDL file from URL: "+url);
        Thread t =
                new Thread() {
                    @Override
                    public void run() {
                        // Thread name: THREAD_PREFIX + threadId++
                        this.setName(threadName);
                        parseWSDLUrl(url);
                    }
                };
        t.start();
    }

    /*
     * Method called from external classes to import a WSDL file specifying content.
     */
    public boolean extContentWSDLImport(final String content) {
        return parseWSDLContent(content);
    }

    public boolean extContentWSDLImport(final String content, final boolean sendMessages) {
        return parseWSDLContent(content, sendMessages);
    }

    /* Method called from external classes to import a WSDL file from an URL. */
    public void extUrlWSDLImport(final String url) {
        parseWSDLUrl(url);
    }

    /*
     * Method called from external classes to import a WSDL file from a local file.
     */
    public void extFileWSDLImport(final File file, final String threadName) {
        Thread t =
                new Thread() {
                    @Override
                    public void run() {
                        this.setName(threadName);
                        parseWSDLFile(file);
                    }
                };
        t.start();
    }

    public boolean canBeWSDLparsed(String content) {
        if (content == null || content.trim().length() <= 0) {
            return false;
        } else {
            // WSDL parsing.
            WSDLParser parser = new WSDLParser();
            try {
                InputStream contentI = new ByteArrayInputStream(content.getBytes("UTF-8"));
                parser.parse(contentI);
                contentI.close();
                return true;
            } catch (Exception e) {
                return false;
            }
        }
    }

    /*
     * Generates WSDL definitions from a WSDL file and then it calls parsing
     * functions.
     */
    private void parseWSDLFile(File file) {
        if (file == null) return;
        try {
            if (View.isInitialised()) {
                // Switch to the output panel, if in GUI mode
                View.getSingleton().getOutputPanel().setTabFocus();
            }

            // WSDL file parsing.
            WSDLParser parser = new WSDLParser();
            final String path = file.getAbsolutePath();
            Definitions wsdl = parser.parse(path);
            parseWSDL(wsdl, true);

        } catch (ResourceDownloadException rde) {
            String exMsg =
                    Constant.messages.getString(
                            "soap.topmenu.tools.importWSDL.fail", file.getAbsolutePath());
            LOG.warn(exMsg);
            if (View.isInitialised()) {
                View.getSingleton().showWarningDialog(exMsg);
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    /*
     * Generates WSDL definitions from a WSDL string and then it calls parsing
     * functions.
     */
    private void parseWSDLUrl(String url) {
        if (url == null || url.trim().equals("")) return;
        try {
            if (View.isInitialised()) {
                // Switch to the output panel, if in GUI mode
                try {
                    View.getSingleton().getOutputPanel().setTabFocus();
                } catch (Exception e) {
                    LOG.debug("Could not set tab focus on Output Panel.");
                }
            }
            /* Sends a request to retrieve remote WSDL file's content. */
            HttpMessage httpRequest = new HttpMessage(new URI(url, false));
            HttpSender sender =
                    new HttpSender(
                            Model.getSingleton().getOptionsParam().getConnectionParam(),
                            true,
                            HttpSender.MANUAL_REQUEST_INITIATOR);
            try {
                sender.sendAndReceive(httpRequest, true);
            } catch (IOException e) {
                LOG.error("Unable to send WSDL request.", e);
                return;
            }

            String content = httpRequest.getResponseBody().toString();
            if (content.trim().isEmpty()) {
                LOG.debug("Response from WSDL file request has no body content, url: " + url);
            } else {
                parseWSDLContent(content);
            }
        } catch (Exception e) {
            LOG.error("There was an error while parsing WSDL from URL. ", e);
        }
    }

    private boolean parseWSDLContent(String content, boolean sendMessages) {
        if (content == null || content.trim().length() <= 0) {
            return false;
        } else {
            // WSDL parsing.
            WSDLParser parser = new WSDLParser();
            try {
                InputStream contentI = new ByteArrayInputStream(content.getBytes("UTF-8"));
                Definitions wsdl = parser.parse(contentI);
                contentI.close();
                parseWSDL(wsdl, sendMessages);
                return true;
            } catch (Exception e) {
                LOG.error("There was an error while parsing WSDL content. ", e);
                return false;
            }
        }
    }

    private boolean parseWSDLContent(String content) {
        return parseWSDLContent(content, true);
    }

    /* Parses WSDL definitions and identifies endpoints and operations. */
    private void parseWSDL(Definitions wsdl, boolean sendMessages) {
        StringBuilder sb = new StringBuilder();
        List<Service> services = wsdl.getServices();
        keyIndex++;

        /* Endpoint identification. */
        for (Service service : services) {
            for (Port port : service.getPorts()) {
                Binding binding = port.getBinding();
                AbstractBinding innerBinding = binding.getBinding();
                String soapPrefix = innerBinding.getPrefix();
                int soapVersion =
                        detectSoapVersion(
                                wsdl, soapPrefix); // SOAP 1.X, where X is represented by this
                // variable.
                /* If the binding is not a SOAP binding, it is ignored. */
                String style = detectStyle(innerBinding);
                if (style != null && (style.equals("document") || style.equals("rpc"))) {

                    List<BindingOperation> operations = binding.getOperations();
                    String endpointLocation = port.getAddress().getLocation().toString();
                    sb.append(
                            "\n|-- Port detected: "
                                    + port.getName()
                                    + " ("
                                    + endpointLocation
                                    + ")\n");

                    /* Identifies operations for each endpoint.. */
                    for (BindingOperation bindOp : operations) {
                        sb.append(
                                "|\t|-- SOAP 1." + soapVersion + " Operation: " + bindOp.getName());
                        /* Adds this operation to the global operations chart. */
                        recordOperation(keyIndex, bindOp);
                        /* Identifies operation's parameters. */
                        List<Part> requestParts = detectParameters(wsdl, bindOp);
                        /* Set values to parameters. */
                        HashMap<String, String> formParams = new HashMap<String, String>();
                        for (Part part : requestParts) {
                            Element element = part.getElement();
                            if (element != null) {
                                formParams.putAll(fillParameters(element, null));
                            }
                        }
                        /* Connection test for each operation. */
                        /* Basic message creation. */
                        SOAPMsgConfig soapConfig =
                                new SOAPMsgConfig(wsdl, soapVersion, formParams, port, bindOp);
                        lastConfig = soapConfig;
                        HttpMessage requestMessage = createSoapRequest(soapConfig);
                        if (sendMessages) sendSoapRequest(keyIndex, requestMessage, sb);
                    } // bindingOperations loop
                } // Binding check if
            } // Ports loop
        }
        printOutput(sb);
    }

    /*
     * Detects SOAP version used in a binding, given the wsdl content and the soap
     * binding prefix.
     */
    private int detectSoapVersion(Definitions wsdl, String soapPrefix) {
        String soapNamespace = wsdl.getNamespace(soapPrefix).toString();
        if (soapNamespace.trim().equals("http://schemas.xmlsoap.org/wsdl/soap12/")) {
            return 2;
        } else {
            return 1;
        }
    }

    private String detectStyle(AbstractBinding binding) {
        try {
            String r = binding.getProperty("style").toString();
            binding.getProperty("transport");
            return r.trim();
        } catch (MissingPropertyExceptionNoStack e) {
            // It has no style or transport property, so it is not a SOAP binding.
            LOG.info("No style or transport property detected", e);
            return null;
        }
    }

    /* Record the given operation in the global chart. */
    private void recordOperation(int wsdlID, BindingOperation bindOp) {
        String soapActionName = "";
        try {
            soapActionName = bindOp.getOperation().getSoapAction();
        } catch (NullPointerException e) {
            // SOAP Action not defined for this operation.
            LOG.info("No SOAP Action defined for this operation.", e);
            return;
        }
        if (!soapActionName.trim().equals("")) {
            wsdlSingleton.putAction(wsdlID, soapActionName);
        }
    }

    private List<Part> detectParameters(Definitions wsdl, BindingOperation bindOp) {
        for (PortType pt : wsdl.getPortTypes()) {
            for (Operation op : pt.getOperations()) {
                if (op.getName().trim().equals(bindOp.getName().trim())) {
                    return op.getInput().getMessage().getParts();
                }
            }
        }
        return null;
    }

    private HashMap<String, String> fillParameters(Element element, String parent) {
        HashMap<String, String> formParams = new HashMap<String, String>();
        try {
            /* Tries to parse it as a complex type first. */
            String xpath = null;
            if (parent != null) xpath = parent + "/" + element.getName();
            else xpath = element.getName();
            ComplexType ct = (ComplexType) element.getEmbeddedType();
            /* Handles when ComplexType is not embedded but referenced by 'type'. */
            if (ct == null) {
                Schema currentSchema = element.getSchema();
                ct = (ComplexType) currentSchema.getType(element.getType());
                if (ct == null)
                    throw new ClassCastException(
                            "Complex Type is null after cast."); // Hashmap is empty here.
            }
            for (Element e : ct.getSequence().getElements()) {
                /* Recursive parsing for nested complex types. */
                formParams.putAll(fillParameters(e, xpath));
            }
        } catch (ClassCastException cce) {
            /* Simple element treatment. */
            if (element == null) return formParams;
            /* Handles simple types. */
            SimpleType simpleType = null;
            try {
                simpleType = (SimpleType) element.getEmbeddedType();
                if (simpleType == null) {
                    Schema currentSchema = element.getSchema();
                    simpleType = (SimpleType) currentSchema.getType(element.getType());
                    if (simpleType == null) {
                        /* It is not simple type, so it is treated as a plain element. */
                        String xpath = "";
                        if (parent != null) xpath = parent + "/" + element.getName();
                        else xpath = element.getName();
                        if (element.getType() != null)
                            return addParameter(xpath, element.getType().getQualifiedName(), null);
                        else return formParams;
                    }
                }
            } catch (ClassCastException cce2) {
                /* It is not simple type, so it is treated as a plain element. */
                String xpath = "";
                if (parent != null) xpath = parent + "/" + element.getName();
                else xpath = element.getName();
                return addParameter(xpath, element.getType().getQualifiedName(), null);
            }
            /* Handles enumeration restriction. */
            BaseRestriction br = simpleType.getRestriction();
            if (br != null) {
                List<EnumerationFacet> enums = br.getEnumerationFacets();
                if (enums != null && enums.size() > 0) {
                    String defaultValue = enums.get(0).getValue();
                    formParams.putAll(
                            addParameter(parent + "/" + element.getName(), "string", defaultValue));
                }
            }
            return formParams;
        } catch (Exception e) {
            LOG.warn(
                    "There was an error when trying to parse element "
                            + element.getName()
                            + " from WSDL file.",
                    e);
        }
        return formParams;
    }

    private HashMap<String, String> addParameter(String path, String paramType, String value) {
        HashMap<String, String> formParams = new HashMap<String, String>();
        LOG.debug("Detected parameter: " + path);
        if (paramType.contains(":")) {
            String[] stringParts = paramType.split(":");
            paramType = stringParts[stringParts.length - 1];
        }
        /* If value is specified, it is directly set. */
        if (value != null) {
            formParams.put("xpath:/" + path, value);
            return formParams;
        }
        /* Parameter value depends on parameter type. */
        if (paramType.equals("string")) {
            formParams.put("xpath:/" + path, "paramValue");
        } else if (paramType.equals("int")
                || paramType.equals("double")
                || paramType.equals("long")) {
            formParams.put("xpath:/" + path, "0");
        } else if (paramType.equals("date")) {
            Date date = new Date();
            SimpleDateFormat dt1 = new SimpleDateFormat("CCYY-MM-DD");
            String dateS = dt1.format(date);
            formParams.put("xpath:/" + path, dateS);
        } else if (paramType.equals("dateTime")) {
            Date date = new Date();
            SimpleDateFormat dt1 = new SimpleDateFormat("CCYY-MM-DDThh:mm:ssZ");
            String dateS = dt1.format(date);
            formParams.put("xpath:/" + path, dateS);
        }
        return formParams;
    }

    /* Generates a SOAP request associated to the specified binding operation. */
    public HttpMessage createSoapRequest(SOAPMsgConfig soapConfig) {
        if (soapConfig == null || !soapConfig.isComplete()) return null;

        /* Retrieving configuration variables. */
        Definitions wsdl = soapConfig.getWsdl();
        HashMap<String, String> formParams = soapConfig.getParams();
        Port port = soapConfig.getPort();
        int soapVersion = soapConfig.getSoapVersion();
        BindingOperation bindOp = soapConfig.getBindOp();

        /* Start message crafting. */
        StringWriter writerSOAPReq = new StringWriter();

        SOARequestCreator creator =
                new SOARequestCreator(wsdl, new RequestCreator(), new MarkupBuilder(writerSOAPReq));
        creator.setBuilder(new MarkupBuilder(writerSOAPReq));
        creator.setDefinitions(wsdl);
        creator.setFormParams(formParams);
        creator.setCreator(new RequestCreator());

        try {
            Binding binding = port.getBinding();
            creator.createRequest(
                    binding.getPortType().getName(), bindOp.getName(), binding.getName());

            // LOG.info("[ExtensionImportWSDL] "+writerSOAPReq);
            /* HTTP Request. */
            String endpointLocation = port.getAddress().getLocation().toString();
            HttpMessage httpRequest = new HttpMessage(new URI(endpointLocation, false));
            /* Body. */
            HttpRequestBody httpReqBody = httpRequest.getRequestBody();
            /* [MARK] Not sure if all servers would handle this encoding type. */
            httpReqBody.append(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\r\n"
                            + writerSOAPReq.getBuffer().toString());
            httpRequest.setRequestBody(httpReqBody);
            /* Header. */
            HttpRequestHeader httpReqHeader = httpRequest.getRequestHeader();
            httpReqHeader.setMethod("POST");
            /* Sets headers according to SOAP version. */
            if (soapVersion == 1) {
                httpReqHeader.setHeader(HttpHeader.CONTENT_TYPE, "text/xml; charset=UTF-8");
                httpReqHeader.setHeader("SOAPAction", bindOp.getOperation().getSoapAction());
            } else if (soapVersion == 2) {
                String contentType = "application/soap+xml; charset=UTF-8";
                String action = bindOp.getOperation().getSoapAction();
                if (!action.trim().equals("")) contentType += "; action=" + action;
                httpReqHeader.setHeader(HttpHeader.CONTENT_TYPE, contentType);
            }
            httpReqHeader.setContentLength(httpReqBody.length());
            httpRequest.setRequestHeader(httpReqHeader);
            /* Saves the message and its configuration. */
            wsdlSingleton.putConfiguration(httpRequest, soapConfig);
            return httpRequest;
        } catch (Exception e) {
            LOG.error(
                    "Unable to generate request for operation '"
                            + bindOp.getName()
                            + "'\n"
                            + e.getMessage(),
                    e);
            return null;
        }
    }

    /*
     * Sends a given SOAP request. File is needed to record its associated ops, and
     * stringBuilder logs the output message.
     */
    private void sendSoapRequest(int wsdlID, HttpMessage httpRequest, StringBuilder sb) {
        if (httpRequest == null) return;
        HttpRequestBody body = httpRequest.getRequestBody();
        /* Avoids connection if message has no proper body. */
        if (body == null || body.getBytes().length <= 0) return;
        /* Connection. */
        HttpSender sender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        HttpSender.MANUAL_REQUEST_INITIATOR);
        /* Send request. */
        try {
            sender.sendAndReceive(httpRequest, true);
        } catch (IOException e) {
            LOG.error("Unable to communicate with SOAP server. Server may be not available.");
            LOG.debug("Trace:", e);
        }
        wsdlSingleton.putRequest(wsdlID, httpRequest);
        persistMessage(httpRequest);
        if (sb != null)
            sb.append(" (Status code: " + httpRequest.getResponseHeader().getStatusCode() + ")\n");
    }

    private static void persistMessage(final HttpMessage message) {
        // Add the message to the history panel and sites tree
        final HistoryReference historyRef;

        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_ZAP_USER,
                            message);
        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
            return;
        }

        final ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        if (extHistory != null) {
            EventQueue.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            extHistory.addHistory(historyRef);
                            Model.getSingleton()
                                    .getSession()
                                    .getSiteTree()
                                    .addPath(historyRef, message);
                        }
                    });
        }
    }

    /* Prints output string in output panel. */
    private void printOutput(StringBuilder sb) {
        if (View.isInitialised()) {
            final String str = sb.toString();
            EventQueue.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            View.getSingleton().getOutputPanel().append(str);
                        }
                    });
        }
    }

    SOAPMsgConfig getLastConfig() {
        return lastConfig;
    }
}
