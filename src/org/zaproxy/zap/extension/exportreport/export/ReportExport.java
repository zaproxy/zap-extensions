/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
 * This file is based on the Paros code file ReportLastScan.java
 */
package org.zaproxy.zap.extension.exportreport.export;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.XML;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.Document;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.exportreport.filechooser.Utils;
import org.zaproxy.zap.extension.exportreport.model.AlertItem;
import org.zaproxy.zap.extension.exportreport.model.Alerts;
import org.zaproxy.zap.extension.exportreport.model.Report;
import org.zaproxy.zap.extension.exportreport.model.Sites;
import org.zaproxy.zap.utils.XMLStringUtil;

// Since it's a utility class it should be marked final and added a private no-arg constructor.
final class ReportExport {

    private ReportExport() {
    }

    private static final Logger logger = Logger.getLogger(ReportExport.class);

    private static String entityEncode(String text) throws UnsupportedEncodingException {
        String result = text;

        if (result == null) {
            return result;
        }
        // There is an encoding issue with the passed in String, this is a fix to maintain encoding and escapes!
        byte ptext[] = result.getBytes(StandardCharsets.ISO_8859_1);
        String value = new String(ptext, StandardCharsets.UTF_8.name());
        String temp = XMLStringUtil.escapeControlChrs(value);

        return temp;
    }

    public static String generateDUMP(String path, String fileName, String reportTitle, String reportBy, String reportFor, String scanDate, String scanVersion, String reportDate, String reportVersion, String reportDesc, ArrayList<String> alertSeverity, ArrayList<String> alertDetails) throws UnsupportedEncodingException, URIException {

        Report report = new Report();
        report.setTitle(entityEncode(reportTitle));
        report.setBy(entityEncode(reportBy));
        report.setFor(entityEncode(reportFor));
        report.setScanDate(entityEncode(scanDate));
        report.setScanVersion(entityEncode(scanVersion));
        report.setReportDate(entityEncode(reportDate));
        report.setReportVersion(entityEncode(reportVersion));
        report.setDesc(entityEncode(reportDesc));

        String description = Constant.messages.getString("exportreport.details.description.label");
        String solution = Constant.messages.getString("exportreport.details.solution.label");
        String otherinfo = Constant.messages.getString("exportreport.details.otherinfo.label");
        String reference = Constant.messages.getString("exportreport.details.reference.label");
        String cweid = Constant.messages.getString("exportreport.details.cweid.label");
        String wascid = Constant.messages.getString("exportreport.details.wascid.label");
        String requestheader = Constant.messages.getString("exportreport.details.requestheader.label");
        String responseheader = Constant.messages.getString("exportreport.details.responseheader.label");
        String requestbody = Constant.messages.getString("exportreport.details.requestbody.label");
        String responsebody = Constant.messages.getString("exportreport.details.responsebody.label");

        Map<Integer, String> mapRiskToTranslation = new HashMap<>();
        mapRiskToTranslation.put(Alert.RISK_HIGH, Constant.messages.getString("exportreport.risk.severity.high.label"));
        mapRiskToTranslation.put(Alert.RISK_MEDIUM, Constant.messages.getString("exportreport.risk.severity.medium.label"));
        mapRiskToTranslation.put(Alert.RISK_LOW, Constant.messages.getString("exportreport.risk.severity.low.label"));
        mapRiskToTranslation.put(Alert.RISK_INFO, Constant.messages.getString("exportreport.risk.severity.info.label"));

        List<Alert> alerts = Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class).getAllAlerts();

        List<String> host = new ArrayList<String>();
        List<Sites> sites = new ArrayList<Sites>();

        // int count = 0;
        for (int i = 0; i <= (alerts.size() - 1); i++) {
            Alert a = alerts.get(i);
            if (a.getHistoryRef() == null) {
                continue;
            } else {
                String tempHost = a.getHistoryRef().getURI().getHost();
                if (!host.contains(tempHost)) {
                    host.add(a.getHistoryRef().getURI().getHost());

                    Sites s = new Sites();
                    URI u = a.getHistoryRef().getURI();
                    int getPort = -1;
                    boolean isSSL = (u.getScheme().startsWith("https"));
                    getPort = isSSL ? ((u.getPort() == -1 && u.getScheme().equalsIgnoreCase("https")) ? 443 : u.getPort()) : ((u.getPort() == -1 && u.getScheme().equalsIgnoreCase("http")) ? 80 : u.getPort());

                    s.setHost(entityEncode(u.getHost()));
                    s.setName(entityEncode(u.getScheme() + "://" + u.getHost()));
                    s.setPort(String.valueOf(getPort));
                    s.setSSL(String.valueOf(isSSL));
                    sites.add(s);
                }
                // count = count + 1; // HERE FOR DEBUG
            }
        }

        for (Sites s : sites) {
            Alerts a = new Alerts();

            for (Alert alert : alerts) {
                if (alert.getHistoryRef() == null) {
                    continue;
                } else {
                    String tempHost = alert.getHistoryRef().getURI().getHost();
                    if (s.getHost().equalsIgnoreCase(tempHost)) {

                        String temp = "";
                        if (!alertSeverity.contains(mapRiskToTranslation.get(alert.getRisk()))) {
                            continue;
                        }

                        AlertItem item = new AlertItem();
                        item.setPluginID(entityEncode(Integer.toString(alert.getPluginId())));
                        item.setAlert(entityEncode(alert.getAlert()));
                        item.setRiskCode(entityEncode(Integer.toString(alert.getRisk())));
                        item.setRiskDesc(entityEncode(Alert.MSG_RISK[alert.getRisk()]));
                        item.setConfidence(entityEncode(Alert.MSG_CONFIDENCE[alert.getConfidence()]));

                        for (int j = 0; j < alertDetails.size(); j++) {
                            if (alertDetails.get(j).equalsIgnoreCase(description))
                                item.setDesc(entityEncode(alert.getDescription()));
                            if (alertDetails.get(j).equalsIgnoreCase(solution))
                                item.setSolution(entityEncode(alert.getSolution()));
                            if (alertDetails.get(j).equalsIgnoreCase(otherinfo) && alert.getOtherInfo() != null && alert.getOtherInfo().length() > 0) {
                                item.setOtherInfo(entityEncode(alert.getOtherInfo()));
                            }
                            if (alertDetails.get(j).equalsIgnoreCase(reference))
                                item.setReference(entityEncode(alert.getReference()));
                            if (alertDetails.get(j).equalsIgnoreCase(cweid) && alert.getCweId() > 0)
                                item.setCWEID(entityEncode(Integer.toString(alert.getCweId())));
                            if (alertDetails.get(j).equalsIgnoreCase(wascid))
                                item.setWASCID(entityEncode(Integer.toString(alert.getWascId())));

                            if (alertDetails.get(j).equalsIgnoreCase(requestheader) || alertDetails.get(j).equalsIgnoreCase(requestbody) || alertDetails.get(j).equalsIgnoreCase(responseheader) || alertDetails.get(j).equalsIgnoreCase(responsebody)) {

                                HttpMessage tempMsg = alert.getMessage();

                                temp = tempMsg.getRequestHeader().toString();
                                if (alertDetails.get(j).equalsIgnoreCase(requestheader) && temp != null && temp.length() > 0) {
                                    item.setRequestHeader(entityEncode(temp));
                                }

                                temp = tempMsg.getRequestBody().toString();
                                if (alertDetails.get(j).equalsIgnoreCase(requestbody) && temp != null && temp.length() > 0) {
                                    item.setRequestBody(entityEncode(temp));
                                }

                                temp = tempMsg.getResponseHeader().toString();
                                if (alertDetails.get(j).equalsIgnoreCase(responseheader) && temp != null && temp.length() > 0) {
                                    item.setResponseHeader(entityEncode(temp));
                                }

                                temp = tempMsg.getResponseBody().toString();
                                if (alertDetails.get(j).equalsIgnoreCase(responsebody) && temp != null && temp.length() > 0) {
                                    item.setResponseBody(entityEncode(temp));
                                }
                            }
                        }

                        // TODO v2.0: Create unique field for Method instead of combining with URI
                        //item.setURI(entityEncode(alert.getPluginId() + " : " + alert.getMethod() + ": " + alert.getUri()));
                        item.setURI(entityEncode(alert.getMethod() + " : " + alert.getUri()));
                        if (alert.getParam() != null && alert.getParam().length() > 0)
                            item.setParam(entityEncode(alert.getParam()));
                        if (alert.getAttack() != null && alert.getAttack().length() > 0)
                            item.setAttack(entityEncode(alert.getAttack()));
                        if (alert.getEvidence() != null && alert.getEvidence().length() > 0)
                            item.setEvidence(entityEncode(alert.getEvidence()));
                        a.add(item);
                    }
                }
            }
            s.setAlerts(a);
            report.add(s);
        }

        try {
            javax.xml.bind.JAXBContext jc = javax.xml.bind.JAXBContext.newInstance(Report.class);
            Marshaller jaxbMarshaller = jc.createMarshaller();
            jaxbMarshaller.setProperty(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT, true);
            jaxbMarshaller.setProperty(javax.xml.bind.Marshaller.JAXB_ENCODING, StandardCharsets.UTF_8.name());

            jaxbMarshaller.marshal(report, new File(path + fileName + Utils.DUMP));

            return path + fileName + Utils.DUMP;
        } catch (JAXBException e) {
            logger.error(e.getMessage(), e);
        }
        return "";
    }

    public static File transformation(ViewDelegate view, String p_result, String p_source, String p_xslt) {
        File f_result = new File(p_result);
        StreamResult result = new StreamResult(f_result);

        File f_source = new File(p_source);
        StreamSource source = new StreamSource(f_source);

        File f_xslt = new File(p_xslt);
        StreamSource xslt = new StreamSource(f_xslt);

        Transformer transformer = null;
        try {
            transformer = TransformerFactory.newInstance().newTransformer(xslt);
            transformer.transform(source, result);
        } catch (TransformerConfigurationException | TransformerFactoryConfigurationError e) {
            logger.error(e.getMessage(), e);
            if (view == null) {
                CommandLine.error(Constant.messages.getString("exportreport.message.error.transformer.config"));
            } else {
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.transformer.config"));
            }
        } catch (TransformerException e) {
            logger.error(e.getMessage(), e);
            if (view == null) {
                CommandLine.error(Constant.messages.getString("exportreport.message.error.transformer.general"));
            } else {
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.transformer.general"));
            }
        }
        return f_result;
    }

    public static File jsonExport(ViewDelegate view, String p_result, String p_source) {
        int PRETTY_PRINT_INDENT_FACTOR = 4;

        File fXmlFile = new File(p_source);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = null;
        try {
            dBuilder = dbFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            logger.error(e.getMessage(), e);
            if (view == null) {
                CommandLine.error(Constant.messages.getString("exportreport.message.error.parser"));
            } else {
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.parser"));
            }
            return null;
        }
        Document doc = null;
        try {
            doc = dBuilder.parse(fXmlFile);
        } catch (SAXException e) {
            logger.error(e.getMessage(), e);
            if (view == null) {
                CommandLine.error(Constant.messages.getString("exportreport.message.error.sax"));
            } else {
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.sax"));
            }
            return null;
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
            if (view == null) {
                CommandLine.error(Constant.messages.getString("exportreport.message.error.io"));
            } else {
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.io"));
            }
            return null;
        }
        String temp = getStringFromDoc(doc);
        String jsonPrettyPrintString = null;
        try {
            JSONObject xmlJSONObj = XML.toJSONObject(temp);
            jsonPrettyPrintString = xmlJSONObj.toString(PRETTY_PRINT_INDENT_FACTOR);
        } catch (JSONException e) {
            logger.error(e.getMessage(), e);
            if (view == null) {
                CommandLine.error(Constant.messages.getString("exportreport.message.error.json"));
            } else {
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.json"));
            }
            return null;
        }
        File f = null;
        try {
            f = write(p_result, jsonPrettyPrintString, false);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            if (view == null) {
                CommandLine.error(Constant.messages.getString("exportreport.message.error.exception"));
            } else {
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.exception"));
            }
        }
        return f;
    }

    public static String getStringFromDoc(Document doc) {
        DOMImplementationLS domImplementation = (DOMImplementationLS) doc.getImplementation();
        LSSerializer lsSerializer = domImplementation.createLSSerializer();
        return lsSerializer.writeToString(doc);
    }

    @SuppressWarnings("resource")
    private static File write(String path, String str, Boolean append) throws Exception {
        File f = new File(path);

        try (Writer writer = Channels.newWriter(new FileOutputStream(f.getAbsoluteFile(), append).getChannel(), StandardCharsets.UTF_8.name())) {
            writer.append(str);
        }
        return f;
    }
}