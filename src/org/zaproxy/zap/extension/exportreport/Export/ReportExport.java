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
package org.zaproxy.zap.extension.exportreport.Export;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.channels.Channels;
import java.util.ArrayList;
import java.util.List;

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

import org.apache.log4j.Logger;

import org.json.*;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.exportreport.FileChooser.Utils;

import org.zaproxy.zap.extension.exportreport.model.AlertItem;
import org.zaproxy.zap.extension.exportreport.model.Alerts;
import org.zaproxy.zap.extension.exportreport.model.Report;
import org.zaproxy.zap.extension.exportreport.model.Sites;
import org.zaproxy.zap.utils.XMLStringUtil;
import org.zaproxy.zap.view.ScanPanel;

import org.w3c.dom.Document;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 */

public class ReportExport {
	
	private static Logger logger = Logger.getLogger(ExportReport.class);
	
	private static String entityEncode(String text) throws UnsupportedEncodingException {
		String result = text;

		if (result == null) {
			return result;
		}
		// There is an encoding issue with the passed in String, this is a fix to maintain encoding and escapes!
		byte ptext[] = result.getBytes("ISO-8859-1"); 
		String value = new String(ptext, Utils.utf8); 
		String temp = XMLStringUtil.escapeControlChrs(value);

		return temp;
	}

	public static String generateDUMP(String path, String fileName, String reportTitle, String reportBy, String reportFor,
			String scanDate, String scanVersion, String reportDate, String reportVersion, String reportDesc,
			ArrayList<String> alertSeverity, ArrayList<String> alertDetails) throws UnsupportedEncodingException {

		SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
		SiteNode root = (SiteNode) siteMap.getRoot();
		int siteNumber = root.getChildCount();

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

		try {
			for (int i = 0; i < siteNumber; i++) {
				SiteNode site = (SiteNode) root.getChildAt(i);
				String siteName = ScanPanel.cleanSiteName(site, true);
				String[] hostAndPort = siteName.split(":");
				boolean isSSL = (site.getNodeName().startsWith("https"));

				Sites s = new Sites();
				s.setHost(entityEncode(hostAndPort[0]));
				s.setName(entityEncode(site.getNodeName()));
				s.setPort(entityEncode(hostAndPort[1]));
				s.setSSL(String.valueOf(isSSL));

				List<Alert> alerts = site.getAlerts();
				Alerts a = new Alerts();
				String temp = "";
				for (Alert alert : alerts) {
					
					if(!alertSeverity.contains(Alert.MSG_RISK[alert.getRisk()])) {
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
						if (alertDetails.get(j).equalsIgnoreCase(otherinfo) && alert.getOtherInfo() != null
								&& alert.getOtherInfo().length() > 0) {
							item.setOtherInfo(entityEncode(alert.getOtherInfo()));
						}
						if (alertDetails.get(j).equalsIgnoreCase(reference))
							item.setReference(entityEncode(alert.getReference()));
						if (alertDetails.get(j).equalsIgnoreCase(cweid) && alert.getCweId() > 0)
							item.setCWEID(entityEncode(Integer.toString(alert.getCweId())));
						if (alertDetails.get(j).equalsIgnoreCase(wascid))
							item.setWASCID(entityEncode(Integer.toString(alert.getWascId())));

						temp = alert.getMessage().getRequestHeader().toString();
						if (alertDetails.get(j).equalsIgnoreCase(requestheader) && temp != null	&& temp.length() > 0) {
							item.setRequestHeader(entityEncode(temp));
						}
						
						temp = alert.getMessage().getRequestBody().toString();
						if (alertDetails.get(j).equalsIgnoreCase(requestbody) && temp != null	&& temp.length() > 0) {
							item.setRequestBody(entityEncode(temp));
						}

						temp = alert.getMessage().getResponseHeader().toString();
						if (alertDetails.get(j).equalsIgnoreCase(responseheader) && temp != null	&& temp.length() > 0) {
							item.setResponseHeader(entityEncode(temp));
						}

						temp = alert.getMessage().getResponseBody().toString();
						if (alertDetails.get(j).equalsIgnoreCase(responsebody) && temp != null	&& temp.length() > 0) {
							item.setResponseBody(entityEncode(temp));
						}
					}
					
					item.setURI(entityEncode(alert.getUri()));
					if (alert.getParam() != null && alert.getParam().length() > 0)
						item.setParam(entityEncode(alert.getParam()));
					if (alert.getAttack() != null && alert.getAttack().length() > 0)
						item.setAttack(entityEncode(alert.getAttack()));
					if (alert.getEvidence() != null && alert.getEvidence().length() > 0)
						item.setEvidence(entityEncode(alert.getEvidence()));

					a.add(item);
				}
				s.setAlerts(a);
				report.add(s);
			}
			javax.xml.bind.JAXBContext jc = javax.xml.bind.JAXBContext.newInstance(Report.class);
			Marshaller jaxbMarshaller = jc.createMarshaller();
			jaxbMarshaller.setProperty(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT, true);
			jaxbMarshaller.setProperty(javax.xml.bind.Marshaller.JAXB_ENCODING, Utils.utf8); // used to be utf-8, might not be able to change to upper case.

			jaxbMarshaller.marshal(report, new File(path + fileName + Utils.dump));

			return path + fileName + Utils.dump;
		} catch (JAXBException e) {
			logger.error(e.getMessage(), e);
		}
		return "";
	}

	public static File TRANSFORMATION(ViewDelegate view, Logger logger, String absolutePath, String p_result, String p_source, String p_xslt) 
	{
		File f_result = new File(p_result);
		StreamResult result = new StreamResult(f_result);

		File f_source = new File(p_source);
		StreamSource source = new StreamSource(f_source);

		File f_xslt = new File(p_xslt);
		StreamSource xslt = new StreamSource(f_xslt);

		Transformer transformer = null;
		try
		{
			transformer = TransformerFactory.newInstance().newTransformer(xslt);
			transformer.transform(source, result);
		}
		catch (TransformerConfigurationException | TransformerFactoryConfigurationError e)
		{
			logger.error(e.getMessage(), e);
			view.showMessageDialog(Constant.messages.getString("exportreport.message.error.transformer.config"));
		}
		catch (TransformerException e)
		{
			logger.error(e.getMessage(), e);
			view.showMessageDialog(Constant.messages.getString("exportreport.message.error.transformer.general"));
		}
		return f_result;
	}
	
	public static File JSON_EXPORT(ViewDelegate view, Logger logger, String absolutePath, String p_result, String p_source) 
	{
		int PRETTY_PRINT_INDENT_FACTOR = 4;
		
		File fXmlFile = new File(p_source);
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = null;
		try
		{
			dBuilder = dbFactory.newDocumentBuilder();
		}
		catch (ParserConfigurationException e)
		{
			logger.error(e.getMessage(), e);
			view.showMessageDialog(Constant.messages.getString("exportreport.message.error.parser"));
		}
		Document doc = null;
		try
		{
			doc = dBuilder.parse(fXmlFile);
		}
		catch (SAXException e)
		{
			logger.error(e.getMessage(), e);
			view.showMessageDialog(Constant.messages.getString("exportreport.message.error.sax"));
		}
		catch (IOException e)
		{
			logger.error(e.getMessage(), e);
			view.showMessageDialog(Constant.messages.getString("exportreport.message.error.io"));
		}
		String temp = getStringFromDoc(doc);
		String jsonPrettyPrintString = null;
		try
		{
			JSONObject xmlJSONObj = XML.toJSONObject(temp);
			jsonPrettyPrintString = xmlJSONObj.toString(PRETTY_PRINT_INDENT_FACTOR);
		}
		catch (JSONException e)
		{
			logger.error(e.getMessage(), e);
			view.showMessageDialog(Constant.messages.getString("exportreport.message.error.json"));
		}
		File f = null;
		try
		{
			f = write(p_result, jsonPrettyPrintString, false);
		}
		catch (Exception e)
		{
			logger.error(e.getMessage(), e);
			view.showMessageDialog(Constant.messages.getString("exportreport.message.error.exception"));
		}
		return f;
	}
	
	public static String getStringFromDoc(Document doc)
	{
		DOMImplementationLS domImplementation = (DOMImplementationLS) doc.getImplementation();
		LSSerializer lsSerializer = domImplementation.createLSSerializer();
		return lsSerializer.writeToString(doc);
	}

	private static File write(String path, String str, Boolean append) throws Exception
	{
		File f = new File(path);

		try (Writer writer = Channels.newWriter(new FileOutputStream(f.getAbsoluteFile(), append).getChannel(), Utils.utf8))
		{
			writer.append(str);
		}
		return f;
	}
}