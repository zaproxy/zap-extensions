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
 */

package org.zaproxy.zap.extension.codedx;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;

public class ExtensionAlertHttp {
	
	private static final Logger LOGGER = LogManager.getLogger(ExtensionAlertHttp.class);

    public ExtensionAlertHttp() {
    }

    public String getXml(SiteNode site) {
        StringBuilder xml = new StringBuilder();
        xml.append("<alerts>");
        List<Alert> alerts = site.getAlerts();
        for (Alert alert : alerts) {
            if (alert.getConfidence() != Alert.CONFIDENCE_FALSE_POSITIVE) {
                String urlParamXML = getUrlParamXML(alert);
                xml.append(alert.toPluginXML(urlParamXML));
            }
        }
        xml.append("</alerts>");
        return xml.toString();
    }

    private String getHTML(Alert alert) {
        // gets HttpMessage request and response data from each alert and removes illegal and special characters
        StringBuilder httpMessage = new StringBuilder();
        
        HttpMessage message = alert.getMessage();
        
        if (message == null) {
        	LOGGER.warn(Constant.messages.getString("codedx.error.httpMessage", alert.getAlertId()));
        	return httpMessage.toString();
        }

        String requestHeader = message.getRequestHeader().toString();
        String requestBody = message.getRequestBody().toString();
        String responseHeader = message.getResponseHeader().toString();
        String responseBody = message.getResponseBody().toString();

        httpMessage.append("<requestdata>");
        httpMessage.append(ReportGenerator.entityEncode(requestHeader));
        httpMessage.append(ReportGenerator.entityEncode(requestBody));
        httpMessage.append("\n</requestdata>\n");
        httpMessage.append("<responsedata>");
        httpMessage.append(ReportGenerator.entityEncode(responseHeader));
        httpMessage.append(ReportGenerator.entityEncode(responseBody));
        httpMessage.append("\n</responsedata>\n");

        return httpMessage.toString();
    }

    public String getUrlParamXML(Alert alert) {

        String uri = alert.getUri();
        String param = alert.getParam();
        String attack = alert.getAttack();
        String otherInfo = alert.getOtherInfo();
        String evidence = alert.getEvidence();

        StringBuilder sb = new StringBuilder(200); // ZAP: Changed the type to StringBuilder.
        sb.append(getHTML(alert));
        sb.append("  <uri>").append(ReportGenerator.entityEncode(uri)).append("</uri>\r\n");
        sb.append("  <param>").append(ReportGenerator.entityEncode(param)).append("</param>\r\n");
        sb.append("  <attack>").append(ReportGenerator.entityEncode(attack)).append("</attack>\r\n");
        if (evidence != null && evidence.length() > 0) {
            sb.append("  <evidence>").append(ReportGenerator.entityEncode(evidence)).append("</evidence>\r\n");
        }
        sb.append("  <otherinfo>").append(ReportGenerator.entityEncode(otherInfo)).append("</otherinfo>\r\n");
        return sb.toString();
    }

}
