package org.zaproxy.zap.extension.codedx;

import java.util.List;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.report.ReportGenerator;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class ExtensionAlertHttp extends ExtensionAlert {

    public ExtensionAlertHttp() {
    }

    @Override
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

        String requestHeader = alert.getMessage().getRequestHeader().toString();
        String requestBody = alert.getMessage().getRequestBody().toString();
        String responseHeader = alert.getMessage().getResponseHeader().toString();
        String responseBody = alert.getMessage().getResponseBody().toString();

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
        sb.append("  <uri>").append(ReportGenerator.entityEncode(uri).replaceAll("&amp;", "&amp;<wbr/>")).append("</uri>\r\n");
        sb.append("  <param>")
                .append(ReportGenerator.entityEncode(param).replaceAll("&amp;", "&amp;<wbr/>"))
                .append("</param>\r\n");
        sb.append("  <attack>")
                .append(ReportGenerator.entityEncode(attack).replaceAll("&amp;", "&amp;<wbr/>"))
                .append("</attack>\r\n");
        if (evidence != null && evidence.length() > 0) {
            sb.append("  <evidence>")
                    .append(ReportGenerator.entityEncode(evidence).replaceAll("&amp;", "&amp;<wbr/>"))
                    .append("</evidence>\r\n");
        }
        sb.append("  <otherinfo>")
                .append(ReportGenerator.entityEncode(otherInfo).replaceAll("&amp;", "&amp;<wbr/>"))
                .append("</otherinfo>\r\n");
        return sb.toString();
    }

}
