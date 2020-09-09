/*
 *
 * Paros and its related class files.
 *
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 *
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2011/10/01 Fixed filename problem (issue 161)
// ZAP: 2012/01/24 Changed outer XML (issue 268) c/o Alla
// ZAP: 2012/03/15 Changed the methods getAlertXML and generate to use the class
// StringBuilder instead of StringBuffer.
// ZAP: 2012/04/25 Added @Override annotation to all appropriate methods.
// ZAP: 2013/03/03 Issue 546: Remove all template Javadoc comments
// ZAP: 2013/07/12 Issue 713: Add CWE and WASC numbers to issues
// ZAP: 2013/12/03 Issue 933: Automatically determine install dir
// ZAP: 2014/07/15 Issue 1263: Generate Report Clobbers Existing Files Without Prompting
// ZAP: 2019/05/08 Normalise format/indentation.
package org.zaproxy.zap.extension.customreport;

import java.io.File;
import java.util.List;
import java.util.Locale;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileFilter;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.XmlReporterExtension;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.utils.XMLStringUtil;
import org.zaproxy.zap.view.ScanPanel;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

public class ReportLastScan {

    private Logger logger = Logger.getLogger(ReportLastScan.class);

    private static final String HTM_FILE_EXTENSION = ".htm";
    private static final String HTML_FILE_EXTENSION = ".html";

    public static final String[] MSG_RISK = {"Informational", "Low", "Medium", "High"};
    public static final String[] MSG_CONFIDENCE = {
        "False Positive", "Low", "Medium", "High", "Confirmed"
    };

    public enum ReportType {
        HTML,
        XML
    }

    public ReportLastScan() {}

    public StringBuilder generate(
            StringBuilder report,
            Model model,
            Boolean inScope,
            List<String> selectedAlerts,
            String reportName,
            String reportDescription,
            Boolean alertDescription,
            Boolean otherInfo,
            Boolean solution,
            Boolean reference,
            Boolean cweid,
            Boolean wascid,
            Boolean attack,
            Boolean param,
            Boolean evidence,
            Boolean requestHeader,
            Boolean responseHeader,
            Boolean requestBody,
            Boolean responseBody)
            throws Exception {
        report.append("<?xml version=\"1.0\"?>");
        report.append("<OWASPZAPReport version=\"")
                .append(Constant.PROGRAM_VERSION)
                .append("\" generated=\"")
                .append(ReportGenerator.getCurrentDateTimeString())
                .append("\">\r\n");
        report.append("<reportname>").append(reportName).append("</reportname>\r\n");
        report.append("<reportdesc>").append(reportDescription).append("</reportdesc>\r\n");
        siteXML(
                report,
                inScope,
                selectedAlerts,
                alertDescription,
                otherInfo,
                solution,
                reference,
                cweid,
                wascid,
                attack,
                param,
                evidence,
                requestHeader,
                responseHeader,
                requestBody,
                responseBody);
        report.append("</OWASPZAPReport>");

        return report;
    }

    private void siteXML(
            StringBuilder report,
            Boolean inScope,
            List<String> selectedAlerts,
            Boolean alertDescription,
            Boolean otherInfo,
            Boolean solution,
            Boolean reference,
            Boolean cweid,
            Boolean wascid,
            Boolean attack,
            Boolean param,
            Boolean evidence,
            Boolean requestHeader,
            Boolean responseHeader,
            Boolean requestBody,
            Boolean responseBody) {

        SiteMap siteMap = Model.getSingleton().getSession().getSiteTree();
        SiteNode root = siteMap.getRoot();
        int siteNumber = root.getChildCount();
        for (int i = 0; i < siteNumber; i++) {
            SiteNode site = (SiteNode) root.getChildAt(i);
            String siteName = ScanPanel.cleanSiteName(site, true);
            String[] hostAndPort = siteName.split(":");
            boolean isSSL = (site.getNodeName().startsWith("https"));
            String siteStart =
                    "<site name=\""
                            + XMLStringUtil.escapeControlChrs(site.getNodeName())
                            + "\""
                            + " host=\""
                            + XMLStringUtil.escapeControlChrs(hostAndPort[0])
                            + "\""
                            + " port=\""
                            + XMLStringUtil.escapeControlChrs(hostAndPort[1])
                            + "\""
                            + " ssl=\""
                            + String.valueOf(isSSL)
                            + "\""
                            + ">\r\n";
            StringBuilder extensionsXML = getExtensionsXML(site);
            String siteEnd = "</site>";
            report.append(siteStart);
            report.append(extensionsXML);

            report.append("<alerts>");
            List<Alert> alerts = site.getAlerts();

            for (Alert alert : alerts) {
                // Skip the alert if the report is inScope only and the alert isn't part of scope or
                // the alert isn't selected
                if (inScope && !alert.getHistoryRef().getSiteNode().isIncludedInScope()
                        || !selectedAlerts.contains(alert.getName())) {
                    continue;
                }

                report.append("<alertitem>\r\n");
                report.append("<pluginid>").append(alert.getPluginId()).append("</pluginid>\r\n");
                report.append("<alert>")
                        .append(replaceEntity(alert.getName()))
                        .append("</alert>\r\n");
                report.append("<riskcode>").append(alert.getRisk()).append("</riskcode>\r\n");
                report.append("<confidence>")
                        .append(alert.getConfidence())
                        .append("</confidence>\r\n");
                report.append("<riskdesc>")
                        .append(
                                replaceEntity(
                                        MSG_RISK[alert.getRisk()]
                                                + " ("
                                                + MSG_CONFIDENCE[alert.getConfidence()]
                                                + ")"))
                        .append("</riskdesc>\r\n");
                if (alertDescription) {
                    report.append("<desc>")
                            .append(replaceEntity(paragraph(alert.getDescription())))
                            .append("</desc>\r\n");
                }
                if (solution) {
                    report.append("<solution>")
                            .append(replaceEntity(paragraph(alert.getSolution())))
                            .append("</solution>\r\n");
                }
                if (alert.getOtherInfo() != null
                        && alert.getOtherInfo().length() > 0
                        && otherInfo) {
                    report.append("<otherinfo>")
                            .append(replaceEntity(alert.getOtherInfo()))
                            .append("</otherinfo>\r\n");
                }
                if (reference) {
                    report.append("<reference>")
                            .append(replaceEntity(paragraph(alert.getReference())))
                            .append("</reference>\r\n");
                }
                if (alert.getCweId() > 0 && cweid) {
                    report.append("<cweid>").append(alert.getCweId()).append("</cweid>\r\n");
                }
                if (alert.getWascId() > 0 && wascid) {
                    report.append("<wascid>").append(alert.getWascId()).append("</wascid>\r\n");
                }
                report.append("  <uri>").append(replaceEntity(alert.getUri())).append("</uri>\r\n");
                if (alert.getParam().length() > 0 && param) {
                    report.append("<param>")
                            .append(replaceEntity(alert.getParam()))
                            .append("</param>\r\n");
                }
                if (alert.getAttack() != null && alert.getAttack().length() > 0 && attack) {
                    report.append("<attack>")
                            .append(replaceEntity(alert.getAttack()))
                            .append("</attack>\r\n");
                }
                if (alert.getEvidence() != null && alert.getEvidence().length() > 0 && evidence) {
                    report.append("<evidence>")
                            .append(replaceEntity(alert.getEvidence()))
                            .append("</evidence>\r\n");
                }
                if (requestHeader) {
                    report.append("<requestheader>")
                            .append(
                                    paragraph(
                                            replaceEntity(
                                                    alert.getMessage()
                                                            .getRequestHeader()
                                                            .toString())))
                            .append("</requestheader>\r\n");
                }
                if (responseHeader) {
                    report.append("<responseheader>")
                            .append(
                                    paragraph(
                                            replaceEntity(
                                                    alert.getMessage()
                                                            .getResponseHeader()
                                                            .toString())))
                            .append("</responseheader>\r\n");
                }
                if (alert.getMessage().getRequestBody().length() > 0 && requestBody) {
                    report.append("<requestbody>")
                            .append(replaceEntity(alert.getMessage().getRequestBody().toString()))
                            .append("</requestbody>\r\n");
                }
                if (alert.getMessage().getResponseBody().length() > 0 && responseBody) {
                    report.append("<responsebody>")
                            .append(replaceEntity(alert.getMessage().getResponseBody().toString()))
                            .append("</responsebody>\r\n");
                }

                report.append("</alertitem>\r\n");
            }

            report.append("</alerts>\r\n");
            report.append(siteEnd);
        }
    }

    public String paragraph(String text) {
        return "<p>" + text.replaceAll("\\r\\n", "</p><p>").replaceAll("\\n", "</p><p>") + "</p>";
    }

    public String replaceEntity(String text) {
        String result = null;
        if (text != null) {
            result = ReportGenerator.entityEncode(text);
        }
        return result;
    }

    public StringBuilder getExtensionsXML(SiteNode site) {
        StringBuilder extensionXml = new StringBuilder();
        ExtensionLoader loader = Control.getSingleton().getExtensionLoader();
        int extensionCount = loader.getExtensionCount();
        for (int i = 0; i < extensionCount; i++) {
            Extension extension = loader.getExtension(i);
            if (extension instanceof XmlReporterExtension
                    && !extension.getName().equals("ExtensionAlert")) {
                String xml_temp = ((XmlReporterExtension) extension).getXml(site);
                extensionXml.append(xml_temp);
            }
        }
        return extensionXml;
    }

    /**
     * Generates a report. Defaults to HTML report if reportType is null.
     *
     * @param view
     * @param model
     * @param reportType
     */
    public void generateReport(ViewDelegate view, Model model, ExtensionCustomReport extension) {
        // ZAP: Allow scan report file name to be specified

        try {
            JFileChooser chooser =
                    new WritableFileChooser(
                            Model.getSingleton().getOptionsParam().getUserDirectory());

            chooser.setFileFilter(
                    new FileFilter() {

                        @Override
                        public boolean accept(File file) {
                            if (file.isDirectory()) {
                                return true;
                            } else if (file.isFile()) {
                                String lcFileName = file.getName().toLowerCase(Locale.ROOT);
                                return (lcFileName.endsWith(HTM_FILE_EXTENSION)
                                        || lcFileName.endsWith(HTML_FILE_EXTENSION));
                            }
                            return false;
                        }

                        @Override
                        public String getDescription() {
                            return Constant.messages.getString("file.format.html");
                        }
                    });

            // select file
            chooser.setSelectedFile(
                    new File(HTML_FILE_EXTENSION)); // Default the filename to a reasonable
            // extension;
            int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
            File file = null;
            if (rc == JFileChooser.APPROVE_OPTION) {
                file = chooser.getSelectedFile();

                // get report contents
                StringBuilder sb = new StringBuilder(500);
                sb =
                        this.generate(
                                sb,
                                model,
                                extension.onlyInScope(),
                                extension.getSelectedAlerts(),
                                extension.getReportName(),
                                extension.getReportDescription(),
                                extension.alertDescription(),
                                extension.otherInfo(),
                                extension.solution(),
                                extension.reference(),
                                extension.cweid(),
                                extension.wascid(),
                                extension.attack(),
                                extension.param(),
                                extension.evidence(),
                                extension.requestHeader(),
                                extension.responseHeader(),
                                extension.requestBody(),
                                extension.responseBody());

                // select template and generate html file
                File report = null;
                String reportXSL = "";
                String extensionPath = Constant.getZapHome() + "/xml/";

                switch (extension.getTemplate()) {
                    case "Concise":
                        String mergeXSL = (extensionPath + "mergeAlertitems.xml.xsl");
                        reportXSL = (extensionPath + "report.concise.html.xsl");
                        ReportGenerator.stringToHtml(
                                sb.toString(), mergeXSL, file.getAbsolutePath());
                        report =
                                ReportGenerator.fileToHtml(
                                        file.getAbsolutePath(), reportXSL, file.getAbsolutePath());
                        break;

                    case "Separated Sites":
                        reportXSL = (extensionPath + "report.separated.html.xsl");
                        report =
                                ReportGenerator.stringToHtml(
                                        sb.toString(), reportXSL, file.getAbsolutePath());
                        break;

                    case "Traditional":
                    default:
                        reportXSL = (extensionPath + "report.traditional.html.xsl");
                        report =
                                ReportGenerator.stringToHtml(
                                        sb.toString(), reportXSL, file.getAbsolutePath());
                }

                // others
                if (report == null) {
                    view.showMessageDialog(
                            Constant.messages.getString(
                                    "report.unknown.error", new Object[] {file.getAbsolutePath()}));
                    return;
                }

                try {
                    DesktopUtils.openUrlInBrowser(report.toURI());
                } catch (Exception e) {
                    logger.error(e.getMessage(), e);
                    view.showMessageDialog(
                            Constant.messages.getString(
                                    "report.complete.warning",
                                    new Object[] {report.getAbsolutePath()}));
                }
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            view.showWarningDialog(Constant.messages.getString("report.unexpected.error"));
        }
    }
}
