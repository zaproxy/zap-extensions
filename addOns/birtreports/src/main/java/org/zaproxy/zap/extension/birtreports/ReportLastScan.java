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
// ZAP: 2019/05/08 Normalise format/indentation.
package org.zaproxy.zap.extension.birtreports;

import java.awt.Desktop;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidParameterException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;
import javax.imageio.ImageIO;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileFilter;
import javax.xml.transform.stream.StreamSource;
import org.apache.log4j.Logger;
import org.eclipse.birt.core.exception.BirtException;
import org.eclipse.birt.core.framework.Platform;
import org.eclipse.birt.report.engine.api.EngineConfig;
import org.eclipse.birt.report.engine.api.EngineException;
import org.eclipse.birt.report.engine.api.IReportRunnable;
import org.eclipse.birt.report.engine.api.IRunAndRenderTask;
import org.eclipse.birt.report.engine.api.PDFRenderOption;
import org.eclipse.birt.report.engine.api.impl.ReportEngine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.RecordScan;
import org.parosproxy.paros.db.paros.ParosDatabase;
import org.parosproxy.paros.db.paros.ParosDatabaseServer;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.extension.report.ReportGenerator;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.XmlReporterExtension;
import org.zaproxy.zap.utils.XMLStringUtil;
import org.zaproxy.zap.view.ScanPanel;

public class ReportLastScan {

    private static final Path MAIN_BIRT_REPORTS_DIR =
            Paths.get(Constant.getZapHome(), "birtreports");
    static final Path REPORT_DESIGN_FILES_DIR = MAIN_BIRT_REPORTS_DIR.resolve("designfiles");

    private static final Path DEFAULT_REPORT_DESIGN =
            REPORT_DESIGN_FILES_DIR.resolve("default-report.rptdesign");
    private static final Path SCRIPTED_REPORT_DESIGN =
            REPORT_DESIGN_FILES_DIR.resolve("scripted-report.rptdesign");

    private static final Path LOGO_FILE_PATH = REPORT_DESIGN_FILES_DIR.resolve("logo.jpg");
    private static final Path XML_REPORT =
            REPORT_DESIGN_FILES_DIR.resolve("xmloutput/xmloutputzap.xml");

    private Logger logger = Logger.getLogger(ReportLastScan.class);
    private ResourceBundle messages = null;
    private StringBuilder sbXML;
    private int totalCount = 0;

    public ReportLastScan() {}

    private String getAlertXML(Database db, RecordScan recordScan) throws DatabaseException {

        Connection conn = null;
        PreparedStatement psAlert = null;
        StringBuilder sb = new StringBuilder();

        if (!(db instanceof ParosDatabase)) {
            throw new InvalidParameterException(db.getClass().getCanonicalName());
        }

        // prepare table connection
        try {
            /*
             * TODO Add-ons should NOT make their own connections to the db any more - the db layer is plugable
             * so could be implemented in a completely different way
             */
            conn = ((ParosDatabaseServer) db.getDatabaseServer()).getNewConnection();
            conn.setReadOnly(true);
            // ZAP: Changed to read all alerts and order by risk
            psAlert =
                    conn.prepareStatement(
                            "SELECT ALERT.ALERTID FROM ALERT ORDER BY RISK, PLUGINID");
            // psAlert = conn.prepareStatement("SELECT ALERT.ALERTID FROM ALERT JOIN SCAN ON
            // ALERT.SCANID = SCAN.SCANID WHERE SCAN.SCANID = ? ORDER BY PLUGINID");
            // psAlert.setInt(1, recordScan.getScanId());
            psAlert.executeQuery();
            ResultSet rs = psAlert.getResultSet();

            if (rs == null) return "";

            RecordAlert recordAlert = null;
            Alert alert = null;
            Alert lastAlert = null;

            StringBuilder sbURLs = new StringBuilder(100);
            String s = null;

            // get each alert from table
            while (rs.next()) {
                int alertId = rs.getInt(1);
                recordAlert = db.getTableAlert().read(alertId);
                alert = new Alert(recordAlert);

                // ZAP: Ignore false positives
                if (alert.getConfidence() == Alert.CONFIDENCE_FALSE_POSITIVE) {
                    continue;
                }

                if (lastAlert != null
                        && (alert.getPluginId() != lastAlert.getPluginId()
                                || alert.getRisk() != lastAlert.getRisk())) {
                    s = lastAlert.toPluginXML(sbURLs.toString());
                    sb.append(s);
                    sbURLs.setLength(0);
                }

                s = alert.getUrlParamXML();
                sbURLs.append(s);

                lastAlert = alert;
            }
            rs.close();

            if (lastAlert != null) {
                sb.append(lastAlert.toPluginXML(sbURLs.toString()));
            }

        } catch (SQLException e) {
            logger.error(e.getMessage(), e);
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    // Ignore
                }
            }
        }

        // exit
        return sb.toString();
    }

    public void uploadLogo(ViewDelegate view) {
        try {
            JFileChooser chooser =
                    new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
            chooser.setFileFilter(
                    new FileFilter() {

                        @Override
                        public boolean accept(File file) {
                            if (file.isDirectory()) {
                                return true;
                            } else if (file.isFile()
                                    && file.getName().toLowerCase().endsWith(".jpg")) {
                                return true;
                            }
                            return false;
                        }

                        @Override
                        public String getDescription() {
                            return ".jpg";
                        }
                    });

            File file = null;

            int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                file = chooser.getSelectedFile();
                if (file != null) {
                    Model.getSingleton()
                            .getOptionsParam()
                            .setUserDirectory(chooser.getCurrentDirectory());
                    BufferedImage image = null;
                    try {

                        image = ImageIO.read(file);
                        ImageIO.write(image, "jpg", LOGO_FILE_PATH.toFile());

                    } catch (IOException e) {
                        e.printStackTrace();
                        view.showWarningDialog("Error: Unable to upload the selected logo image.");
                    }
                }
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            view.showWarningDialog(
                    "There is some problem in choosen logo image. Please try again.");
        }
    }

    private File generate(String fileName, Model model) throws Exception {

        StringBuilder sb = new StringBuilder(500);
        // ZAP: Dont require scan to have been run

        sb.append("<?xml version=\"1.0\"?>");
        sb.append("<OWASPZAPReport version=\"")
                .append(Constant.PROGRAM_VERSION)
                .append("\" generated=\"")
                .append(ReportGenerator.getCurrentDateTimeString())
                .append("\">\r\n");
        // To call another function to filter xml records
        // sbXML = sb.append(getAlertXML(model.getDb(), null));
        sbXML = siteXML();
        sb.append(sbXML);
        sb.append("</OWASPZAPReport>");

        // Remove p HTML tags from the contents.
        String reportContents = sb.toString().replace("&lt;p&gt;", "").replace("&lt;/p&gt;", "\n");

        File report = ReportGenerator.stringToHtml(reportContents, (StreamSource) null, fileName);

        return report;
    }

    public int setCount(int count) {
        return totalCount = count;
    }

    private StringBuilder siteXML() {
        StringBuilder report = new StringBuilder();
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
                            + ">";
            StringBuilder extensionsXML = getExtensionsXML(site);
            String siteEnd = "</site>";
            report.append(siteStart);
            report.append(extensionsXML);
            report.append(siteEnd);
        }
        return report;
    }

    public StringBuilder getExtensionsXML(SiteNode site) {
        StringBuilder extensionXml = new StringBuilder();
        ExtensionLoader loader = Control.getSingleton().getExtensionLoader();
        int extensionCount = loader.getExtensionCount();
        for (int i = 0; i < extensionCount; i++) {
            Extension extension = loader.getExtension(i);
            if (extension instanceof XmlReporterExtension) {
                extensionXml.append(((XmlReporterExtension) extension).getXml(site));
                // Un-comment the below statement to add sorting and grouping of alerts feature
                // extensionXml.append(((XmlReporterExtension)extension).getXmlgroup(site,
                // totalCount));
            }
        }
        return extensionXml;
    }

    public void generateXml(ViewDelegate view, Model model) {

        // ZAP: Allow scan report file name to be specified
        try {
            JFileChooser chooser =
                    new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
            chooser.setFileFilter(
                    new FileFilter() {

                        @Override
                        public boolean accept(File file) {
                            if (file.isDirectory()) {
                                return true;
                            } else if (file.isFile()
                                    && file.getName().toLowerCase().endsWith(".xml")) {
                                return true;
                            }
                            return false;
                        }

                        @Override
                        public String getDescription() {
                            return Constant.messages.getString("file.format.xml");
                        }
                    });

            File file = null;
            int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                file = chooser.getSelectedFile();
                if (file != null) {
                    Model.getSingleton()
                            .getOptionsParam()
                            .setUserDirectory(chooser.getCurrentDirectory());
                    String fileNameLc = file.getAbsolutePath().toLowerCase();
                    if (!fileNameLc.endsWith(".xml")) {
                        file = new File(file.getAbsolutePath() + ".xml");
                    }
                }

                if (!file.getParentFile().canWrite()) {
                    view.showMessageDialog(
                            Constant.messages.getString(
                                    "report.write.error", new Object[] {file.getAbsolutePath()}));
                    return;
                }

                File report = generate(file.getAbsolutePath(), model);
                if (report == null) {
                    view.showMessageDialog(
                            Constant.messages.getString(
                                    "report.unknown.error", new Object[] {file.getAbsolutePath()}));
                    return;
                }

                try {
                    if (Desktop.isDesktopSupported()) {
                        Desktop.getDesktop().open(report);
                    }
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
            view.showWarningDialog(Constant.messages.getString("report.unexpected.warning"));
        }
    }

    public void generateXmlforBirtPdf(ViewDelegate view, Model model) {
        try {
            // generate xml file
            Files.createDirectories(XML_REPORT.getParent());
            File report = generate(XML_REPORT.toString(), model);
            if (report == null) {
                view.showMessageDialog(
                        Constant.messages.getString("report.unknown.error", XML_REPORT));
                return;
            }
            if (sbXML.length() == 0)
                view.showWarningDialog("You are about to generate an empty report.");

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            // view.showWarningDialog(Constant.messages.getString("report.unexpected.warning"));

        }
    }

    public void executeBirtScriptReport(ViewDelegate view, String title) {
        try {

            AlertReport report = new AlertReport();
            report.getAlertsReport();

            // user chooses where to save PDF report
            JFileChooser chooser =
                    new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
            chooser.setFileFilter(
                    new FileFilter() {

                        @Override
                        public boolean accept(File file) {
                            if (file.isDirectory()) {
                                return true;
                            } else if (file.isFile()
                                    && file.getName().toLowerCase().endsWith(".pdf")) {
                                return true;
                            }
                            return false;
                        }

                        @Override
                        public String getDescription() {
                            return Constant.messages.getString("birtreports.file.format.pdf");
                        }
                    });

            File file = null;
            int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                file = chooser.getSelectedFile();
            }
            if (file != null) {
                Model.getSingleton()
                        .getOptionsParam()
                        .setUserDirectory(chooser.getCurrentDirectory());
                String fileNameLc = file.getAbsolutePath().toLowerCase();
                // if a user forgets to specify .pdf at the end of the filename
                // then append it with the file name
                if (!fileNameLc.endsWith(".pdf")) {
                    file = new File(file.getAbsolutePath() + ".pdf");
                    fileNameLc = file.getAbsolutePath();
                } // select the file and close the Save dialog box

                // BIRT engine code
                EngineConfig config = new EngineConfig();
                config.setResourcePath(REPORT_DESIGN_FILES_DIR.toString());
                Platform.startup(config);

                ReportEngine engine = new ReportEngine(config);

                IReportRunnable reportRunnable =
                        engine.openReportDesign(SCRIPTED_REPORT_DESIGN.toString());
                IRunAndRenderTask runAndRender = engine.createRunAndRenderTask(reportRunnable);

                // Get Current Report Title
                System.out.println(
                        reportRunnable
                                .getDesignHandle()
                                .getProperty("title")); // or IReportRunnable.TITLE

                // Set New Report Title
                reportRunnable.getDesignHandle().setProperty("title", title);

                // Scripted source related code
                HashMap<String, List<Alert>> contextMap = new HashMap<String, List<Alert>>();
                // List<Alert> sortedList = report.sortAndGroupAlerts(this.totalCount);
                // Unsorted list - to make the code work with existing release
                List<Alert> sortedList = report.alerts;
                contextMap.put("Alerts", sortedList);
                runAndRender.setAppContext(contextMap);

                PDFRenderOption option = new PDFRenderOption();
                option.setOutputFileName(
                        fileNameLc); // takes old file name but now I did some modification

                option.setOutputFormat("PDF");
                runAndRender.setRenderOption(option);
                runAndRender.run();
                runAndRender.close();
                // open the PDF
                boolean isOpen = openPDF(new File(fileNameLc));
                if (!isOpen)
                    view.showWarningDialog(
                            "Error: Unable to open PDF from location: " + fileNameLc);
                // engine.destroy();
                // Platform.shutdown();

                // }
                //

            }
        } catch (EngineException e) {
            e.printStackTrace();
        } catch (BirtException e) {
            view.showWarningDialog("Error with BIRT API: " + e.toString());
            e.printStackTrace();
        }

        //

    }
    // end

    public void executeBirtPdfReport(ViewDelegate view, String title) {
        try {

            // user chooses where to save PDF report
            JFileChooser chooser =
                    new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
            chooser.setFileFilter(
                    new FileFilter() {

                        @Override
                        public boolean accept(File file) {
                            if (file.isDirectory()) {
                                return true;
                            } else if (file.isFile()
                                    && file.getName().toLowerCase().endsWith(".pdf")) {
                                return true;
                            }
                            return false;
                        }

                        @Override
                        public String getDescription() {
                            return Constant.messages.getString("birtreports.file.format.pdf");
                        }
                    });

            File file = null;
            int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                file = chooser.getSelectedFile();
            }
            if (file != null) {
                Model.getSingleton()
                        .getOptionsParam()
                        .setUserDirectory(chooser.getCurrentDirectory());
                String fileNameLc = file.getAbsolutePath().toLowerCase();
                // if a user forgets to specify .pdf at the end of the filename
                // then append it with the file name
                if (!fileNameLc.endsWith(".pdf")) {
                    file = new File(file.getAbsolutePath() + ".pdf");
                    fileNameLc = file.getAbsolutePath();
                } // select the file and close the Save dialog box

                // BIRT engine code
                EngineConfig config = new EngineConfig();
                config.setResourcePath(REPORT_DESIGN_FILES_DIR.toString());
                Platform.startup(config);

                ReportEngine engine = new ReportEngine(config);

                IReportRunnable reportRunnable =
                        engine.openReportDesign(DEFAULT_REPORT_DESIGN.toString());
                IRunAndRenderTask runAndRender = engine.createRunAndRenderTask(reportRunnable);

                // Get Current Report Title
                System.out.println(
                        reportRunnable
                                .getDesignHandle()
                                .getProperty("title")); // or IReportRunnable.TITLE

                // Set New Report Title
                reportRunnable.getDesignHandle().setProperty("title", title);
                // reportRunnable.getDesignHandle()

                PDFRenderOption option = new PDFRenderOption();
                option.setOutputFileName(
                        fileNameLc); // takes old file name but now I did some modification

                option.setOutputFormat("PDF");
                runAndRender.setRenderOption(option);
                runAndRender.run();
                runAndRender.close();
                // open the PDF
                boolean isOpen = openPDF(new File(fileNameLc));
                if (!isOpen)
                    view.showWarningDialog(
                            "Error: Unable to open PDF from location: " + fileNameLc);
                // engine.destroy();
                // Platform.shutdown();

                // }
                //

            }
        } catch (EngineException e) {
            e.printStackTrace();
        } catch (BirtException e) {
            view.showWarningDialog("Error with BIRT API: " + e.toString());
            e.printStackTrace();
        }

        //

    }
    // end
    public boolean openPDF(File file) {
        /*        try
        {
            if (OSDetector.isWindows())
            {
                Runtime.getRuntime().exec(new String[]
                {"rundll32 url.dll,FileProtocolHandler",
                 file.getAbsolutePath()});
                return true;
            } else if (OSDetector.isLinux() || OSDetector.isMac())
            {
                Runtime.getRuntime().exec(new String[]{"/usr/bin/open",
                                                       file.getAbsolutePath()});
                return true;
            } else
            {
                // Unknown OS, try with desktop
                if (Desktop.isDesktopSupported())
                {
                    Desktop.getDesktop().open(file);
                    return true;
                }
                else
                {
                    return false;
                }
            }
        } catch (Exception e)
        {
            e.printStackTrace(System.err);
            return false;
        }*/

        if (Desktop.isDesktopSupported()) {
            try {
                // File myFile = new File("/path/to/file.pdf");
                Desktop.getDesktop().open(file);
            } catch (IOException ex) {
                // no application registered for PDFs
                return false;
            }
        }
        return true;
    }

    public static class OSDetector {
        private static boolean isWindows = false;
        private static boolean isLinux = false;
        private static boolean isMac = false;

        static {
            String os = System.getProperty("os.name").toLowerCase();
            isWindows = os.contains("win");
            isLinux = os.contains("nux") || os.contains("nix");
            isMac = os.contains("mac");
        }

        public static boolean isWindows() {
            return isWindows;
        }

        public static boolean isLinux() {
            return isLinux;
        }

        public static boolean isMac() {
            return isMac;
        }
    }
}
