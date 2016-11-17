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

import java.awt.Toolkit;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Locale;

import javax.swing.SwingWorker;

import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.exportreport.ExtensionExportReport;
import org.zaproxy.zap.extension.exportreport.filechooser.FileList;
import org.zaproxy.zap.extension.exportreport.filechooser.ReportFileView;
import org.zaproxy.zap.extension.exportreport.filechooser.ReportFilter;
import org.zaproxy.zap.extension.exportreport.filechooser.Utils;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

/*
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 */

public class ExportReport {
    private static final Logger logger = Logger.getLogger(ExportReport.class);

    private Task task; // Create a task and dump the export into the background, essential for large exports.
    private static WritableFileChooser fc; // Global because the property change listener won't be able to access if it's local scope.

    private static class Task extends SwingWorker<Void, Void> {
        private ViewDelegate view;
        private ExtensionExportReport extension;
        private String fileExtension;
        private File f;

        public Task(ViewDelegate view, ExtensionExportReport extension, String fileExtension, File f) {
            this.view = view;
            this.extension = extension;
            this.fileExtension = fileExtension;
            this.f = f;
        }

        @Override
        public Void doInBackground() {
            String file = f.getName();
            String absolutePath = f.getAbsolutePath();
            String fileName = file.substring(0, file.lastIndexOf(fileExtension) - 1);
            String path = absolutePath.substring(0, absolutePath.lastIndexOf(file));

            String xmlPath = "";
            try {
                xmlPath = ReportExport.generateDUMP(path, fileName, extension.extensionGetTitle(), extension.extensionGetBy(), extension.extensionGetFor(), extension.extensionGetScanDate(), extension.extensionGetScanVer(), extension.extensionGetReportDate(), extension.extensionGetReportVer(), extension.extensionGetDescription(), extension.getIncludedAlertSeverity(), extension.getIncludedAlertDetails());
            } catch (UnsupportedEncodingException e) {
                logger.error(e.getMessage(), e);
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.dump"));
                return null;
            } catch (URIException e) {
                logger.error(e.getMessage(), e);
                // Update error message for dump
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.dump"));
                return null;
            }

            String extensionPath = Constant.getZapHome() + "xml" + File.separator;
            String mergeXSL = extensionPath + "merge.xml.xsl";
            String reportXSL = extensionPath + "report.html.xsl";

            File f_view = null; // Needs to be initialized for check below;
            boolean show = false;
            String xmlGenerated = path + fileName + ".xml";

            try {
                switch (fileExtension.toLowerCase(Locale.ROOT)) {
                case Utils.HTML:
                    f_view = ReportExport.transformation(view, xmlGenerated, xmlPath, mergeXSL);
                    // f_view = null;
                    f_view = ReportExport.transformation(view, absolutePath, xmlGenerated, reportXSL);
                    deleteFile(xmlGenerated);// , "The merged XML file: ");
                    show = true;
                    break;
                case Utils.BOOTSTRAP:
                    view.showMessageDialog(Constant.messages.getString("exportreport.message.notice.bootstrap"));
                    break;
                case Utils.XML:
                    f_view = ReportExport.transformation(view, xmlGenerated, xmlPath, mergeXSL);
                    show = true;
                    break;
                case Utils.JSON:
                    view.showMessageDialog(Constant.messages.getString("exportreport.message.notice.json"));
                    f_view = ReportExport.transformation(view, xmlGenerated, xmlPath, mergeXSL);
                    // f_view = null;
                    f_view = ReportExport.jsonExport(view, absolutePath, xmlGenerated);
                    deleteFile(xmlGenerated);// , "The merged XML file: ");
                    break;
                case Utils.PDF:
                    view.showMessageDialog(Constant.messages.getString("exportreport.message.notice.pdf"));
                    // f_view = null;
                    break;
                case Utils.DOC:
                    view.showMessageDialog(Constant.messages.getString("exportreport.message.notice.doc"));
                    // f_view = null;
                    break;
                default:
                    break;
                }
            } finally {
                deleteFile(xmlPath);
            }

            try {
                if ((f_view != null) && show) {
                    DesktopUtils.openUrlInBrowser(f_view.toURI());
                }
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
                view.showWarningDialog(Constant.messages.getString("exportreport.message.error.file.open"));
            }
            return null;
        }

        /**
         * Executed in event dispatching thread
         */
        @Override
        public void done() {
            Toolkit.getDefaultToolkit().beep();
        }
    }

    public boolean generateReport(ExtensionExportReport extension, String absolutePath, String ext, ArrayList<String> sourceDetailsList, ArrayList<String> alertSeverityList, ArrayList<String> alertDetailsList) {

        File f = new File(absolutePath);
        String file = f.getName();
        String fileExtension = ext;
        String fileName = file.substring(0, file.lastIndexOf(fileExtension) - 1);
        String path = absolutePath.substring(0, absolutePath.lastIndexOf(file));

        String extensionGetTitle = sourceDetailsList.get(0);
        String extensionGetBy = sourceDetailsList.get(1);
        String extensionGetFor = sourceDetailsList.get(2);
        String extensionGetScanDate = sourceDetailsList.get(3);
        String extensionGetReportDate = sourceDetailsList.get(4);
        String extensionGetScanVer = sourceDetailsList.get(5);
        String extensionGetReportVer = sourceDetailsList.get(6);
        String getDescription = sourceDetailsList.get(7);

        String xmlPath = "";
        try {
            xmlPath = ReportExport.generateDUMP(path, fileName, extensionGetTitle, extensionGetBy, extensionGetFor, extensionGetScanDate, extensionGetScanVer, extensionGetReportDate, extensionGetReportVer, getDescription, alertSeverityList, alertDetailsList);
        } catch (UnsupportedEncodingException e) {
            logger.error(e.getMessage(), e);
            CommandLine.error(Constant.messages.getString("exportreport.message.error.dump"));
            return false;
        } catch (URIException e) {
            logger.error(e.getMessage(), e);
            // Update error message for dump
            CommandLine.error(Constant.messages.getString("exportreport.message.error.dump"));
            return false;
        }

        String extensionPath = Constant.getZapHome() + "xml" + File.separator;
        String mergeXSL = extensionPath + "merge.xml.xsl";
        String reportXSL = extensionPath + "report.html.xsl";

        File f_view = null; // Needs to be initialized for check below;
        boolean show = false;
        String xmlGenerated = path + fileName + ".xml" + ".temp";

        try {
            switch (fileExtension.toLowerCase(Locale.ROOT)) {
            case Utils.HTML:
                f_view = ReportExport.transformation(null, xmlGenerated, xmlPath, mergeXSL);
                f_view = ReportExport.transformation(null, absolutePath, xmlGenerated, reportXSL);
                deleteFile(xmlGenerated);
                show = true;
                break;
            case Utils.BOOTSTRAP:
                CommandLine.error(Constant.messages.getString("exportreport.message.notice.bootstrap"));
                return false;
            case Utils.XML:
                xmlGenerated = path + fileName+ ".xml";
                f_view = ReportExport.transformation(null, xmlGenerated, xmlPath, mergeXSL);
                show = true;
                break;
            case Utils.JSON:
                CommandLine.info(Constant.messages.getString("exportreport.message.notice.json"));
                f_view = ReportExport.transformation(null, xmlGenerated, xmlPath, mergeXSL);
                f_view = ReportExport.jsonExport(null, absolutePath, xmlGenerated);
                deleteFile(xmlGenerated);
                break;
            case Utils.PDF:
                CommandLine.error(Constant.messages.getString("exportreport.message.notice.pdf"));
                return false;
            case Utils.DOC:
                CommandLine.error(Constant.messages.getString("exportreport.message.notice.doc"));
                return false;
            default:
                break;
            }
        } finally {
            deleteFile(xmlPath);
        }

        /* add a command line variable called show to determine if browser will open or not. */
        // try {
        // if ((f_view != null) && show) {
        // DesktopUtils.openUrlInBrowser(f_view.toURI());
        // }
        // } catch (Exception e) {
        // logger.error(e.getMessage(), e);
        // CommandLine.error(Constant.messages.getString("exportreport.message.error.file.open"));
        // }
        return true;
    }

    public void generateReport(ViewDelegate view, ExtensionExportReport extension) {
        FileList list = extension.getFileList();
        try {
            if (fc == null) {
                fc = generateWriteableFileChooser(list);
                fc.addPropertyChangeListener(WritableFileChooser.FILE_FILTER_CHANGED_PROPERTY, new PropertyChangeListener() {
                    @Override
                    public void propertyChange(PropertyChangeEvent evt) {
                        ReportFilter filter = (ReportFilter) evt.getNewValue();
                        String extension = (filter.getExtensionByDescription(filter.getDescription()).length() == 0 ? "" : "." + filter.getExtensionByDescription(filter.getDescription()));
                        fc.setSelectedFile(new File(extension));
                    }
                });
            }

            int rc = fc.showSaveDialog(View.getSingleton().getMainFrame());

            boolean valid = false;
            String fileExtension = "";
            while (rc == WritableFileChooser.APPROVE_OPTION && !valid) {
                fileExtension = list.compareExtension(fc.getSelectedFile().getName());
                if (fileExtension.length() > 0) {
                    valid = true;
                }
                if (!valid) {
                    // Determine in v2.0 which method to use for display of
                    // error messages based on feedback.
                    // JOptionPane.showMessageDialog(null,
                    // "The file " + fc.getSelectedFile() + " is not a valid
                    // destination file.", "Open Error",
                    // JOptionPane.ERROR_MESSAGE);
                    view.showWarningDialog(Constant.messages.getString("exportreport.message.error.file.destination", fc.getSelectedFile()));
                    rc = fc.showSaveDialog(View.getSingleton().getMainFrame());
                }
            }

            if (rc == WritableFileChooser.APPROVE_OPTION && valid) {
                task = new Task(view, extension, fileExtension, fc.getSelectedFile());
                task.execute();
            }

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            view.showWarningDialog(Constant.messages.getString("exportreport.message.error.exception"));
        }
    }

    private WritableFileChooser generateWriteableFileChooser(FileList list) {
        fc = new WritableFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());

        fc.addChoosableFileFilter(new ReportFilter(list, Utils.ALL));
        fc.addChoosableFileFilter(new ReportFilter(list, Utils.HTML));
        fc.addChoosableFileFilter(new ReportFilter(list, Utils.BOOTSTRAP));
        fc.addChoosableFileFilter(new ReportFilter(list, Utils.XML));
        fc.addChoosableFileFilter(new ReportFilter(list, Utils.JSON));
        fc.addChoosableFileFilter(new ReportFilter(list, Utils.PDF));
        fc.addChoosableFileFilter(new ReportFilter(list, Utils.DOC));

        fc.setAcceptAllFileFilterUsed(false);

        fc.setFileView(new ReportFileView(list));

        return fc;
    }

    private static void deleteFile(String str) {
        // String err debugging only, remove in v2.0
        File f = new File(str);
        boolean deleted = false;
        if (f.exists() && !f.isDirectory()) {
            deleted = f.delete();
        }
        if (!deleted) {
            logger.error("Error: File could not be deleted.");
        }
    }
}
