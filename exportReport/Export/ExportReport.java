package org.zaproxy.zap.extension.exportReport.Export;

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

import java.awt.Toolkit;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.text.MessageFormat;
import java.util.Locale;

import javax.swing.JOptionPane;
import javax.swing.SwingWorker;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.exportReport.ExtensionExportReport;
import org.zaproxy.zap.extension.exportReport.FileChooser.*;
import org.zaproxy.zap.utils.DesktopUtils;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

/*
 * AUTHOR		:	GORAN SARENKAPA - JordanGS
 * SPONSOR		:	RYERSON UNIVERSITY
 * CLASS		:	ExportReport.java 
 * DESC			:	FileChooser setup class. Runs the Export as a background task with a Swing Worker.
 * CREATED ON	:	MARCH 10TH, 2016
 * CURRENT VER	:	V1.0
 * SOURCE		:	https://github.com/JordanGS/workspace/tree/master/zap-extensions/src/org/zaproxy/zap/extension/exportReport
 */

/* 
 * MODIFED BY	:	<NAME> - <GIT USER>
 * MOD DATE		:	
 * MOD VERSION	:	<VERSION OF PLUGIN>
 * MOD DESC		:	
 */

public class ExportReport {
	private Logger logger = Logger.getLogger(ExportReport.class);

	private Task task; // Create a task and dump the export into the background,
						// essential for large exports.
	private WritableFileChooser fc; // Global because the property change
									// listener won't be able to access if it's
									// local scope.

	class Task extends SwingWorker<Void, Void> {
		private ViewDelegate view;
		private ExtensionExportReport extension;
		private String fileExtension;

		public Task(ViewDelegate view, ExtensionExportReport extension, String fileExtension) {
			this.view = view;
			this.extension = extension;
			this.fileExtension = fileExtension;
		}

		/**
		 * Main task. Executed in background thread.
		 */
		@Override
		public Void doInBackground() {
			File f = fc.getSelectedFile();

			String file = f.getName();
			String absolutePath = f.getAbsolutePath();
			String fileName = file.substring(0, file.lastIndexOf(fileExtension) - 1);
			String path = absolutePath.substring(0, absolutePath.lastIndexOf(file));

			String XML_PATH = "";
			try
			{
				XML_PATH = ReportExport.generateDUMP(path, fileName, extension.extensionGetTitle(),
						extension.extensionGetBy(), extension.extensionGetFor(), extension.extensionGetScanDate(),
						extension.extensionGetScanVer(), extension.extensionGetReportDate(),
						extension.extensionGetReportVer(), extension.getDescription(),
						extension.getIncludedAlertSeverity(), extension.getIncludedAlertDetails());
			}
			catch (UnsupportedEncodingException e)
			{
				logger.error(e.getMessage(), e);
				view.showMessageDialog(MessageFormat.format("Error: Problem encoding the DUMP File content, please see log for more details.", new Object[] { absolutePath }));
			}

			String extensionPath = Constant.getZapHome() + "xml" + File.separator;
			String mergeXSL = (extensionPath + "merge.xml.xsl");
			String reportXSL = (extensionPath + "report.html.xsl");

			File f_view = null;
			boolean show = false;
			switch (fileExtension.toLowerCase(Locale.ROOT)) {
			case Utils.html:
				f_view = ReportExport.TRANSFORMATION(view, logger, absolutePath, (path + fileName + ".xml"), XML_PATH, mergeXSL);
				f_view = null;
				f_view = ReportExport.TRANSFORMATION(view, logger, absolutePath, absolutePath,(path + fileName + ".xml"), reportXSL);
				deleteFile(path + fileName + ".xml", "The merged XML file: ");
				show = true;
				break;
			case Utils.bootstrap:
				view.showMessageDialog("Bootstrap: Currently unavilable, expected release is v2.0.");
				f_view = null;
				break;
			case Utils.xml:
				f_view = ReportExport.TRANSFORMATION(view, logger, absolutePath, (path + fileName + ".xml"), XML_PATH, mergeXSL);
				show = true;
				break;
			case Utils.json:
				view.showMessageDialog(MessageFormat.format("JSON: File will be generated but won't automatically open.", new Object[] { absolutePath }));
				f_view = ReportExport.TRANSFORMATION(view, logger, absolutePath, (path + fileName + ".xml"), XML_PATH, mergeXSL);
				f_view = null;
				f_view = ReportExport.JSON_EXPORT(view, logger, absolutePath, absolutePath,(path + fileName + ".xml"));
				deleteFile(path + fileName + ".xml", "The merged XML file: ");
				break;
			case Utils.pdf:
				view.showMessageDialog("PDF: Currently unavilable, expected release is v2.0.");
				f_view = null;
				break;
			case Utils.doc:
				view.showMessageDialog("DOC: Currently unavilable, expected release is v2.0.");
				f_view = null;
				break;
			default:
				break;
			}
			deleteFile(XML_PATH, "The data dump file: ");
			try {
				if (!(f_view == null) && (show == true))
				{
					DesktopUtils.openUrlInBrowser(f_view.toURI());					
				}
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
				view.showMessageDialog(MessageFormat.format("Error opening file.", new Object[] { absolutePath }));
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

	public void generateReport(ViewDelegate view, ExtensionExportReport extension) {
		FileList list = generateFileList();
		try {
			if (fc == null) {
				fc = generateWriteableFileChooser(fc, list);
				fc.addPropertyChangeListener(WritableFileChooser.FILE_FILTER_CHANGED_PROPERTY,
						new PropertyChangeListener() {
							@Override
							public void propertyChange(PropertyChangeEvent evt) {
								ReportFilter filter = (ReportFilter) evt.getNewValue();
								String extension = (filter.getExtensionByDescription(filter.getDescription())
										.length() == 0 ? ""
												: "." + filter.getExtensionByDescription(filter.getDescription()));
								fc.setSelectedFile(new File(extension));
							}
						});
			}

			int rc = fc.showSaveDialog(View.getSingleton().getMainFrame());

			boolean bool = false;
			String fileExtension = "";
			while (rc == WritableFileChooser.APPROVE_OPTION && !bool) {
				fileExtension = list.compareExtension(fc.getSelectedFile().getName());
				if (fileExtension.length() > 0) {
					bool = true;
				}
				if (!bool) {
					JOptionPane.showMessageDialog(null,
							"The file " + fc.getSelectedFile() + " is not a valid destination file.", "Open Error",
							JOptionPane.ERROR_MESSAGE);
					rc = fc.showSaveDialog(View.getSingleton().getMainFrame());
				}
			}

			if (rc == WritableFileChooser.APPROVE_OPTION & bool) {
				task = new Task(view, extension, fileExtension);
				task.execute();
			}

		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			view.showWarningDialog("Error occured, please see log for further details.");
		}
	}

	private FileList generateFileList() {
		FileList list = new FileList();
		list.add(Utils.html, Utils.htmlType, Utils.html, Utils.htmlDescription, Utils.htmlIcon);
		list.add(Utils.bootstrap, Utils.bootstrapType, Utils.bootstrap, Utils.bootstrapDescription,
				Utils.bootstrapIcon);
		list.add(Utils.xml, Utils.xmlType, Utils.xml, Utils.xmlDescription, Utils.xmlIcon);
		list.add(Utils.json, Utils.jsonType, Utils.json, Utils.jsonDescription, Utils.jsonIcon);
		list.add(Utils.pdf, Utils.pdfType, Utils.pdf, Utils.pdfDescription, Utils.pdfIcon);
		list.add(Utils.doc, Utils.docType, Utils.doc, Utils.docDescription, Utils.docIcon);
		return list;
	}

	private WritableFileChooser generateWriteableFileChooser(WritableFileChooser fc, FileList list) {
		fc = new WritableFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());

		fc.addChoosableFileFilter(new ReportFilter(list, Utils.ALL));
		fc.addChoosableFileFilter(new ReportFilter(list, Utils.html));
		fc.addChoosableFileFilter(new ReportFilter(list, Utils.bootstrap));
		fc.addChoosableFileFilter(new ReportFilter(list, Utils.xml));
		fc.addChoosableFileFilter(new ReportFilter(list, Utils.json));
		fc.addChoosableFileFilter(new ReportFilter(list, Utils.pdf));
		fc.addChoosableFileFilter(new ReportFilter(list, Utils.doc));

		fc.setAcceptAllFileFilterUsed(false);

		fc.setFileView(new ReportFileView(list));

		return fc;
	}

	private void deleteFile(String str, String err) {
		File f = new File(str);
		boolean deleted = false;
		if (f.exists() && !f.isDirectory()) {
			deleted = f.delete();
		}
		if (!deleted) {
			// Print to err
		}
	}
}
