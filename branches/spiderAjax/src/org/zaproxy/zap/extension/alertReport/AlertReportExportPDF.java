/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2011 The ZAP Development team
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
package org.zaproxy.zap.extension.alertReport;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;

import com.itextpdf.text.Anchor;
import com.itextpdf.text.BadElementException;
import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Font;
import com.itextpdf.text.Image;
import com.itextpdf.text.PageSize;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfImportedPage;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfWriter;

/**
 * Export Alert to PDF report
 * Fill field 'Other Info' of the Alert to describe test
 * One line for describing the step and other line for adding an image file. For example:
 * Step URL attack
 * DV-005-ImageTest1.png
 * Step  2 URL attack
 * DV-005-ImageTest2.png
 * Then, it's fill into the report
 */
public class AlertReportExportPDF {

		//private static ExtensionAlertReportExport extension = null;
		private static final Logger logger = Logger.getLogger(AlertReportExportPDF.class);
		private static Font titleFont = new Font(Font.FontFamily.TIMES_ROMAN, 28,
			Font.BOLD);
	
		private static Font catFont = new Font(Font.FontFamily.TIMES_ROMAN, 18,
				Font.BOLD);
		private static Font subFont = new Font(Font.FontFamily.TIMES_ROMAN, 16,
				Font.BOLD);
		private static Font smallBold = new Font(Font.FontFamily.TIMES_ROMAN, 12,
				Font.BOLD);
		private static Font litleFont = new Font(Font.FontFamily.TIMES_ROMAN, 8,
				Font.NORMAL);
		
	
		public AlertReportExportPDF() {
			super();
			
		}

		public boolean exportAlert(java.util.List<java.util.List<Alert>> alerts, String fileName,ExtensionAlertReportExport extensionExport){
			Document document = new Document(PageSize.A4);
			try {
				//Document documentAdd = null;
				PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(fileName));
				document.open();
				boolean attach = false;
				//add attach document is exist
				if (!extensionExport.getParams().getDocumentAttach().isEmpty()){
					PdfReader reader = new PdfReader(extensionExport.getParams().getDocumentAttach());
					int n = reader.getNumberOfPages();
					PdfImportedPage page;
					// Go through all pages
					for (int i = 1; i <= n; i++) {
						page = writer.getImportedPage(reader, i);
						Image instance = Image.getInstance(page);
						instance.scalePercent(95f);
						document.add(instance);
					}
					attach =true;
				}
				if (!attach){
					addMetaData(document,extensionExport);
					addTitlePage(document,extensionExport);
				}
				for (int i = 0; i < alerts.size(); i++) {
					java.util.List<Alert> alertAux = (java.util.List<Alert>) alerts.get(i);
					addContent(document,alertAux,extensionExport);
				}
				
				document.close();
				return true;
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
				document.close();
				return false;
			}
			
		}

		// iText allows to add metadata to the PDF which can be viewed in your Adobe
		// Reader
		// under File -> Properties
		private static void addMetaData(Document document,ExtensionAlertReportExport extensionExport) {
					
			document.addTitle(extensionExport.getParams().getTitleReport());
			document.addSubject(extensionExport.getParams().getCustomerName());
			document.addKeywords(extensionExport.getParams().getPdfKeywords());
			document.addAuthor(extensionExport.getParams().getAuthorName());
			document.addCreator(extensionExport.getParams().getAuthorName());
		}

		private static void addTitlePage(Document document,ExtensionAlertReportExport extensionExport)
				throws DocumentException {
			
			document.addHeader("Header1", "Header2");
			
			Paragraph preface = new Paragraph();
			// We add one empty line
			addEmptyLine(preface, 3);
			//add logo first page
			addImage(preface, extensionExport.getParams().getLogoFileName(),40f);
		
			addEmptyLine(preface, 4);
			// Lets write a big header
			Paragraph paragraph = new Paragraph(extensionExport.getParams().getTitleReport(), titleFont);
			paragraph.setAlignment(Paragraph.ALIGN_CENTER);
			preface.add(paragraph);
			
			addEmptyLine(preface, 3);
			paragraph = new Paragraph(extensionExport.getParams().getCustomerName(),	catFont);
			paragraph.setAlignment(Paragraph.ALIGN_CENTER);
			preface.add(paragraph);
		
			
			addEmptyLine(preface, 15);
			
			preface.add(new Paragraph(extensionExport.getMessageString("alert.export.message.export.pdf.confidential"),smallBold));
			preface.add(new Paragraph(extensionExport.getParams().getConfidentialText(), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
					litleFont));

			document.add(preface);
			// Start a new page
			document.newPage();
		}

		/**
		 * Add image a Paragraph
		 * @param paragraph
		 * @param image
		 * @param path
		 * @throws BadElementException
		 */
		private static void addImage(Paragraph paragraph, String imagePath,float scalePercent) throws BadElementException{
			Image image1;
			try {
				if (!imagePath.isEmpty()){
					image1 = Image.getInstance(imagePath);
					if (scalePercent!=0)
							image1.scalePercent(40f);
					image1.setAlignment(Image.ALIGN_CENTER);
					paragraph.add(image1);
				}
			} catch (MalformedURLException e) {
				logger.error(e.getMessage(), e);
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
			
			
		}
		
		private static void addContent(Document document,java.util.List<Alert> alerts,ExtensionAlertReportExport extensionExport) throws DocumentException {
			
			Alert alert = alerts.get(0);
			
			Anchor anchor = new Anchor(alert.getAttack(), catFont);
			anchor.setName(alert.getAttack());
			
			Paragraph content = new Paragraph();
			content.add(new Paragraph(alert.getAlert(), catFont));
			content.add(new Paragraph(extensionExport.getMessageString("alert.export.message.export.pdf.description"), subFont));
			content.add(new Paragraph(alert.getDescription()));
			addEmptyLine(content, 1);
			content.add(new Paragraph(extensionExport.getMessageString("alert.export.message.export.pdf.risk"), subFont));
			content.add(new Paragraph(Alert.MSG_RISK[alert.getRisk()]));
			addEmptyLine(content, 1);
			content.add(new Paragraph(extensionExport.getMessageString("alert.export.message.export.pdf.reability"), subFont));
			content.add(new Paragraph(Alert.MSG_RISK[alert.getReliability()]));
			addEmptyLine(content, 1);
			content.add(new Paragraph(extensionExport.getMessageString("alert.export.message.export.pdf.urls"), subFont));
			
			// write all url with the same pluginid
			for (int i = 0; i < alerts.size(); i++) {
				Alert alertAux = alerts.get(i);
				//add url link and attack
				anchor = new Anchor((i+1)+"-" + alertAux.getUri());
				anchor.setReference(alertAux.getUri());
				content.add(anchor);
				if (!alertAux.getParam().isEmpty()){	
					content.add(new Paragraph("           "+extensionExport.getMessageString("alert.export.message.export.pdf.parameters")+": "+alertAux.getParam()));
					addEmptyLine(content, 1);
				}
				if (!alertAux.getAttack().isEmpty()){
					content.add(new Paragraph(extensionExport.getMessageString("alert.export.message.export.pdf.attack"), subFont));
					content.add(new Paragraph(alertAux.getAttack()));
					addEmptyLine(content, 1);
				}
				//add images test
				addEmptyLine(content, 1);
				String images = alertAux.getOtherInfo(); 
				if (!images.isEmpty()){
					String[] list = images.split("\n");
					for (int j = 0, lengh = list.length/2; j <= lengh; j += 2) {
						//if (!((j+1)>=list.length)){
						String step = list[j];
						Paragraph paragraph = new Paragraph(step);
						content.add(paragraph);
						addEmptyLine(content, 1);
						//add step and image
						String imageName = "";
						String path = extensionExport.getParams().getWorkingDirImages();
						if (!list[j+1].isEmpty()){
							imageName = list[j+1];
							//if exist an image
							try{
								if ((imageName.endsWith(".png")||imageName.endsWith(".jpg"))&&(!path.isEmpty())){
									addImage(content, path+"/"+imageName, 60f);
									addEmptyLine(content, 1);
									paragraph = new Paragraph(extensionExport.getMessageString("alert.export.message.export.pdf.image")+": "+Integer.toString(j),	litleFont);
									paragraph.setAlignment(Paragraph.ALIGN_CENTER);
									content.add(paragraph);
								}else{
									paragraph = new Paragraph(imageName);
									content.add(paragraph);
									addEmptyLine(content, 1);
								}
							} catch (Exception e) {
								logger.error(e.getMessage(), e);
							}
						}
				//		j++;
				//	}
						
						
					
					}
				}
				
				addEmptyLine(content, 1);
						
			}
			addEmptyLine(content, 1);
			content.add(new Paragraph(extensionExport.getMessageString("alert.export.message.export.pdf.solution"), subFont));
			content.add(new Paragraph(alert.getSolution()));
			addEmptyLine(content, 1);
			content.add(new Paragraph(extensionExport.getMessageString("alert.export.message.export.pdf.references"), subFont));
			content.add(new Paragraph(alert.getReference()));
			addEmptyLine(content, 1);
            document.add(content);
			
            // Start a new page
			document.newPage();

		}

		/*public class ReadAndUsePdf {
			private static String INPUTFILE = "c:/temp/FirstPdf.pdf";
			private static String OUTPUTFILE = "c:/temp/ReadPdf.pdf";

			public static void main(String[] args) throws DocumentException,
					IOException {
				Document document = new Document();

				PdfWriter writer = PdfWriter.getInstance(document,
						new FileOutputStream(OUTPUTFILE));
				document.open();
				PdfReader reader = new PdfReader(INPUTFILE);
				int n = reader.getNumberOfPages();
				PdfImportedPage page;
				// Go through all pages
				for (int i = 1; i <= n; i++) {
					// Only page number 2 will be included
					if (i == 2) {
						page = writer.getImportedPage(reader, i);
						Image instance = Image.getInstance(page);
						document.add(instance);
					}
				}
				document.close();

			}

		} */


		private static void addEmptyLine(Paragraph paragraph, int number) {
			for (int i = 0; i < number; i++) {
				paragraph.add(new Paragraph(" "));
			}
		}
	
}
