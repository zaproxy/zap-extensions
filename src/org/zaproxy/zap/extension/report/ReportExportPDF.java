package org.zaproxy.zap.extension.report;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;

import org.parosproxy.paros.core.scanner.Alert;

import com.itextpdf.text.Anchor;
import com.itextpdf.text.BadElementException;
import com.itextpdf.text.BaseColor;
import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Font;
import com.itextpdf.text.Image;
import com.itextpdf.text.List;
import com.itextpdf.text.ListItem;
import com.itextpdf.text.PageSize;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.Section;
import com.itextpdf.text.pdf.PdfWriter;

/**
 *Export Alert to PDF
 * Fill field 'Other Info' of the Alert to describe test
 * One line for describing the step and other line for adding an image file. For example:
 * Step URL attack
 * DV-005-ImageTest1.png
 * Step  2 URL attack
 * DV-005-ImageTest2.png
 *
 */
public class ReportExportPDF {

		private static ExtensionReportExport extension = null;
		private static Font titleFont = new Font(Font.FontFamily.TIMES_ROMAN, 28,
			Font.BOLD);
	
		private static Font catFont = new Font(Font.FontFamily.TIMES_ROMAN, 18,
				Font.BOLD);
		private static Font redFont = new Font(Font.FontFamily.TIMES_ROMAN, 12,
				Font.NORMAL, BaseColor.RED);
		private static Font subFont = new Font(Font.FontFamily.TIMES_ROMAN, 16,
				Font.BOLD);
		private static Font smallBold = new Font(Font.FontFamily.TIMES_ROMAN, 12,
				Font.BOLD);
		private static Font litleFont = new Font(Font.FontFamily.TIMES_ROMAN, 8,
				Font.NORMAL);
		
	
		public ReportExportPDF() {
			super();
			
		}

		public boolean exportAlertPDF(java.util.List<Alert> alerts, String fileName,ExtensionReportExport extensionExport){
			try {
				extension = extensionExport;
				Document document = new Document(PageSize.A4);
				PdfWriter.getInstance(document, new FileOutputStream(fileName));
				document.open();
				addMetaData(document);
				addTitlePage(document);
				addContent(document,alerts);
				document.close();
				return true;
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}
			
		}

		// iText allows to add metadata to the PDF which can be viewed in your Adobe
		// Reader
		// under File -> Properties
		private static void addMetaData(Document document) {
					
			document.addTitle(extension.getParams().getTitleReport());
			document.addSubject(extension.getParams().getCustomerName());
			document.addKeywords(extension.getParams().getPdfKeywords());
			document.addAuthor(extension.getParams().getAuthorName());
			document.addCreator(extension.getParams().getAuthorName());
		}

		private static void addTitlePage(Document document)
				throws DocumentException {
			
			document.addHeader("Header1", "Header2");
			
			Paragraph preface = new Paragraph();
			// We add one empty line
			addEmptyLine(preface, 3);
			//add logo first page
			addImage(preface, extension.getParams().getLogoFileName(),40f);
		
			addEmptyLine(preface, 4);
			// Lets write a big header
			Paragraph paragraph = new Paragraph(extension.getParams().getTitleReport(), titleFont);
			paragraph.setAlignment(Paragraph.ALIGN_CENTER);
			preface.add(paragraph);
			
			addEmptyLine(preface, 3);
			paragraph = new Paragraph(extension.getParams().getCustomerName(),	catFont);
			paragraph.setAlignment(Paragraph.ALIGN_CENTER);
			preface.add(paragraph);
		
			
			addEmptyLine(preface, 15);
			
			preface.add(new Paragraph(extension.getMessageString("alert.export.message.export.pdf.confidential"),smallBold));
			preface.add(new Paragraph(extension.getParams().getConfidentialText(), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
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
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
		}
		
		private static void addContent(Document document,java.util.List<Alert> alerts) throws DocumentException, MalformedURLException, IOException {
			
			Alert alert = alerts.get(0);
			
			Anchor anchor = new Anchor(alert.getAttack(), catFont);
			anchor.setName(alert.getAttack());
			
			Paragraph content = new Paragraph();
			content.add(new Paragraph(alert.getAlert(), catFont));
			content.add(new Paragraph(extension.getMessageString("alert.export.message.export.pdf.description"), subFont));
			content.add(new Paragraph(alert.getDescription()));
			addEmptyLine(content, 1);
			content.add(new Paragraph(extension.getMessageString("alert.export.message.export.pdf.risk"), subFont));
			content.add(new Paragraph(Alert.MSG_RISK[alert.getRisk()]));
			addEmptyLine(content, 1);
			content.add(new Paragraph(extension.getMessageString("alert.export.message.export.pdf.reability"), subFont));
			content.add(new Paragraph(Alert.MSG_RISK[alert.getReliability()]));
			addEmptyLine(content, 1);
			content.add(new Paragraph(extension.getMessageString("alert.export.message.export.pdf.urls"), subFont));
			//add url link and attack
			anchor = new Anchor(alert.getUri());
			anchor.setReference(alert.getUri());
			content.add(anchor);
			if (!alert.getParam().isEmpty()){	
				content.add(new Paragraph("           "+extension.getMessageString("alert.export.message.export.pdf.parameters")+": "+alert.getParam()));
				addEmptyLine(content, 1);
			}
			if (!alert.getAttack().isEmpty()){
				content.add(new Paragraph(extension.getMessageString("alert.export.message.export.pdf.attack"), subFont));
				content.add(new Paragraph(alert.getAttack()));
				addEmptyLine(content, 1);
			}
			// write all url with the same pluginid
			for (int i = 0; i < alerts.size(); i++) {
				Alert alertAux = alerts.get(i);
				
				//add images test
				addEmptyLine(content, 1);
				String images = alertAux.getOtherInfo(); 
				if (!images.isEmpty()){
					String[] list = images.split("\n");
					for (int j = 0; j < list.length; j++) {
						
						if (!((j+1)>=list.length)){
							String step = list[j];
							Paragraph paragraph = new Paragraph(step);
							content.add(paragraph);
							addEmptyLine(content, 1);
							//add step and image
							String imageName = "";
							String path = extension.getParams().getWorkingDirImages();
							imageName = list[j+1];
							//if exist an image
							if ((imageName.contains(".png")||imageName.contains(".jpg"))&&(!path.isEmpty())){
								addImage(content, path+"/"+imageName, 60f);
								addEmptyLine(content, 1);
								paragraph = new Paragraph(extension.getMessageString("alert.export.message.export.pdf.image")+": "+String.valueOf(j),	litleFont);
								paragraph.setAlignment(Paragraph.ALIGN_CENTER);
								content.add(paragraph);
							}else{
								paragraph = new Paragraph(imageName);
								content.add(paragraph);
								addEmptyLine(content, 1);
							}
							j++;
						}
						
						
					
					}
				}
				
				addEmptyLine(content, 1);
						
			}
			addEmptyLine(content, 1);
			content.add(new Paragraph(extension.getMessageString("alert.export.message.export.pdf.solution"), subFont));
			content.add(new Paragraph(alert.getSolution()));
			addEmptyLine(content, 1);
			content.add(new Paragraph(extension.getMessageString("alert.export.message.export.pdf.references"), subFont));
			content.add(new Paragraph(alert.getReference()));
			addEmptyLine(content, 1);
            document.add(content);
			
			
			//add paragraph


		}


		private static void createList(Section subCatPart) {
			List list = new List(true, false, 10);
			list.add(new ListItem("First point"));
			list.add(new ListItem("Second point"));
			list.add(new ListItem("Third point"));
			subCatPart.add(list);
		}

		private static void addEmptyLine(Paragraph paragraph, int number) {
			for (int i = 0; i < number; i++) {
				paragraph.add(new Paragraph(" "));
			}
		}
	
}
