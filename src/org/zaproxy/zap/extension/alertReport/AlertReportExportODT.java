package org.zaproxy.zap.extension.alertReport;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.log4j.Logger;
import org.odftoolkit.odfdom.pkg.OdfFileDom;
import org.odftoolkit.odfdom.type.Color;
import org.odftoolkit.simple.TextDocument;
import org.odftoolkit.simple.draw.FrameStyleHandler;
import org.odftoolkit.simple.draw.Image;
import org.odftoolkit.simple.meta.Meta;
import org.odftoolkit.simple.style.Border;
import org.odftoolkit.simple.style.StyleTypeDefinitions;
import org.odftoolkit.simple.style.StyleTypeDefinitions.AnchorType;
import org.odftoolkit.simple.style.StyleTypeDefinitions.CellBordersType;
import org.odftoolkit.simple.style.StyleTypeDefinitions.FrameHorizontalPosition;
import org.odftoolkit.simple.style.StyleTypeDefinitions.HorizontalAlignmentType;
import org.odftoolkit.simple.style.StyleTypeDefinitions.HorizontalRelative;
import org.odftoolkit.simple.style.StyleTypeDefinitions.VerticalRelative;
import org.odftoolkit.simple.table.Cell;
import org.odftoolkit.simple.table.Table;
import org.odftoolkit.simple.text.Footer;
import org.odftoolkit.simple.text.Header;
import org.odftoolkit.simple.text.Paragraph;
import org.parosproxy.paros.core.scanner.Alert;

import com.itextpdf.text.BadElementException;

/**
 * Export Alert to ODT report Fill field 'Other Info' of the Alert to describe
 * test One line for describing the step and other line for adding an image
 * file. For example: Step URL attack DV-005-ImageTest1.png Step 2 URL attack
 * DV-005-ImageTest2.png Then, it's fill into the report
 * http://incubator.apache.
 * org/odftoolkit/simple/document/cookbook/Text%20Document.html#Generate
 * TextDocument
 */
public class AlertReportExportODT {

	private static ExtensionAlertReportExport extension = null;
	private static final Logger logger = Logger
			.getLogger(AlertReportExportODT.class);

	private String outputFileName;
	private static TextDocument outputDocument = null;
	private static TextDocument documentAdd = null;

	// fonts
	private static org.odftoolkit.simple.style.Font fontText = new org.odftoolkit.simple.style.Font(
			"Arial", StyleTypeDefinitions.FontStyle.REGULAR, 12, Color.BLACK);
	private static org.odftoolkit.simple.style.Font fontTitleTextReport = new org.odftoolkit.simple.style.Font(
			"Arial", StyleTypeDefinitions.FontStyle.BOLD, 28, Color.BLACK);
	private static org.odftoolkit.simple.style.Font fontSmallBold = new org.odftoolkit.simple.style.Font(
			"Arial", StyleTypeDefinitions.FontStyle.BOLD, 9, Color.BLACK);
	private static org.odftoolkit.simple.style.Font fontSmall = new org.odftoolkit.simple.style.Font(
			"Arial", StyleTypeDefinitions.FontStyle.REGULAR, 9, Color.BLACK);
	private static org.odftoolkit.simple.style.Font fontTitleBold = new org.odftoolkit.simple.style.Font(
			"Arial", StyleTypeDefinitions.FontStyle.BOLD, 14, Color.BLACK);

	public AlertReportExportODT() {
		super();
		setupOutputDocument();
	}

	public static TextDocument getOutputDocument() {
		return outputDocument;
	}

	void setupOutputDocument() {
	/*	try {
			outputDocument = TextDocument.newTextDocument();
			

		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			outputDocument = null;
		}*/
	}

	void saveOutputDocument() {
		try {
			outputDocument.save(outputFileName);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	public boolean exportAlert(java.util.List alerts, String fileName,
			ExtensionAlertReportExport extensionExport) {
		try {
			outputDocument = TextDocument.newTextDocument();
			extension = extensionExport;
			outputFileName = fileName;
			//add attach document is exist
			if (!extension.getParams().getDocumentAttach().isEmpty()){
				documentAdd = (TextDocument)TextDocument.loadDocument(extension.getParams().getDocumentAttach());
		    	outputDocument = documentAdd;
			}
			// if add attach document
			if (documentAdd==null){
				//addFooter();
				//addHeader();
				addMetaData();
				addTitlePage();
			}
			for (int i = 0; i < alerts.size(); i++) {
				java.util.List alertAux = (java.util.List) alerts.get(i);
				addContent(alertAux);
			}
			saveOutputDocument();
			return true;
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			return false;
		}

	}

	// iText allows to add metadata to the PDF which can be viewed in your Adobe
	// Reader
	// under File -> Properties
	private static void addMetaData() throws Exception {
		  OdfFileDom metadom = outputDocument.getMetaDom();
	      Meta metadata = new Meta(metadom);
		  metadata.addKeyword(extension.getParams().getPdfKeywords());
	      metadata.setCreator(extension.getParams().getAuthorName());
	      metadata.setSubject(extension.getParams().getCustomerName());
	      metadata.setTitle(extension.getParams().getTitleReport());
		
	}

	private static void addLines(int cant) throws Exception {
		for (int i = 0; i < cant; i++) {
			outputDocument.addParagraph(null);
		}
	}

	private static void addFooter(){
		Footer footer = outputDocument.getFooter();
		
		Table table1 = footer.addTable(1, 1);

		Cell cellByPosition = table1.getCellByPosition(0, 0);

		cellByPosition.setStringValue("Footer");
		cellByPosition.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
		cellByPosition.setFont(fontSmall);
	}
	
	private static void addHeader(){
		Header docHeader = outputDocument.getHeader();
		
		Table table1 = docHeader.addTable(1, 2);

		table1.getCellByPosition(0, 0).setStringValue("header table cell");

		//Cell cell = table1.getCellByPosition(1, 0);

		//Image image1 = cell.setImage(new URI("file:/c:/image.jpg"));
	}
	
	private static void addTitlePage() throws Exception {

		addLines(2);
		
		Paragraph para = outputDocument.addParagraph(null);
		
		//add company logo
		addImage(para, extension.getParams().getLogoFileName(), 0);
	
		addLines(4);
		// Lets write a big header
	    para = outputDocument.addParagraph(null);
		
	    para.setTextContent(extension.getParams().getTitleReport());
	    para.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
	    para.setFont(fontTitleTextReport);
		
		addLines(4);
		para = outputDocument.addParagraph(null);
		para.setTextContent(extension.getParams().getCustomerName());
		para.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
		para.setFont(fontTitleTextReport);

		addLines(15);

		Table table = outputDocument.addTable(2, 1);

		Cell cell = table.getCellByPosition(0, 0);
		cell.setStringValue(extension
				.getMessageString("alert.export.message.export.pdf.confidential"));
		cell.setFont(fontSmallBold);
		String color = Color.toSixDigitHexRGB("#87cefa");
		cell.setCellBackgroundColor(Color.valueOf(color));
		Cell cell1 = table.getCellByPosition(0, 1);
		cell1.setStringValue(extension.getParams().getConfidentialText());
		cell1.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
		cell1.setFont(fontSmall);

		outputDocument.addPageBreak();

	}

	/**
	 * Add image a Paragraph
	 * @param paragraph
	 * @param image
	 * @param path
	 * @throws BadElementException
	 * @throws URISyntaxException 
	 */
	private static void addImage(Paragraph paragraph, String imagePath,float scalePercent) throws BadElementException, URISyntaxException{
		try {
			if (!imagePath.isEmpty()){
				Image image1 = Image.newImage(paragraph, new URI("file:///"	+ imagePath));
				image1.setHorizontalPosition(FrameHorizontalPosition.CENTER);
				FrameStyleHandler handler = image1.getStyleHandler();
				handler.setAchorType(AnchorType.TO_FRAME);
				Border border = new Border(Color.BLACK, 1, StyleTypeDefinitions.SupportedLinearMeasure.PT);
				handler.setBorders(border, CellBordersType.ALL_FOUR);
				handler.setHorizontalRelative(HorizontalRelative.PARAGRAPH_START_MARGIN);
				handler.setVerticalRelative(VerticalRelative.TEXT);
				
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
		
		
	}
	
	private static void addContent(java.util.List<Alert> alerts) throws Exception {
		
		Alert alert = alerts.get(0);
		
		//Title Alert
		Paragraph para = outputDocument.addParagraph(null);
		
		Table table = outputDocument.addTable(1, 1);
		Cell cell = table.getCellByPosition(0, 0);
		Border border = new Border(Color.BLACK, 0, StyleTypeDefinitions.SupportedLinearMeasure.PT);
	    cell.setBorders(CellBordersType.NONE, border);
		cell.setStringValue(alert.getAlert());
		cell.setFont(fontTitleBold);
		String color = Color.toSixDigitHexRGB("#87cefa");
		cell.setCellBackgroundColor(Color.valueOf(color));
		
		addLines(1);
		//add title description
		para = outputDocument.addParagraph(extension.getMessageString("alert.export.message.export.pdf.description"));
		para.setFont(fontTitleBold);
		para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
		addLines(1);
		//add description
		para = outputDocument.addParagraph(alert.getDescription());
		para.setFont(fontText);
		para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
		
		addLines(1);
		
		//add title risk
		para = outputDocument.addParagraph(extension.getMessageString("alert.export.message.export.pdf.risk"));
		para.setFont(fontTitleBold);
		para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
		addLines(1);
		//add risk
		para = outputDocument.addParagraph(Alert.MSG_RISK[alert.getRisk()]);
		para.setFont(fontText);
		para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
		addLines(1);
		//add title reability
		para = outputDocument.addParagraph(extension.getMessageString("alert.export.message.export.pdf.reability"));
		para.setFont(fontTitleBold);
		para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
		addLines(1);
		//add reability
		para = outputDocument.addParagraph(Alert.MSG_RISK[alert.getReliability()]);
		para.setFont(fontText);
		para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
		addLines(1);
		//add title urls
		para = outputDocument.addParagraph(extension.getMessageString("alert.export.message.export.pdf.urls"));
		para.setFont(fontTitleBold);
		para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
	
		// write all url with the same pluginid
		for (int i = 0; i < alerts.size(); i++) {
			Alert alertAux = alerts.get(i);
			//add url link and attack
			para = outputDocument.addParagraph((i+1)+"-" + alertAux.getUri());
			para.setFont(fontText);
			para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
			para.applyHyperlink(new URI(alertAux.getUri()));
			
			if (!alertAux.getParam().isEmpty()){	
				para = outputDocument.addParagraph(extension.getMessageString("alert.export.message.export.pdf.parameters")+": "+alertAux.getParam());
				para.setFont(fontText);
				para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
				addLines(1);
			}
			if (!alertAux.getAttack().isEmpty()){
				para = outputDocument.addParagraph(extension.getMessageString("alert.export.message.export.pdf.attack"));
				para.setFont(fontTitleBold);
				para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
				para = outputDocument.addParagraph(alertAux.getAttack());
				para.setFont(fontText);
				para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
				addLines(1);
			}
			//add images test
			addLines(1);
			String images = alertAux.getOtherInfo(); 
			if (!images.isEmpty()){
				String[] list = images.split("\n");
				int imageCount = 1;
				for (int j = 0; j < list.length; j++) {
					
					if (!((j+1)>=list.length)){
						String step = list[j];
						para = outputDocument.addParagraph(step);
						para.setFont(fontText);
						para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
						addLines(1);
						//add step and image
						String imageName = "";
						String path = extension.getParams().getWorkingDirImages();
						imageName = list[j+1];
						//if exist an image
						try{
							if ((imageName.contains(".png")||imageName.contains(".jpg"))&&(!path.isEmpty())){
								para = outputDocument.addParagraph(null);
								para.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
								addImage(para, path+"/"+imageName, 60f);
								addLines(1);
								para = outputDocument.addParagraph(extension.getMessageString("alert.export.message.export.pdf.image")+": "+String.valueOf(imageCount));
								para.setFont(fontText);
								para.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
								imageCount++;
							}else{
								para = outputDocument.addParagraph(imageName);
								para.setFont(fontText);
								para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
								addLines(1);
							}
						} catch (Exception e) {
							logger.error(e.getMessage(), e);
						}
						j++;
					}
					
					
				
				}
			}
			
			addLines(1);
					
		}
		addLines(1);
		para = outputDocument.addParagraph(extension.getMessageString("alert.export.message.export.pdf.solution"));
		para.setFont(fontTitleBold);
		para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
		para = outputDocument.addParagraph(alert.getSolution());
		para.setFont(fontText);
		para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
		
		addLines(1);
		para = outputDocument.addParagraph(extension.getMessageString("alert.export.message.export.pdf.references"));
		para.setFont(fontTitleBold);
		para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
		para = outputDocument.addParagraph(alert.getReference());
		para.setFont(fontText);
		para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
		addLines(1);
			
        // Start a new page
		outputDocument.addPageBreak();

	}
}
