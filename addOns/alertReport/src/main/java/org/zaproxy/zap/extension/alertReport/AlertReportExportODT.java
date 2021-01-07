/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.alertReport;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import org.odftoolkit.simple.text.Paragraph;
import org.parosproxy.paros.core.scanner.Alert;

/**
 * Export Alert to ODT report Fill field 'Other Info' of the Alert to describe test One line for
 * describing the step and other line for adding an image file. For example: Step URL attack
 * DV-005-ImageTest1.png Step 2 URL attack DV-005-ImageTest2.png Then, it's fill into the report
 * http://incubator.apache. org/odftoolkit/simple/document/cookbook/Text%20Document.html#Generate
 * TextDocument
 */
public class AlertReportExportODT {

    private static ExtensionAlertReportExport extension = null;
    private static final Logger logger = LogManager.getLogger(AlertReportExportODT.class);

    // fonts
    private static org.odftoolkit.simple.style.Font fontText =
            new org.odftoolkit.simple.style.Font(
                    "Arial", StyleTypeDefinitions.FontStyle.REGULAR, 12, Color.BLACK);
    private static org.odftoolkit.simple.style.Font fontTitleTextReport =
            new org.odftoolkit.simple.style.Font(
                    "Arial", StyleTypeDefinitions.FontStyle.BOLD, 28, Color.BLACK);
    private static org.odftoolkit.simple.style.Font fontSmallBold =
            new org.odftoolkit.simple.style.Font(
                    "Arial", StyleTypeDefinitions.FontStyle.BOLD, 9, Color.BLACK);
    private static org.odftoolkit.simple.style.Font fontSmall =
            new org.odftoolkit.simple.style.Font(
                    "Arial", StyleTypeDefinitions.FontStyle.REGULAR, 9, Color.BLACK);
    private static org.odftoolkit.simple.style.Font fontTitleBold =
            new org.odftoolkit.simple.style.Font(
                    "Arial", StyleTypeDefinitions.FontStyle.BOLD, 14, Color.BLACK);

    public AlertReportExportODT() {
        super();
    }

    void saveOutputDocument(TextDocument outputDocument, String outputFileName) {
        try {
            outputDocument.save(outputFileName);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

    public boolean exportAlert(
            java.util.List<List<Alert>> alerts,
            String fileName,
            ExtensionAlertReportExport extensionExport) {
        try {
            TextDocument outputDocument = null;
            extension = extensionExport;
            // add attach document is exist
            if (!extension.getParams().getDocumentAttach().isEmpty()) {
                outputDocument =
                        TextDocument.loadDocument(extension.getParams().getDocumentAttach());
            } else {
                outputDocument = TextDocument.newTextDocument();
                addMetaData(outputDocument);
                addTitlePage(outputDocument);
            }
            for (int i = 0; i < alerts.size(); i++) {
                java.util.List<Alert> alertAux = alerts.get(i);
                addContent(outputDocument, alertAux);
            }
            saveOutputDocument(outputDocument, fileName);
            return true;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return false;
        }
    }

    /**
     * Setting metadata document
     *
     * @param outputDocument
     * @throws Exception
     */
    private static void addMetaData(TextDocument outputDocument) throws Exception {
        OdfFileDom metadom = outputDocument.getMetaDom();
        Meta metadata = new Meta(metadom);
        metadata.addKeyword(extension.getParams().getPdfKeywords());
        metadata.setCreator(extension.getParams().getAuthorName());
        metadata.setSubject(extension.getParams().getCustomerName());
        metadata.setTitle(extension.getParams().getTitleReport());
    }

    /**
     * Add lines blank to document
     *
     * @param outputDocument
     * @param size
     * @throws Exception
     */
    private static void addLines(TextDocument outputDocument, int size) throws Exception {
        for (int i = 0; i < size; i++) {
            outputDocument.addParagraph(null);
        }
    }

    /*
     * private static void addFooter(TextDocument outputDocument){ Footer footer
     * = outputDocument.getFooter();
     *
     * Table table1 = footer.addTable(1, 1);
     *
     * Cell cellByPosition = table1.getCellByPosition(0, 0);
     *
     * cellByPosition.setStringValue("Footer");
     * cellByPosition.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
     * cellByPosition.setFont(fontSmall); }
     *
     * private static void addHeader(TextDocument outputDocument){ Header
     * docHeader = outputDocument.getHeader();
     *
     * Table table1 = docHeader.addTable(1, 2);
     *
     * table1.getCellByPosition(0, 0).setStringValue("header table cell");
     *
     * //Cell cell = table1.getCellByPosition(1, 0);
     *
     * //Image image1 = cell.setImage(new URI("file:/c:/image.jpg")); }
     */
    private static void addTitlePage(TextDocument outputDocument) throws Exception {

        addLines(outputDocument, 2);

        Paragraph para = outputDocument.addParagraph(null);

        // add company logo
        addImage(para, extension.getParams().getLogoFileName(), 0);

        addLines(outputDocument, 4);
        // Lets write a big header
        para = outputDocument.addParagraph(null);

        para.setTextContent(extension.getParams().getTitleReport());
        para.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
        para.setFont(fontTitleTextReport);

        addLines(outputDocument, 4);
        para = outputDocument.addParagraph(null);
        para.setTextContent(extension.getParams().getCustomerName());
        para.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
        para.setFont(fontTitleTextReport);

        addLines(outputDocument, 15);

        Table table = outputDocument.addTable(2, 1);

        Cell cell = table.getCellByPosition(0, 0);
        cell.setStringValue(
                extension
                        .getMessages()
                        .getString("alertreport.export.message.export.pdf.confidential"));
        cell.setFont(fontSmallBold);
        String color = Color.toSixDigitHexRGB("#87cefa");
        cell.setCellBackgroundColor(Color.valueOf(color));
        Cell cell1 = table.getCellByPosition(0, 1);
        cell1.setStringValue(extension.getParams().getConfidentialText());
        cell1.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
        cell1.setFont(fontSmall);

        // outputDocument.addPageBreak();

    }

    /**
     * Add image a Paragraph
     *
     * @param paragraph
     * @param imagePath
     * @param scalePercent
     * @throws URISyntaxException
     */
    private static void addImage(Paragraph paragraph, String imagePath, float scalePercent) {
        try {
            if (!imagePath.isEmpty()) {
                Image image1 = Image.newImage(paragraph, new URI("file:///" + imagePath));
                image1.setHorizontalPosition(FrameHorizontalPosition.CENTER);
                FrameStyleHandler handler = image1.getStyleHandler();
                handler.setAchorType(AnchorType.TO_FRAME);
                Border border =
                        new Border(Color.BLACK, 1, StyleTypeDefinitions.SupportedLinearMeasure.PT);
                handler.setBorders(border, CellBordersType.ALL_FOUR);
                handler.setHorizontalRelative(HorizontalRelative.PARAGRAPH_START_MARGIN);
                handler.setVerticalRelative(VerticalRelative.TEXT);
            }
        } catch (URISyntaxException e) {
            logger.error(e.getMessage(), e);
        }
    }

    /**
     * get content field alert from property default extension
     *
     * @param pluginId
     * @param key
     * @param contentDefault
     * @param extensionExport
     * @return
     */
    private static String getFieldAlertProperty(
            Integer pluginId,
            String key,
            String contentDefault,
            ExtensionAlertReportExport extensionExport) {
        if (key.contains("risk") || key.contains("reliability")) {
            return getMessage(
                    extensionExport, "alertreport.export.pluginid." + key, contentDefault);
        }
        StringBuilder sbKey = new StringBuilder(50);
        sbKey.append("alertreport.export.pluginid.");
        sbKey.append(pluginId);
        sbKey.append('.');
        sbKey.append(key);

        return getMessage(extensionExport, sbKey.toString(), contentDefault);
    }

    private static String getMessage(
            ExtensionAlertReportExport extensionExport, String key, String defaultValue) {
        if (extensionExport.getMessages().containsKey(key)) {
            return extensionExport.getMessages().getString(key);
        }
        return defaultValue;
    }

    private static void addContent(TextDocument outputDocument, java.util.List<Alert> alerts)
            throws Exception {
        outputDocument.addPageBreak();

        Alert alert = alerts.get(0);
        // Title Alert
        Paragraph para = outputDocument.addParagraph(null);

        Table table = outputDocument.addTable(1, 1);
        Cell cell = table.getCellByPosition(0, 0);
        Border border = new Border(Color.BLACK, 0, StyleTypeDefinitions.SupportedLinearMeasure.PT);
        cell.setBorders(CellBordersType.NONE, border);
        cell.setStringValue(alert.getName());
        cell.setFont(fontTitleBold);
        String color = Color.toSixDigitHexRGB("#87cefa");
        cell.setCellBackgroundColor(Color.valueOf(color));

        addLines(outputDocument, 1);
        // add title description
        para =
                outputDocument.addParagraph(
                        extension
                                .getMessages()
                                .getString("alertreport.export.message.export.pdf.description"));
        para.setFont(fontTitleBold);
        para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
        addLines(outputDocument, 1);
        // add description
        para =
                outputDocument.addParagraph(
                        getFieldAlertProperty(
                                alert.getPluginId(),
                                "description",
                                alert.getDescription(),
                                extension));
        para.setFont(fontText);
        para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);

        addLines(outputDocument, 1);

        // add title risk
        para =
                outputDocument.addParagraph(
                        extension
                                .getMessages()
                                .getString("alertreport.export.message.export.pdf.risk"));
        para.setFont(fontTitleBold);
        para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
        addLines(outputDocument, 1);
        // add risk
        para =
                outputDocument.addParagraph(
                        getFieldAlertProperty(
                                alert.getPluginId(),
                                "risk." + String.valueOf(alert.getRisk()),
                                Alert.MSG_RISK[alert.getRisk()],
                                extension));
        para.setFont(fontText);
        para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
        addLines(outputDocument, 1);
        // add title reability
        para =
                outputDocument.addParagraph(
                        extension
                                .getMessages()
                                .getString("alertreport.export.message.export.pdf.reability"));
        para.setFont(fontTitleBold);
        para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
        addLines(outputDocument, 1);
        // add reability
        para =
                outputDocument.addParagraph(
                        getFieldAlertProperty(
                                alert.getPluginId(),
                                "reliability." + String.valueOf(alert.getConfidence()),
                                Alert.MSG_CONFIDENCE[alert.getConfidence()],
                                extension));
        para.setFont(fontText);
        para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
        addLines(outputDocument, 1);
        // add title urls
        para =
                outputDocument.addParagraph(
                        extension
                                .getMessages()
                                .getString("alertreport.export.message.export.pdf.urls"));
        para.setFont(fontTitleBold);
        para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);

        // write all url with the same pluginid
        for (int i = 0; i < alerts.size(); i++) {
            Alert alertAux = alerts.get(i);
            // add url link and attack
            para = outputDocument.addParagraph((i + 1) + "-" + alertAux.getUri());
            para.setFont(fontText);
            para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
            para.applyHyperlink(new URI(alertAux.getUri()));

            if (!alertAux.getParam().isEmpty()) {
                para =
                        outputDocument.addParagraph(
                                extension
                                                .getMessages()
                                                .getString(
                                                        "alertreport.export.message.export.pdf.parameters")
                                        + ": "
                                        + alertAux.getParam());
                para.setFont(fontText);
                para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
                addLines(outputDocument, 1);
            }
            if (alertAux.getAttack() != null && !alertAux.getAttack().isEmpty()) {
                para =
                        outputDocument.addParagraph(
                                extension
                                        .getMessages()
                                        .getString("alertreport.export.message.export.pdf.attack"));
                para.setFont(fontTitleBold);
                para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
                para = outputDocument.addParagraph(alertAux.getAttack());
                para.setFont(fontText);
                para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
                addLines(outputDocument, 1);
            }
            if (alertAux.getEvidence() != null && !alertAux.getEvidence().isEmpty()) {
                para =
                        outputDocument.addParagraph(
                                extension
                                        .getMessages()
                                        .getString(
                                                "alertreport.export.message.export.pdf.evidence"));
                para.setFont(fontTitleBold);
                para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
                para = outputDocument.addParagraph(alertAux.getEvidence());
                para.setFont(fontText);
                para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
                addLines(outputDocument, 1);
            }
            // add images test
            addLines(outputDocument, 1);
            String images = alertAux.getOtherInfo();
            if (!images.isEmpty()) {
                String[] list = images.split("\n");
                int imageCount = 1;
                // for (int j = 0, length = list.length/2;j <= length; j += 1) {
                for (int j = 0; j < list.length; j++) {
                    if (!((j + 1) >= list.length)) {
                        String step = list[j];
                        para = outputDocument.addParagraph(step);
                        para.setFont(fontText);
                        para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
                        addLines(outputDocument, 1);
                        // add step and image
                        String imageName = "";
                        String path = extension.getParams().getWorkingDirImages();
                        if (((j + 1) < list.length) && (!list[j + 1].isEmpty())) {
                            imageName = list[j + 1];
                            // if exist an image
                            try {
                                if ((imageName.endsWith(".png") || imageName.endsWith(".jpg"))
                                        && (!path.isEmpty())) {
                                    para = outputDocument.addParagraph(null);
                                    para.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
                                    addImage(para, path + "/" + imageName, 60f);
                                    addLines(outputDocument, 1);
                                    para =
                                            outputDocument.addParagraph(
                                                    extension
                                                                    .getMessages()
                                                                    .getString(
                                                                            "alertreport.export.message.export.pdf.image")
                                                            + ": "
                                                            + Integer.toString(imageCount));
                                    para.setFont(fontText);
                                    para.setHorizontalAlignment(HorizontalAlignmentType.CENTER);
                                    imageCount++;
                                } else {
                                    para = outputDocument.addParagraph(imageName);
                                    para.setFont(fontText);
                                    para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
                                    addLines(outputDocument, 1);
                                }
                            } catch (Exception e) {
                                logger.error(e.getMessage(), e);
                            }
                        }
                        j++;
                    }
                }
            }

            addLines(outputDocument, 1);
        }

        if (!alert.getSolution().equals("")) {
            addLines(outputDocument, 1);
            para =
                    outputDocument.addParagraph(
                            extension
                                    .getMessages()
                                    .getString("alertreport.export.message.export.pdf.solution"));
            para.setFont(fontTitleBold);
            para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
            para =
                    outputDocument.addParagraph(
                            getFieldAlertProperty(
                                    alert.getPluginId(),
                                    "solution",
                                    alert.getSolution(),
                                    extension));
            para.setFont(fontText);
            para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
        }
        if (!alert.getReference().equals("")) {
            addLines(outputDocument, 1);
            para =
                    outputDocument.addParagraph(
                            extension
                                    .getMessages()
                                    .getString("alertreport.export.message.export.pdf.references"));
            para.setFont(fontTitleBold);
            para.setHorizontalAlignment(HorizontalAlignmentType.LEFT);
            para = outputDocument.addParagraph(alert.getReference());
            para.setFont(fontText);
            para.setHorizontalAlignment(HorizontalAlignmentType.JUSTIFY);
        }
        addLines(outputDocument, 1);
    }
}
