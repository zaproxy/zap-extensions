/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.exportreport.export;

import java.awt.Graphics2D;
import java.awt.GridLayout;
import java.awt.RenderingHints;
import java.awt.geom.Point2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.imageio.ImageIO;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import org.apache.log4j.Logger;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.edit.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.xobject.PDPixelMap;
import org.apache.pdfbox.pdmodel.graphics.xobject.PDXObjectImage;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.extension.exportreport.ExtensionExportReport;
import org.zaproxy.zap.utils.DisplayUtils;

/** Export Alerts to a PDF report */
public class ReportExportPDF {

    private static final Logger logger = Logger.getLogger(ReportExportPDF.class);

    private enum TextJustification {
        LEFT,
        RIGHT,
        CENTRE
    }

    private static final PDRectangle pageSize = PDPage.PAGE_SIZE_A4;

    /**
     * holds font, font size, and formatting information
     *
     * @author 70pointer@gmail.com
     */
    private static class Formatting {
        private final PDFont font; // also contains the font formatting info (bold, italics, etc.)
        private final int fontSize;
        private final TextJustification textJustification;

        Formatting(PDFont font, int fontSize, TextJustification textJustification) {
            this.font = font;
            this.fontSize = fontSize;
            this.textJustification = textJustification;
        }

        public PDFont getFont() {
            return font;
        }

        public int getFontSize() {
            return fontSize;
        }

        public TextJustification getTextJustification() {
            return textJustification;
        }
    }

    // various formatting used in the report
    private static final Formatting titlePageHeader1Formatting =
            new Formatting(PDType1Font.TIMES_BOLD, 28, TextJustification.CENTRE);
    private static final Formatting titlePageHeader2Formatting =
            new Formatting(PDType1Font.TIMES_BOLD, 18, TextJustification.CENTRE);
    private static final Formatting alertCategoryLabelFormatting =
            new Formatting(PDType1Font.TIMES_BOLD, 20, TextJustification.LEFT);
    private static final Formatting alertLabelFormatting =
            new Formatting(PDType1Font.TIMES_BOLD, 16, TextJustification.LEFT);
    private static final Formatting alertTextFormatting =
            new Formatting(PDType1Font.TIMES_ROMAN, 12, TextJustification.LEFT);
    private static final Formatting textFormatting =
            new Formatting(PDType1Font.TIMES_ROMAN, 12, TextJustification.LEFT);
    private static final Formatting smallLabelFormatting =
            new Formatting(PDType1Font.TIMES_BOLD, 12, TextJustification.LEFT);
    private static final Formatting smallPrintFormatting =
            new Formatting(PDType1Font.TIMES_ROMAN, 8, TextJustification.LEFT); // not bold

    /**
     * Since PDFBox does all insertions at a named point, and does not handle any of the text
     * wrapping or pagination we need to calculate and update the insert point as we go
     */
    private Point2D.Float textInsertionPoint;

    /** the PDF document being updated with content */
    private PDDocument document;

    /**
     * Again, since PDFBox does not handle the pagination for us, we need to handle it. The addText
     * method will update the page when the addition of text pushes the text onto a new page
     */
    private PDPage page;

    /** a page margin, into which we will not place any content */
    private static int marginPoints =
            (int) ((72f / 25.4f) * 10); // a 10mm margin, expressed in points

    public ReportExportPDF() {
        super();
    }

    /**
     * export the alerts to the named file, using the options specified
     *
     * @param alerts
     * @param fileName
     * @param extensionExport
     * @return
     */
    public boolean exportAlert(
            java.util.List<java.util.List<Alert>> alerts,
            String fileName,
            ExtensionExportReport extensionExport,
            ViewDelegate view) {

        boolean successfulExport;
        // Used to define gridlayout and window size
        final boolean includeHttp = includeHttpInfo(extensionExport);

        /*
         * Generate progress window if view != null
         */
        JProgressBar progBar = null;
        JFrame frame = null;

        // Open a progress window indicating it may take a few moments to generate
        if (view != null) {
            // Setup frame
            frame =
                    new JFrame(
                            extensionExport
                                    .getMessages()
                                    .getString("exportreport.export.progress.title"));
            frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);

            if (includeHttp) {
                frame.setSize(460, 100);
            } else {
                frame.setSize(400, 85);
            }

            frame.setResizable(false);

            // Components
            final JLabel labelString =
                    new JLabel(
                            extensionExport
                                    .getMessages()
                                    .getString("exportreport.export.message.progress"));
            final JLabel labelStringHTTPContent =
                    new JLabel(
                            extensionExport
                                    .getMessages()
                                    .getString("exportreport.export.message.httpmessage.warning"));

            // Label Alignment
            labelString.setHorizontalAlignment(JLabel.CENTER);
            labelStringHTTPContent.setHorizontalAlignment(JLabel.CENTER);

            // Set window icon and position
            frame.setIconImages(DisplayUtils.getZapIconImages());
            frame.setLocationRelativeTo(SwingUtilities.getWindowAncestor(frame));

            // setup progress bar
            progBar = new JProgressBar();
            progBar.setMinimum(0);
            progBar.setMaximum(alerts.size());
            progBar.setValue(0);

            // setup window layout
            if (includeHttp) {
                frame.setLayout(new GridLayout(3, 1));
            } else {
                frame.setLayout(new GridLayout(2, 1));
            }

            // Add Components
            frame.getContentPane().add(labelString);

            // add the warning for http content generation if it is to be included
            if (includeHttp) {
                frame.getContentPane().add(labelStringHTTPContent);
            }

            frame.getContentPane().add(progBar);

            // Show window
            frame.setVisible(true);

            try {
                // Allow the window to open before starting the generation
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                logger.debug(ex);
            }
        } else {
            CommandLine.info(
                    extensionExport
                            .getMessages()
                            .getString("exportreport.export.message.progress"));

            // add the warning for http content generation if it is to be included
            if (includeHttp) {
                CommandLine.info(
                        extensionExport
                                .getMessages()
                                .getString("exportreport.export.message.httpmessage.warning"));
            }
        }

        /*
         * Generate the report
         */
        document = new PDDocument();
        File outputfile = new File(fileName);

        try {
            // add the PDF metadata and title page in code
            addMetaData(extensionExport);
            addTitlePage(extensionExport);

            // add the alert content for each of the alert categories in turn
            for (int i = 0; i < alerts.size(); i++) {
                java.util.List<Alert> alertAux = alerts.get(i);

                // Update progress bar if in GUI
                if (view != null) {
                    progBar.setValue(i);
                }

                addContent(alertAux, extensionExport);
            }

            if (view != null) {
                progBar.setValue(alerts.size());
            }

            // Finalize the document
            document.save(outputfile);
            document.close();

            // return value indicating the export was successful
            successfulExport = true;

        } catch (Exception e) {
            logger.error("An error occurred trying to generate a Report PDF: " + e, e);

            // return value indicating the export failed
            successfulExport = false;

        } finally {
            // close the progress window if in GUI
            if (view != null) {
                frame.setVisible(false);
                frame.dispose();
                frame = null;
            }
        }

        return successfulExport;
    }

    /**
     * Determines if the HTTP information was requested to be included.
     *
     * @param extensionExport
     * @return
     */
    private boolean includeHttpInfo(ExtensionExportReport extensionExport) {
        ArrayList<String> detailsToInclude = extensionExport.getIncludedAlertDetails();

        if (detailsToInclude.contains(
                        extensionExport
                                .getMessages()
                                .getString("exportreport.details.requestheader.label"))
                || detailsToInclude.contains(
                        extensionExport
                                .getMessages()
                                .getString("exportreport.details.requestbody.label"))
                || detailsToInclude.contains(
                        extensionExport
                                .getMessages()
                                .getString("exportreport.details.responseheader.label"))
                || detailsToInclude.contains(
                        extensionExport
                                .getMessages()
                                .getString("exportreport.details.responsebody.label"))) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Joins similar alerts to reduce output size
     *
     * @param extension
     * @return
     */
    public java.util.List<List<Alert>> joinSimilarAlerts(ExtensionExportReport extension) {
        // Make list of all alerts, joining same alerts
        java.util.List<List<Alert>> alerts = new ArrayList<>();
        java.util.List<Alert> allAlerts = extension.getAllAlerts();
        Collections.sort(allAlerts, Collections.reverseOrder());

        // join same alerts
        for (int i = 0; i < allAlerts.size(); i++) {
            Alert alertAllAlerts = allAlerts.get(i);
            alerts.add(extension.getAlertsSelected(alertAllAlerts));
            for (int j = 0; j < allAlerts.size(); j++) {
                Alert alertToCompare = allAlerts.get(j);
                if (alertAllAlerts.getName().equals(alertToCompare.getName())) {
                    allAlerts.remove(j);
                    j = 0;
                }
            }
            i = 0;
        }

        return alerts;
    }

    /**
     * Removes all alerts which have a risk level not to be included
     *
     * @param extension
     * @param alerts
     * @return
     */
    public java.util.List<List<Alert>> filterAlertsByRiskLevel(
            ExtensionExportReport extension, List<List<Alert>> alerts) {
        /*
         * Output list modifications:
         *  - Remove alerts that are not to be included based on risk names
         *  - If the alert is included, remove details that are not to be included
         */
        ArrayList<String> selectedRisks = extension.getIncludedAlertSeverity();
        ArrayList<String> alertRisks = extension.getAlertSeverity();

        for (int i = alerts.size() - 1; i >= 0; i--) {
            List<Alert> alertList = alerts.get(i);

            for (int j = alertList.size() - 1; j >= 0; j--) {
                Alert alert = alertList.get(j);

                if (!selectedRisks.contains(alertRisks.get(alert.getRisk()))) {
                    alertList.remove(j);
                }
            }

            // Remove any alert lists which contain no alerts
            if (alerts.get(i).size() == 0) {
                alerts.remove(i);
            }
        }

        return alerts;
    }

    /**
     * adds PDF metadata to the PDF document
     *
     * @param extensionExport
     */
    private void addMetaData(ExtensionExportReport extensionExport) {
        PDDocumentInformation docInfo = document.getDocumentInformation();
        docInfo.setTitle(extensionExport.extensionGetTitle());
        docInfo.setSubject(extensionExport.extensionGetFor());
        docInfo.setKeywords("");
        docInfo.setAuthor(extensionExport.extensionGetBy());
        docInfo.setCreator(extensionExport.extensionGetBy());
        docInfo.setProducer("OWASP ZAP");
    }

    /**
     * add a title page to the PDF document
     *
     * @param extensionExport
     * @throws IOException
     */
    private void addTitlePage(ExtensionExportReport extensionExport) throws IOException {

        page = new PDPage(pageSize);
        document.addPage(page);

        // calculate initial positioning on the page (origin = bottom left)
        textInsertionPoint =
                new Point2D.Float(
                        page.findMediaBox().getLowerLeftX() + marginPoints,
                        page.findMediaBox().getUpperRightY() - marginPoints);

        /*
         * TODO: Removed for the time being to adapt class to ExportReport (to be reimplemented).
         */
        // draw the logo at 40% size.
        // textInsertionPoint = addImage(extensionExport.getParams().getLogoFileName(), 40f,
        // textInsertionPoint);

        for (int i = 0; i < 4; i++) {
            textInsertionPoint = addText(textFormatting, " ", textInsertionPoint);
        }
        textInsertionPoint =
                addText(
                        titlePageHeader1Formatting,
                        extensionExport.extensionGetTitle(),
                        textInsertionPoint);
        for (int i = 0; i < 3; i++) {
            textInsertionPoint = addText(textFormatting, " ", textInsertionPoint);
        }
        textInsertionPoint =
                addText(
                        titlePageHeader2Formatting,
                        extensionExport.extensionGetFor(),
                        textInsertionPoint);
        for (int i = 0; i < 15; i++) {
            textInsertionPoint = addText(textFormatting, " ", textInsertionPoint);
        }

        /*
         * TODO: Reimplement the confidentiality message support. This was previously set through the options of alertReport
         */
        /*
        textInsertionPoint =
                addText(
                        smallLabelFormatting,
                        extensionExport
                                .getMessages()
                                .getString("exportreport.export.message.pdf.confidential"),
                        textInsertionPoint);
        textInsertionPoint =
                addText(
                        smallPrintFormatting,
                        extensionExport.getParams().getConfidentialText(),
                        textInsertionPoint);
        */
    }

    /**
     * Add the specified text to the PDF document, using the specified formatting, and continuing
     * from the specified text insertion point. The method will handle all text wrapping and
     * pagination, in order to keep all of the text within the page body, and off the margin. New
     * pages will be added by the method, if required.
     *
     * @param formatting
     * @param text
     * @param textInsertionPoint
     * @return
     * @throws IOException
     */
    private Point2D.Float addText(
            Formatting formatting, String text, Point2D.Float textInsertionPoint)
            throws IOException {
        // handles the case where an alert category falls off the end of a page (this is not
        // automatically handled by the pdfbox library)

        PDPageContentStream contentStream = new PDPageContentStream(document, page, true, true);
        // contentStream.moveTo (0,0);
        contentStream.beginText();
        contentStream.setFont(formatting.getFont(), formatting.getFontSize());

        float pageWidthPoints = page.getMediaBox().getWidth();
        float usableWidthPoints = pageWidthPoints - (marginPoints * 2);
        // all text must be drawn at a y pos > this value to be off the margin, and on the page
        // (note: the origin is at bottom left of the page)
        float textYMinThreshold = marginPoints;

        float previousX = 0, previousY = 0;
        float xoffset = 0, yoffset = 0;
        List<String> textByLine = splitTextForWidth(text, formatting, usableWidthPoints);
        for (String lineOfText : textByLine) {
            // calculate the x position, depending on the justification
            // the font size (which is measured in points) needs to feed into the calculation of the
            // y position.
            // it isn't known until now, and could be different for each distinct piece of text
            float textWidthInPoints =
                    formatting.getFontSize()
                            * formatting.getFont().getStringWidth(lineOfText)
                            / 1000;
            switch (formatting.getTextJustification()) {
                case LEFT:
                    xoffset = (float) textInsertionPoint.getX() - previousX;
                    yoffset =
                            (float) textInsertionPoint.getY()
                                    - formatting.getFontSize()
                                    - previousY;
                    previousX = (float) textInsertionPoint.getX();
                    previousY = (float) textInsertionPoint.getY() - formatting.getFontSize();
                    break;
                case RIGHT:
                    xoffset = pageWidthPoints - textWidthInPoints - previousX;
                    yoffset =
                            (float) textInsertionPoint.getY()
                                    - formatting.getFontSize()
                                    - previousY;
                    previousX = pageWidthPoints - textWidthInPoints;
                    previousY = (float) textInsertionPoint.getY() - formatting.getFontSize();
                    break;
                case CENTRE:
                    xoffset = (pageWidthPoints - textWidthInPoints) / 2 - previousX;
                    yoffset =
                            (float) textInsertionPoint.getY()
                                    - formatting.getFontSize()
                                    - previousY;
                    previousX = (pageWidthPoints - textWidthInPoints) / 2;
                    previousY = (float) textInsertionPoint.getY() - formatting.getFontSize();
                    break;
                default:
                    throw new IOException(
                            "Unsupported text justification option: "
                                    + formatting.textJustification);
            }

            float absoluteY = (float) textInsertionPoint.getY() - formatting.getFontSize();
            if (absoluteY < textYMinThreshold) {
                // close off the current page
                contentStream.endText();
                contentStream.saveGraphicsState();
                contentStream.close();

                // and start a new page..
                page = new PDPage(pageSize);
                document.addPage(page);
                contentStream = new PDPageContentStream(document, page, true, true);
                contentStream.beginText();
                contentStream.setFont(formatting.getFont(), formatting.getFontSize());

                // calculate initial positioning on the page (origin = bottom left)
                textInsertionPoint = getPageInitialInsertionPoint();
                // for a new new page, the offset is from 0,0, so it needs to be re-calculated from
                // the origin, not from the "previous" position on the page
                xoffset = (float) textInsertionPoint.getX();
                yoffset = (float) textInsertionPoint.getY() - formatting.getFontSize();
                previousY = yoffset;
            }

            // move from the previous text position (within the beginText() + endText()) by the
            // appropriate delta..
            // and draw..
            contentStream.moveTextPositionByAmount(xoffset, yoffset);
            contentStream.drawString(lineOfText);

            // update the text insertion point for the next line, using 1.5 spacing..
            textInsertionPoint =
                    new Point2D.Float(
                            (float) textInsertionPoint.getX(),
                            (float) textInsertionPoint.getY() - (formatting.getFontSize() * 1.5f));
        }

        contentStream.endText();
        contentStream.saveGraphicsState();
        contentStream.close();

        return textInsertionPoint;
    }

    /**
     * split the text into chunks that will fit on the page width, given the text formatting. Handle
     * newlines in the text. If necessary, but only as a final resort, split the text in the middle
     * of a long word. First tries to split using spaces.
     *
     * @param text
     * @param formatting
     * @param maxWidthInPoints
     * @return
     * @throws IOException
     */
    private List<String> splitTextForWidth(
            String text, Formatting formatting, float maxWidthInPoints) throws IOException {
        List<String> lines = new ArrayList<String>();
        int lastSpace = -1;
        while (text.length() > 0) {
            // before we get into looking at breaking based on spaces, find the next newline, and
            // determine if it occurs
            // within the current line of text.  If it does, add the portion before the newline as a
            // line in itself,
            // and re-start the logic from the character after the newline
            int newlineIndex = text.indexOf('\n');
            if (newlineIndex > -1) {
                String toNewlineSubString = text.substring(0, newlineIndex);
                float toNewlineTextWidth =
                        formatting.getFontSize()
                                * formatting.getFont().getStringWidth(toNewlineSubString)
                                / 1000;
                if (toNewlineTextWidth <= maxWidthInPoints) {
                    lines.add(toNewlineSubString);
                    if (text.length() > (newlineIndex + 1)) text = text.substring(newlineIndex + 1);
                    else text = "";
                    lastSpace = -1;
                    continue; // to the next iteration
                }
            }

            // there are no newlines within the current available width.
            // base case: does the full text fits in a single line? if so, just add it as is.
            float fulltextWidth =
                    formatting.getFontSize() * formatting.getFont().getStringWidth(text) / 1000;
            if (fulltextWidth <= maxWidthInPoints) {
                lines.add(text);
                text = "";
                lastSpace = -1;
                continue;
            }

            // inductive cases
            int spaceIndex = text.indexOf(' ', lastSpace + 1);
            String subString = spaceIndex < 0 ? text : text.substring(0, spaceIndex);
            float textWidth =
                    formatting.getFontSize()
                            * formatting.getFont().getStringWidth(subString)
                            / 1000;
            if (textWidth > maxWidthInPoints) {
                if (lastSpace < 0) {
                    lastSpace =
                            getIndexOfSubtringThatFitsWithinWidth(
                                    subString, maxWidthInPoints, formatting);
                    subString = text.substring(0, lastSpace);
                    lines.add(subString);
                    text =
                            text.substring(
                                    lastSpace); // don't chop off the character at the position
                    lastSpace = -1;
                    continue; // to the next iteration
                } else {
                    subString = text.substring(0, lastSpace);
                    lines.add(subString);
                    text =
                            text.substring(lastSpace)
                                    .trim(); // do chop off the character at the position
                    lastSpace = -1;
                }
            } else {
                // track the location of the space we were looking at, and loop to the next word
                // break (in the next iteration)
                lastSpace = spaceIndex;
            }
        }
        return lines;
    }

    /**
     * calculate the index of a substring that will fit within the specified width. Does nor look at
     * the specific characters used at all.
     *
     * @param subString
     * @param maxWidthInPoints
     * @return
     * @throws IOException
     */
    private int getIndexOfSubtringThatFitsWithinWidth(
            String subString, float maxWidthInPoints, Formatting formatting) throws IOException {
        for (int testLength = 1; testLength <= subString.length(); testLength++) {
            float textWidth =
                    formatting.getFontSize()
                            * formatting
                                    .getFont()
                                    .getStringWidth(subString.substring(0, testLength))
                            / 1000;
            if (textWidth > maxWidthInPoints) {
                return testLength - 1;
            }
        }
        return subString.length();
    }

    /**
     * Adds the image to the PDF document at the insertion point, first scaling the image as
     * necessary For now, the image is centred on the line, and no other content is placed on the
     * line. This may change.
     *
     * @param imagePath
     * @param scalePercent
     * @param textInsertionPoint
     * @return
     * @throws IOException
     */
    private Point2D.Float addImage(
            String imagePath, float scalePercent, Point2D.Float textInsertionPoint)
            throws IOException {
        if (!imagePath.isEmpty()) {

            // create the image
            PDXObjectImage image = null;
            BufferedImage awtImage = ImageIO.read(new File(imagePath));
            image = new PDPixelMap(document, awtImage);

            // and scale it
            if (scalePercent != 0) {
                int newWidth = (int) (awtImage.getWidth() * (scalePercent / 100));
                int newHeight = (int) (awtImage.getHeight() * (scalePercent / 100));
                BufferedImage resized = new BufferedImage(newWidth, newHeight, awtImage.getType());
                Graphics2D g = resized.createGraphics();
                g.setRenderingHint(
                        RenderingHints.KEY_INTERPOLATION,
                        RenderingHints.VALUE_INTERPOLATION_BILINEAR);
                g.drawImage(
                        awtImage,
                        0,
                        0,
                        newWidth,
                        newHeight,
                        0,
                        0,
                        awtImage.getWidth(),
                        awtImage.getHeight(),
                        null);
                g.dispose();
                image = new PDPixelMap(document, resized);
            }

            // centre align the image.  Note that the page dimension units here are in points.
            float pageWidthPoints = page.getMediaBox().getWidth();
            float imageWidthInPoints = image.getWidth();

            // apparently this must be created after the image is created, for some reason..
            PDPageContentStream contentStream = new PDPageContentStream(document, page, true, true);

            contentStream.drawImage(
                    image,
                    (pageWidthPoints / 2) - (imageWidthInPoints / 2),
                    (float) textInsertionPoint.getY() - image.getHeight());
            contentStream.close();

            // update the text insertion point after drawing an image
            textInsertionPoint =
                    new Point2D.Float(
                            marginPoints, (float) (textInsertionPoint.getY() - image.getHeight()));
        }

        return textInsertionPoint;
    }

    /**
     * get content for the named alert category, using the key provided, and the default value
     * provided.
     *
     * @param pluginId
     * @param key
     * @param contentDefault
     * @param extensionExport
     * @return
     */
    private static String getFieldAlertProperty(
            int pluginId,
            String key,
            String contentDefault,
            ExtensionExportReport extensionExport) {
        if (key.contains("risk") || key.contains("reliability")) {
            return getMessage(
                    extensionExport, "exportreport.export.pluginid." + key, contentDefault);
        }
        StringBuilder sbKey = new StringBuilder(50);
        sbKey.append("exportreport.export.pluginid.");
        sbKey.append(pluginId);
        sbKey.append('.');
        sbKey.append(key);

        return getMessage(extensionExport, sbKey.toString(), contentDefault);
    }

    /**
     * get a property
     *
     * @param extensionExport
     * @param key
     * @param defaultValue
     * @return
     */
    private static String getMessage(
            ExtensionExportReport extensionExport, String key, String defaultValue) {
        if (extensionExport.getMessages().containsKey(key)) {
            return extensionExport.getMessages().getString(key);
        }
        return defaultValue;
    }

    /**
     * get the initial insertion point on a new page
     *
     * @return
     */
    private Point2D.Float getPageInitialInsertionPoint() {
        return new Point2D.Float(
                page.findMediaBox().getLowerLeftX() + marginPoints,
                page.findMediaBox().getUpperRightY() - marginPoints);
    }

    /**
     * adds content to the PDF report for the list of alerts provided, which are all for the same
     * alert category
     *
     * @param alerts
     * @param extensionExport
     * @throws IOException
     */
    private void addContent(java.util.List<Alert> alerts, ExtensionExportReport extensionExport)
            throws IOException {

        String labelDescription =
                extensionExport.getMessages().getString("exportreport.details.description.label");
        String labelRisk =
                extensionExport.getMessages().getString("exportreport.details.risk.label");
        String labelReliability =
                extensionExport.getMessages().getString("exportreport.details.confidence.label");
        String labelURLs =
                extensionExport.getMessages().getString("exportreport.details.urls.label");
        String labelParameter =
                extensionExport.getMessages().getString("exportreport.details.parameters.label");
        String labelAttack =
                extensionExport.getMessages().getString("exportreport.details.attack.label");
        String labelEvidence =
                extensionExport.getMessages().getString("exportreport.details.evidence.label");
        String labelOtherInfo =
                extensionExport
                        .getMessages()
                        .getString("exportreport.details.otherinformation.label");
        String labelSolution =
                extensionExport.getMessages().getString("exportreport.details.solution.label");
        String labelReferences =
                extensionExport.getMessages().getString("exportreport.details.reference.label");
        String labelCWEID =
                extensionExport.getMessages().getString("exportreport.details.cweid.label");
        String labelWASCID =
                extensionExport.getMessages().getString("exportreport.details.wascid.label");
        String labelReqHeader =
                extensionExport.getMessages().getString("exportreport.details.requestheader.label");
        String labelRespHeader =
                extensionExport
                        .getMessages()
                        .getString("exportreport.details.responseheader.label");
        String labelReqBody =
                extensionExport.getMessages().getString("exportreport.details.requestbody.label");
        String labelRespBody =
                extensionExport.getMessages().getString("exportreport.details.responsebody.label");

        // detailsToInclude is used to filter out details not wanted by the user
        ArrayList<String> detailsToInclude = extensionExport.getIncludedAlertDetails();

        Alert alert = alerts.get(0);

        page = new PDPage(pageSize);
        document.addPage(page);

        // calculate initial positioning on the page (origin = bottom left)
        // Point2D.Float textInsertionPoint = new Point2D.Float(page.findMediaBox().getLowerLeftX()
        // + marginPoints, page.findMediaBox().getUpperRightY() - marginPoints);
        Point2D.Float textInsertionPoint = getPageInitialInsertionPoint();

        textInsertionPoint =
                addText(alertCategoryLabelFormatting, alert.getName(), textInsertionPoint);

        // Not added if not selected as detail to include
        if (detailsToInclude.contains(
                extensionExport
                        .getMessages()
                        .getString("exportreport.details.description.label"))) {
            textInsertionPoint =
                    addText(alertLabelFormatting, labelDescription, textInsertionPoint);
            textInsertionPoint =
                    addText(
                            alertTextFormatting,
                            getFieldAlertProperty(
                                    alert.getPluginId(),
                                    "description",
                                    alert.getDescription(),
                                    extensionExport),
                            textInsertionPoint);
            textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
        }

        textInsertionPoint = addText(alertLabelFormatting, labelRisk, textInsertionPoint);
        textInsertionPoint =
                addText(
                        alertTextFormatting,
                        getFieldAlertProperty(
                                alert.getPluginId(),
                                "risk." + String.valueOf(alert.getRisk()),
                                Alert.MSG_RISK[alert.getRisk()],
                                extensionExport),
                        textInsertionPoint);
        textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);

        textInsertionPoint = addText(alertLabelFormatting, labelReliability, textInsertionPoint);
        textInsertionPoint =
                addText(
                        alertTextFormatting,
                        getFieldAlertProperty(
                                alert.getPluginId(),
                                "reliability." + String.valueOf(alert.getConfidence()),
                                Alert.MSG_CONFIDENCE[alert.getConfidence()],
                                extensionExport),
                        textInsertionPoint);
        textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);

        // CWE ID
        if (detailsToInclude.contains(
                extensionExport.getMessages().getString("exportreport.details.cweid.label"))) {
            textInsertionPoint = addText(alertLabelFormatting, labelCWEID, textInsertionPoint);
            textInsertionPoint =
                    addText(
                            alertTextFormatting,
                            Integer.toString(alert.getCweId()),
                            textInsertionPoint);

            textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
        }

        // WASC ID
        if (detailsToInclude.contains(
                extensionExport.getMessages().getString("exportreport.details.wascid.label"))) {
            textInsertionPoint = addText(alertLabelFormatting, labelWASCID, textInsertionPoint);
            textInsertionPoint =
                    addText(
                            alertTextFormatting,
                            Integer.toString(alert.getWascId()),
                            textInsertionPoint);
            textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
        }

        // Request Header
        if (detailsToInclude.contains(
                extensionExport
                        .getMessages()
                        .getString("exportreport.details.requestheader.label"))) {
            textInsertionPoint = addText(alertLabelFormatting, labelReqHeader, textInsertionPoint);
            textInsertionPoint =
                    addText(
                            alertTextFormatting,
                            alert.getMessage().getRequestHeader().toString(),
                            textInsertionPoint);
            textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
        }

        // Request Body
        if (detailsToInclude.contains(
                extensionExport
                        .getMessages()
                        .getString("exportreport.details.requestbody.label"))) {
            textInsertionPoint = addText(alertLabelFormatting, labelReqBody, textInsertionPoint);
            textInsertionPoint =
                    addText(
                            alertTextFormatting,
                            alert.getMessage().getRequestBody().toString(),
                            textInsertionPoint);
            textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
        }

        // Response Header
        if (detailsToInclude.contains(
                extensionExport
                        .getMessages()
                        .getString("exportreport.details.responseheader.label"))) {
            textInsertionPoint = addText(alertLabelFormatting, labelRespHeader, textInsertionPoint);
            textInsertionPoint =
                    addText(
                            alertTextFormatting,
                            alert.getMessage().getResponseHeader().toString(),
                            textInsertionPoint);
            textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
        }

        // Response Body
        if (detailsToInclude.contains(
                extensionExport
                        .getMessages()
                        .getString("exportreport.details.responsebody.label"))) {
            textInsertionPoint = addText(alertLabelFormatting, labelRespBody, textInsertionPoint);
            textInsertionPoint =
                    addText(
                            alertTextFormatting,
                            alert.getMessage().getResponseBody().toString(),
                            textInsertionPoint);
            textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
        }

        textInsertionPoint = addText(alertLabelFormatting, labelURLs, textInsertionPoint);

        // TODO: binary data (Base64 decoded data is the only example I can find) flows onto the
        // margin..
        // can we do something about it??

        // for each alert within this category
        for (int i = 0; i < alerts.size(); i++) {
            Alert alertAux = alerts.get(i);

            // output the URL, and parameter information for each alert for this category
            textInsertionPoint =
                    addText(
                            alertTextFormatting,
                            (i + 1) + "-" + alertAux.getUri(),
                            textInsertionPoint);

            if (!alertAux.getParam().isEmpty()) {
                textInsertionPoint =
                        addText(
                                alertTextFormatting,
                                labelParameter + ": " + alertAux.getParam(),
                                textInsertionPoint);
            }
            if (alertAux.getAttack() != null && !alertAux.getAttack().isEmpty()) {
                textInsertionPoint =
                        addText(
                                alertTextFormatting,
                                labelAttack + ": " + alertAux.getAttack(),
                                textInsertionPoint);
            }
            if (alertAux.getEvidence() != null && !alertAux.getEvidence().isEmpty()) {
                textInsertionPoint =
                        addText(
                                alertTextFormatting,
                                labelEvidence + ": " + alertAux.getEvidence(),
                                textInsertionPoint);
            }

            // Not added if not selected as detail to include
            if (detailsToInclude.contains(
                            extensionExport
                                    .getMessages()
                                    .getString("exportreport.details.otherinfo.label"))
                    && !alertAux.getOtherInfo().isEmpty()) {
                textInsertionPoint =
                        addText(
                                alertTextFormatting,
                                labelOtherInfo + ": " + alertAux.getOtherInfo(),
                                textInsertionPoint);
            }
            // put a blank line after each URL's worth of information
            textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
        }

        if (detailsToInclude.contains(
                extensionExport.getMessages().getString("exportreport.details.solution.label"))) {
            String solution =
                    getFieldAlertProperty(
                            alert.getPluginId(), "solution", alert.getSolution(), extensionExport);
            if (!solution.isEmpty()) {
                textInsertionPoint =
                        addText(alertLabelFormatting, labelSolution, textInsertionPoint);
                textInsertionPoint =
                        addText(
                                alertTextFormatting,
                                getFieldAlertProperty(
                                        alert.getPluginId(),
                                        "solution",
                                        alert.getSolution(),
                                        extensionExport),
                                textInsertionPoint);
                textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
            }
        }

        if (detailsToInclude.contains(
                        extensionExport
                                .getMessages()
                                .getString("exportreport.details.reference.label"))
                && !alert.getReference().isEmpty()) {
            textInsertionPoint = addText(alertLabelFormatting, labelReferences, textInsertionPoint);
            textInsertionPoint =
                    addText(alertTextFormatting, alert.getReference(), textInsertionPoint);
            textInsertionPoint = addText(alertTextFormatting, " ", textInsertionPoint);
        }
    }
}
