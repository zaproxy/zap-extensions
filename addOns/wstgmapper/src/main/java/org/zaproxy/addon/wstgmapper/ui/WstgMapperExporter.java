/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.wstgmapper.ui;

import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.wstgmapper.CoverageCalculator;
import org.zaproxy.addon.wstgmapper.ReportGenerator;
import org.zaproxy.addon.wstgmapper.WstgMapperChecklistManager;
import org.zaproxy.addon.wstgmapper.WstgMapperData;
import org.zaproxy.addon.wstgmapper.WstgMapperMappingManager;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;

/**
 * Handles the file-export workflow for the add-on.
 *
 * <p>This class owns the save dialogs, filename normalization, and disk writes so the panel can
 * trigger exports without taking on report-generation or filesystem responsibilities directly.
 */
public class WstgMapperExporter {

    private static final Logger LOGGER = LogManager.getLogger(WstgMapperExporter.class);

    private final ReportGenerator reportGenerator;
    private final WstgMapperData data;
    private final WstgMapperMappingManager mappingManager;
    private final WstgMapperChecklistManager checklistManager;
    private final CoverageCalculator coverageCalculator;

    public WstgMapperExporter(
            ReportGenerator reportGenerator,
            WstgMapperData data,
            WstgMapperMappingManager mappingManager,
            WstgMapperChecklistManager checklistManager,
            CoverageCalculator coverageCalculator) {
        this.reportGenerator = reportGenerator;
        this.data = data;
        this.mappingManager = mappingManager;
        this.checklistManager = checklistManager;
        this.coverageCalculator = coverageCalculator;
    }

    public void export(Component parent) {
        exportMarkdown(parent);
    }

    public void exportMarkdown(Component parent) {
        export(parent, ".md", true);
    }

    public void exportCsv(Component parent) {
        export(parent, ".csv", false);
    }

    public void exportCategoryMarkdown(Component parent, WstgCategory category) {
        exportCategory(parent, category, ".md", true);
    }

    public void exportCategoryCsv(Component parent, WstgCategory category) {
        exportCategory(parent, category, ".csv", false);
    }

    private void export(Component parent, String extension, boolean markdown) {
        JFileChooser chooser = createChooser(markdown, defaultBaseFileName());
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = normalizeFile(chooser.getSelectedFile(), extension);
        if (!confirmOverwrite(parent, file)) {
            return;
        }

        try {
            writeExportFile(file, data, coverageCalculator, markdown);
            JOptionPane.showMessageDialog(
                    parent,
                    Constant.messages.getString(
                            "wstgmapper.export.success.message", file.getAbsolutePath()),
                    Constant.messages.getString("wstgmapper.export.success.title"),
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            LOGGER.error("Failed to export WSTG Mapper report.", e);
            JOptionPane.showMessageDialog(
                    parent,
                    Constant.messages.getString("wstgmapper.export.error.message", e.getMessage()),
                    Constant.messages.getString("wstgmapper.export.error.title"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportCategory(
            Component parent, WstgCategory category, String extension, boolean markdown) {
        JFileChooser chooser =
                createChooser(markdown, category.getId().toLowerCase() + "-wstgmapper");
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = normalizeFile(chooser.getSelectedFile(), extension);
        if (!confirmOverwrite(parent, file)) {
            return;
        }

        try {
            WstgMapperData categoryData = new WstgMapperData(java.util.List.of(category));
            CoverageCalculator categoryCoverage =
                    new CoverageCalculator(categoryData, checklistManager, mappingManager);
            writeExportFile(file, categoryData, categoryCoverage, markdown);
        } catch (IOException e) {
            LOGGER.error("Failed to export category report.", e);
        }
    }

    private void writeExportFile(
            File file,
            WstgMapperData exportData,
            CoverageCalculator exportCoverage,
            boolean markdown)
            throws IOException {
        String content =
                markdown
                        ? reportGenerator.generateMarkdown(
                                exportData, checklistManager, exportCoverage)
                        : reportGenerator.generateCsv(exportData, checklistManager, exportCoverage);
        Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
    }

    private static JFileChooser createChooser(boolean markdown, String baseFileName) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(Constant.messages.getString("wstgmapper.export.dialog.title"));
        FileNameExtensionFilter markdownFilter =
                new FileNameExtensionFilter(
                        Constant.messages.getString("wstgmapper.export.filter.markdown"), "md");
        FileNameExtensionFilter csvFilter =
                new FileNameExtensionFilter(
                        Constant.messages.getString("wstgmapper.export.filter.csv"), "csv");
        chooser.addChoosableFileFilter(markdownFilter);
        chooser.addChoosableFileFilter(csvFilter);
        chooser.setFileFilter(markdown ? markdownFilter : csvFilter);
        chooser.setSelectedFile(new File(baseFileName + (markdown ? ".md" : ".csv")));
        return chooser;
    }

    private static String defaultBaseFileName() {
        return Constant.messages.getString("wstgmapper.export.default.filename");
    }

    private static File normalizeFile(File file, String extension) {
        String path = file.getAbsolutePath();
        if (!path.toLowerCase().endsWith(extension)) {
            return new File(path + extension);
        }
        return file;
    }

    private static boolean confirmOverwrite(Component parent, File file) {
        if (!file.exists()) {
            return true;
        }
        int choice =
                JOptionPane.showConfirmDialog(
                        parent,
                        Constant.messages.getString(
                                "wstgmapper.export.overwrite.message", file.getName()),
                        Constant.messages.getString("wstgmapper.export.overwrite.title"),
                        JOptionPane.YES_NO_OPTION);
        return choice == JOptionPane.YES_OPTION;
    }
}
