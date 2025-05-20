/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2010 The ZAP Development Team
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
package org.zaproxy.addon.client.ui;

import java.awt.Component;
import java.io.File;
import java.util.Locale;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.commonlib.MenuWeights;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

@SuppressWarnings("serial")
public class PopupMenuExportClientMap extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;
    private static final String YAML_EXT = ".yaml";

    private ExtensionClientIntegration extension;

    /**
     * Constructs a {@code PopupMenuExportClientMap} with the given label and extension.
     *
     * @param label the label of the menu item
     * @param extension the extension to access the model and view, must not be {@code null}.
     * @throws IllegalArgumentException if the given {@code extension} is {@code null}.
     */
    public PopupMenuExportClientMap(String label, ExtensionClientIntegration extension) {
        super(label);

        if (extension == null) {
            throw new IllegalArgumentException("Parameter extension must not be null.");
        }
        this.extension = extension;

        this.addActionListener(e -> performAction());
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        return "treeClient".equals(invoker.getName());
    }

    private void performAction() {
        File file = getOutputFile();
        if (file == null) {
            return;
        }

        extension.exportClientMap(file.getAbsolutePath());
    }

    private File getOutputFile() {
        FileNameExtensionFilter yamlFilesFilter =
                new FileNameExtensionFilter(
                        Constant.messages.getString("client.tree.popup.export.format.yaml"),
                        "yaml");
        WritableFileChooser chooser =
                new WritableFileChooser(extension.getModel().getOptionsParam().getUserDirectory()) {

                    private static final long serialVersionUID = 1L;

                    @Override
                    public void approveSelection() {
                        File file = getSelectedFile();
                        if (file != null) {
                            String filePath = file.getAbsolutePath();

                            setSelectedFile(
                                    new File(
                                            filePath.toLowerCase(Locale.ROOT).endsWith(YAML_EXT)
                                                    ? filePath
                                                    : filePath + YAML_EXT));
                        }

                        super.approveSelection();
                    }
                };

        chooser.addChoosableFileFilter(yamlFilesFilter);
        chooser.setFileFilter(yamlFilesFilter);

        int rc = chooser.showSaveDialog(extension.getView().getMainFrame());
        if (rc == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    @Override
    public int getWeight() {
        return MenuWeights.MENU_CONTEXT_EXPORT_URLS_WEIGHT;
    }
}
