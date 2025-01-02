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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator.Feature;
import java.awt.Component;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.stream.Collectors;
import javax.swing.JFileChooser;
import javax.swing.JTree;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.commonlib.MenuWeights;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

@SuppressWarnings("serial")
public class PopupMenuExportClientMap extends ExtensionPopupMenuItem {

    private static final long serialVersionUID = 1L;
    protected static ExtensionClientIntegration extension;
    private static final String YAML_EXT = ".yaml";
    private static final Logger LOGGER = LogManager.getLogger(PopupMenuExportClientMap.class);
    private static final String STATS_EXPORT_CLIENTMAP =
            ExtensionClientIntegration.PREFIX + ".export.clientmap";

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
        PopupMenuExportClientMap.extension = extension;

        this.addActionListener(e -> performAction());
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if ("treeClient".equals(invoker.getName())) {
            JTree clientTree = (JTree) invoker;
            setEnabled(clientTree.getRowCount() > 1);
            return true;
        }
        return false;
    }

    protected void performAction() {
        File file = getOutputFile();
        if (file == null) {
            return;
        }

        writeClientMap(file);
        Stats.incCounter(STATS_EXPORT_CLIENTMAP);
    }

    protected void writeClientMap(File file) {

        try (BufferedWriter fw = new BufferedWriter(new FileWriter(file, false))) {

            ClientMapWriter.exportClientMap(fw, extension.getClientTree());

        } catch (Exception e1) {
            LOGGER.warn("An error occurred while exporting the Client Map:", e1);
            extension
                    .getView()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "client.tree.popup.export.error", file.getAbsolutePath()));
        }
    }

    protected File getOutputFile() {
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

    final class ClientMapWriter {

        private static final Logger LOGGER = LogManager.getLogger(ClientMapWriter.class);

        private static final String NODE_KEY = "node";
        private static final String ROOT_NODE_NAME = "ClientMap";
        private static final String CHILDREN_KEY = "children";
        private static final String NAME_KEY = "name";
        private static final String URL_KEY = "url";
        private static final String STORAGE_KEY = "isStorage";
        private static final String VISITED_KEY = "visited";

        ClientMapWriter() {}

        public static void exportClientMap(File file) throws IOException {
            try (FileWriter fw = new FileWriter(file, false)) {
                exportClientMap(fw);
            }
        }

        public static void exportClientMap(Writer fw) throws IOException {
            exportClientMap(fw, extension.getClientTree());
        }

        public static void exportClientMap(Writer fw, ClientMap clientMap) throws IOException {
            try (BufferedWriter bw = new BufferedWriter(fw)) {
                outputNode(bw, clientMap.getRoot(), 0);
            }
        }

        private static void outputKV(
                BufferedWriter fw, String indent, boolean first, String key, Object value)
                throws IOException {
            fw.write(indent);
            if (first) {
                fw.write("- ");
            } else {
                fw.write("  ");
            }
            fw.write(key);
            fw.write(": ");
            ObjectMapper mapper =
                    new ObjectMapper(
                            new YAMLFactory()
                                    .disable(Feature.WRITE_DOC_START_MARKER)
                                    .enable(Feature.LITERAL_BLOCK_STYLE));
            fw.write(mapper.writeValueAsString(value));
        }

        private static boolean outputKVIfNotEmpty(
                BufferedWriter fw, String indent, boolean first, String key, Object value)
                throws IOException {
            if (value == null
                    || (value instanceof String strVal && strVal.isEmpty())
                    || (value instanceof Integer num && num.intValue() <= 0)) {
                return first;
            }
            indent = indent + "  ";
            if (value instanceof String strVal) {
                outputKV(fw, indent, first, key, strVal);
                return false;
            } else {
                outputKV(fw, indent, first, key, value);
                return false;
            }
        }

        private static void outputNode(BufferedWriter fw, ClientNode node, int level)
                throws IOException {
            if (node.isStorage()) {
                // Skip storage nodes in the tree
                // Those details are represented as components of their source
                return;
            }
            // We could create a set of data structures and use jackson, but the format is very
            // simple and this is much more memory efficient - it still uses jackson for value
            // output
            String indent = " ".repeat(level * 2);

            outputKV(fw, indent, true, NODE_KEY, level == 0 ? ROOT_NODE_NAME : node.toString());

            outputKV(fw, indent, false, NAME_KEY, node.getUserObject().getName());
            outputKV(fw, indent, false, URL_KEY, node.getUserObject().getUrl());
            outputKV(fw, indent, false, STORAGE_KEY, node.getUserObject().isStorage());
            outputKV(fw, indent, false, VISITED_KEY, node.getUserObject().isVisited());
            if (node.getUserObject().getComponents() != null
                    && !node.getUserObject().getComponents().isEmpty()) {
                fw.write(indent + "  ");
                fw.write("components:\n");

                boolean first = true;

                LinkedHashSet<ClientSideComponent> sortedComponents =
                        node.getUserObject().getComponents().stream()
                                .sorted()
                                .collect(Collectors.toCollection(LinkedHashSet::new));
                for (ClientSideComponent component : sortedComponents) {
                    first = outputKVIfNotEmpty(fw, indent, first, "href", component.getHref());
                    first = outputKVIfNotEmpty(fw, indent, first, "id", component.getId());
                    first =
                            outputKVIfNotEmpty(
                                    fw, indent, first, "tagName", component.getTagName());
                    first =
                            outputKVIfNotEmpty(
                                    fw, indent, first, "tagType", component.getTagType());
                    if (!component.isStorageEvent()) {
                        first = outputKVIfNotEmpty(fw, indent, first, "text", component.getText());
                    }
                    first = outputKVIfNotEmpty(fw, indent, first, "type", component.getType());
                    first =
                            outputKVIfNotEmpty(
                                    fw,
                                    indent,
                                    first,
                                    "typeForDisplay",
                                    component.getTypeForDisplay());
                    first = outputKVIfNotEmpty(fw, indent, first, "formId", component.getFormId());
                    first =
                            outputKVIfNotEmpty(
                                    fw,
                                    indent,
                                    first,
                                    "isStorageEvent",
                                    component.isStorageEvent());
                    first = true;
                }
            }

            Stats.incCounter(STATS_EXPORT_CLIENTMAP + ".node");

            if (node.getChildCount() > 0) {
                fw.write(indent);
                fw.write("  ");
                fw.write(CHILDREN_KEY);
                fw.write(": ");
                fw.newLine();
                node.children()
                        .asIterator()
                        .forEachRemaining(
                                c -> {
                                    try {
                                        outputNode(fw, (ClientNode) c, level + 1);
                                    } catch (IOException e) {
                                        LOGGER.error(e.getMessage(), e);
                                    }
                                });
            }
        }
    }
}
