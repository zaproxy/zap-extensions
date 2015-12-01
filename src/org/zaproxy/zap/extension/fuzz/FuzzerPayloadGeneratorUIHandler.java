/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.swing.GroupLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz.FuzzersDirChangeListener;
import org.zaproxy.zap.extension.fuzz.FuzzerPayloadGeneratorUIHandler.FuzzerPayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.StringPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIPanel;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.view.JCheckBoxTree;
import org.zaproxy.zap.view.JCheckBoxTree.CheckChangeEvent;
import org.zaproxy.zap.view.JCheckBoxTree.CheckChangeEventListener;

public class FuzzerPayloadGeneratorUIHandler implements
        PayloadGeneratorUIHandler<String, StringPayload, FuzzerPayloadGenerator, FuzzerPayloadGeneratorUI> {

    private static final String PAYLOAD_GENERATOR_NAME = Constant.messages.getString("fuzz.payloads.generator.fileFuzzers.name");

    private final ExtensionFuzz extensionFuzz;

    public FuzzerPayloadGeneratorUIHandler(ExtensionFuzz extensionFuzz) {
        this.extensionFuzz = extensionFuzz;
    }

    @Override
    public String getName() {
        return PAYLOAD_GENERATOR_NAME;
    }

    @Override
    public Class<FuzzerPayloadGeneratorUI> getPayloadGeneratorUIClass() {
        return FuzzerPayloadGeneratorUI.class;
    }

    @Override
    public Class<FuzzerPayloadGeneratorUIPanel> getPayloadGeneratorUIPanelClass() {
        return FuzzerPayloadGeneratorUIPanel.class;
    }

    @Override
    public FuzzerPayloadGeneratorUIPanel createPanel() {
        return new FuzzerPayloadGeneratorUIPanel(extensionFuzz);
    }

    public static class FuzzerPayloadGeneratorUI implements PayloadGeneratorUI<String, StringPayload, FuzzerPayloadGenerator> {

        private final List<FuzzerPayloadSource> selectedFuzzers;
        private int numberOfPayloads;

        public FuzzerPayloadGeneratorUI(List<FuzzerPayloadSource> selectedFuzzers) {
            this.selectedFuzzers = Collections.unmodifiableList(new ArrayList<>(selectedFuzzers));
            this.numberOfPayloads = -1;
        }

        public List<FuzzerPayloadSource> getSelectedFuzzers() {
            return selectedFuzzers;
        }

        @Override
        public Class<FuzzerPayloadGenerator> getPayloadGeneratorClass() {
            return FuzzerPayloadGenerator.class;
        }

        @Override
        public String getName() {
            return PAYLOAD_GENERATOR_NAME;
        }

        @Override
        public String getDescription() {
            StringBuilder descriptionBuilder = new StringBuilder();
            for (FuzzerPayloadSource selectedFuzzer : selectedFuzzers) {
                if (descriptionBuilder.length() > 100) {
                    break;
                }
                if (descriptionBuilder.length() > 0) {
                    descriptionBuilder.append(", ");
                }
                descriptionBuilder.append(selectedFuzzer.getName());
            }

            if (descriptionBuilder.length() > 100) {
                descriptionBuilder.setLength(100);
                descriptionBuilder.replace(97, 100, "...");
            }
            return descriptionBuilder.toString();
        }

        @Override
        public long getNumberOfPayloads() {
            if (numberOfPayloads == -1) {
                numberOfPayloads = 0;
                for (FuzzerPayloadSource selectedFuzzer : selectedFuzzers) {
                    numberOfPayloads += selectedFuzzer.getPayloadGenerator().getNumberOfPayloads();
                }
            }
            return numberOfPayloads;
        }

        @Override
        public FuzzerPayloadGenerator getPayloadGenerator() {
            List<PayloadGenerator<String, StringPayload>> generators = new ArrayList<>();
            for (FuzzerPayloadSource selectedFuzzer : selectedFuzzers) {
                generators.add(selectedFuzzer.getPayloadGenerator());
            }
            return new FuzzerPayloadGenerator(generators);
        }

        @Override
        public FuzzerPayloadGeneratorUI copy() {
            return this;
        }

    }

    public static class FuzzerPayloadGeneratorUIPanel implements
            PayloadGeneratorUIPanel<String, StringPayload, FuzzerPayloadGenerator, FuzzerPayloadGeneratorUI> {

        private static final String FILE_FUZZERS_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.fileFuzzers.files.label");
        private static final String PAYLOADS_PREVIEW_FIELD_LABEL = Constant.messages.getString("fuzz.payloads.generator.fileFuzzers.payloadsPreview.label");

        private static final int MAX_NUMBER_PAYLOAD_FUZZERS_PREVIEW = 35;
        private static final int MAX_NUMBER_PAYLOADS_PREVIEW = 30;

        private final ExtensionFuzz extensionFuzz;
        private final FuzzersDirChangeListener fuzzersDirChangeListener;

        private JPanel fieldsPanel;

        private JCheckBoxTree fileFuzzersCheckBoxTree;
        private TreePath defaultCategoryTreePath;
        private JTextArea payloadsPreviewTextArea;

        public FuzzerPayloadGeneratorUIPanel(ExtensionFuzz extensionFuzz) {
            this.extensionFuzz = extensionFuzz;

            this.fuzzersDirChangeListener = new FuzzersDirChangeListener() {

                @Override
                public void fuzzersDirChanged(FuzzersDir fuzzersDir) {
                    createFileFuzzersCheckBoxTreeModel();
                }
            };
            
            fieldsPanel = new JPanel();

            GroupLayout layout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(layout);
            layout.setAutoCreateGaps(true);

            JLabel fileFuzzersLabel = new JLabel(FILE_FUZZERS_FIELD_LABEL);
            fileFuzzersLabel.setLabelFor(getFileFuzzersCheckBoxTree());
            JLabel payloadsPreviewLabel = new JLabel(PAYLOADS_PREVIEW_FIELD_LABEL);
            payloadsPreviewLabel.setLabelFor(getPayloadsPreviewTextArea());

            JScrollPane scrollPane = new JScrollPane(getFileFuzzersCheckBoxTree());
            JScrollPane payloadsPreviewScrollPane = new JScrollPane(getPayloadsPreviewTextArea());

            layout.setHorizontalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(fileFuzzersLabel)
                                            .addComponent(payloadsPreviewLabel))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addComponent(scrollPane)
                                            .addComponent(payloadsPreviewScrollPane)));

            layout.setVerticalGroup(
                    layout.createSequentialGroup()
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(fileFuzzersLabel)
                                            .addComponent(scrollPane))
                            .addGroup(
                                    layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(payloadsPreviewLabel)
                                            .addComponent(payloadsPreviewScrollPane)));
        }

        private JCheckBoxTree getFileFuzzersCheckBoxTree() {
            if (fileFuzzersCheckBoxTree == null) {
                fileFuzzersCheckBoxTree = new JCheckBoxTree();
                fileFuzzersCheckBoxTree.setRootVisible(false);
                fileFuzzersCheckBoxTree.setShowsRootHandles(true);
                fileFuzzersCheckBoxTree.addCheckChangeEventListener(new CheckChangeEventListener() {

                    @Override
                    public void checkStateChanged(CheckChangeEvent e) {
                        updatePayloadsPreviewTextArea();
                    }
                });
                fileFuzzersCheckBoxTree.setVisibleRowCount(10);

                createFileFuzzersCheckBoxTreeModel();
            }
            return fileFuzzersCheckBoxTree;
        }

        private void createFileFuzzersCheckBoxTreeModel() {
            List<FuzzerPayloadSource> currentSelections = getSelectedFuzzers();

            DefaultMutableTreeNode root = new DefaultMutableTreeNode();
            for (FuzzerPayloadCategory category : extensionFuzz.getFuzzersDir().getCategories()) {
                addNodes(category, root);
            }

            fileFuzzersCheckBoxTree.setModel(new DefaultTreeModel(root));
            // Following two statements are a hack to make the check boxes of the nodes to render correctly
            fileFuzzersCheckBoxTree.expandAll();
            fileFuzzersCheckBoxTree.collapseAll();

            TreePath treePath = null;
            if (!extensionFuzz.getFuzzOptions().isCustomDefaultCategory()) {
                String defaultCategory = extensionFuzz.getFuzzOptions().getDefaultCategoryName();
                root = (DefaultMutableTreeNode) fileFuzzersCheckBoxTree.getModel().getRoot();
                @SuppressWarnings("unchecked")
                Enumeration<DefaultMutableTreeNode> nodes = root.breadthFirstEnumeration();
                while (nodes.hasMoreElements()) {
                    DefaultMutableTreeNode node = nodes.nextElement();
                    Object object = node.getUserObject();
                    if (object instanceof FuzzerPayloadCategory) {
                        if (defaultCategory.equals(((FuzzerPayloadCategory) object).getFullName())) {
                            treePath = new TreePath(node.getPath());
                            break;
                        }
                    }
                }
            }

            if (treePath == null) {
                treePath = fileFuzzersCheckBoxTree.getPathForRow(0);
            }
            defaultCategoryTreePath = treePath;

            setSelectedFuzzers(currentSelections);
            getFileFuzzersCheckBoxTree().expandPath(defaultCategoryTreePath);
        }

        private static void addNodes(FuzzerPayloadCategory category, DefaultMutableTreeNode node) {
            DefaultMutableTreeNode dirNode = new DefaultMutableTreeNode(category);
            for (FuzzerPayloadCategory subCategory : category.getSubCategories()) {
                addNodes(subCategory, dirNode);
            }
            for (FuzzerPayloadSource payloadSource : category.getFuzzerPayloadSources()) {
                dirNode.add(new DefaultMutableTreeNode(payloadSource));
            }
            node.add(dirNode);
        }

        private JTextArea getPayloadsPreviewTextArea() {
            if (payloadsPreviewTextArea == null) {
                payloadsPreviewTextArea = new JTextArea(15, 10);
                payloadsPreviewTextArea.setEditable(false);
            }
            return payloadsPreviewTextArea;
        }

        private void updatePayloadsPreviewTextArea() {
            StringBuilder contents = new StringBuilder();
            try {
                int count = 0;
                for (FuzzerPayloadSource payloadsSource : getSelectedFuzzers()) {
                    if (count >= MAX_NUMBER_PAYLOAD_FUZZERS_PREVIEW) {
                        break;
                    }
                    count++;

                    contents.append(payloadsSource.getName()).append('\n');
                    try (ResettableAutoCloseableIterator<StringPayload> payloads = payloadsSource.getPayloadGenerator()
                            .iterator()) {
                        for (int i = 0; i < MAX_NUMBER_PAYLOADS_PREVIEW && payloads.hasNext(); i++) {
                            contents.append("  ").append(i + 1).append(": ").append(payloads.next().getValue()).append('\n');
                        }
                        if (payloads.hasNext()) {
                            contents.append("  ...").append('\n');
                        }
                        contents.append('\n');
                    }
                }
                getPayloadsPreviewTextArea().setEnabled(true);
            } catch (Exception ignore) {
                contents.setLength(0);
                contents.append(Constant.messages.getString("fuzz.payloads.generator.fileFuzzers.payloadsPreview.error"));
                getPayloadsPreviewTextArea().setEnabled(false);
            }
            getPayloadsPreviewTextArea().setText(contents.toString());
            getPayloadsPreviewTextArea().setCaretPosition(0);
        }

        @Override
        public void init(MessageLocation messageLocation) {
            extensionFuzz.addFuzzersDirChangeListener(fuzzersDirChangeListener);
            resetFileFuzzersCheckBoxTree();
            getFileFuzzersCheckBoxTree().expandPath(defaultCategoryTreePath);
        }

        private void resetFileFuzzersCheckBoxTree() {
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) getFileFuzzersCheckBoxTree().getModel().getRoot();
            getFileFuzzersCheckBoxTree().checkSubTree(new TreePath(root.getPath()), false);
            getFileFuzzersCheckBoxTree().collapseAll();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(FuzzerPayloadGeneratorUI payloadGeneratorUI) {
            setSelectedFuzzers(payloadGeneratorUI.getSelectedFuzzers());
            updatePayloadsPreviewTextArea();
        }

        private void setSelectedFuzzers(List<FuzzerPayloadSource> fileFuzzers) {
            resetFileFuzzersCheckBoxTree();

            if (fileFuzzers.isEmpty()) {
                return;
            }

            List<FuzzerPayloadSource> selections = new ArrayList<>(fileFuzzers);
            DefaultMutableTreeNode root = (DefaultMutableTreeNode) getFileFuzzersCheckBoxTree().getModel().getRoot();
            @SuppressWarnings("unchecked")
            Enumeration<DefaultMutableTreeNode> nodes = root.depthFirstEnumeration();
            while (!selections.isEmpty() && nodes.hasMoreElements()) {
                DefaultMutableTreeNode node = nodes.nextElement();
                if (selections.remove(node.getUserObject())) {
                    TreePath path = new TreePath(node.getPath());
                    getFileFuzzersCheckBoxTree().check(path, true);
                    getFileFuzzersCheckBoxTree().expandPath(path.getParentPath());
                }
            }
        }

        @Override
        public FuzzerPayloadGeneratorUI getPayloadGeneratorUI() {
            return new FuzzerPayloadGeneratorUI(getSelectedFuzzers());
        }

        private List<FuzzerPayloadSource> getSelectedFuzzers() {
            TreePath[] paths = getFileFuzzersCheckBoxTree().getCheckedPaths();
            List<FuzzerPayloadSource> selectedFuzzers = new ArrayList<>(paths.length);
            for (TreePath selection : paths) {
                DefaultMutableTreeNode node = ((DefaultMutableTreeNode) selection.getLastPathComponent());
                if (node.isLeaf()) {
                    selectedFuzzers.add((FuzzerPayloadSource) node.getUserObject());
                }
            }
            Collections.sort(selectedFuzzers);
            return selectedFuzzers;
        }

        @Override
        public void clear() {
            getPayloadsPreviewTextArea().setText("");
            extensionFuzz.removeFuzzersDirChangeListener(fuzzersDirChangeListener);
        }

        @Override
        public boolean validate() {
            if (hasSelections()) {
                return true;
            }

            JOptionPane.showMessageDialog(
                    null,
                    Constant.messages.getString("fuzz.payloads.generator.fileFuzzers.warnNoFile.message"),
                    Constant.messages.getString("fuzz.payloads.generator.fileFuzzers.warnNoFile.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            getFileFuzzersCheckBoxTree().requestFocusInWindow();
            return false;
        }

        private boolean hasSelections() {
            for (TreePath selection : getFileFuzzersCheckBoxTree().getCheckedPaths()) {
                if (((DefaultMutableTreeNode) selection.getLastPathComponent()).isLeaf()) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public String getHelpTarget() {
            // THC add help page...
            return null;
        }
    }

}
