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

import java.awt.KeyboardFocusManager;
import java.awt.event.ActionEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.AbstractAction;
import javax.swing.BoxLayout;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.KeyStroke;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultTreeSelectionModel;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import org.jdesktop.swingx.JXFindBar;
import org.jdesktop.swingx.decorator.Highlighter;
import org.jdesktop.swingx.renderer.StringValues;
import org.jdesktop.swingx.search.AbstractSearchable;
import org.jdesktop.swingx.search.SearchFactory;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz.FuzzersDirChangeListener;
import org.zaproxy.zap.extension.fuzz.FuzzerPayloadGeneratorUIHandler.FuzzerPayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.AbstractPersistentPayloadGeneratorUIPanel;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.ModifyPayloadsPanel;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;
import org.zaproxy.zap.view.JCheckBoxTree;
import org.zaproxy.zap.view.JCheckBoxTree.CheckChangeEvent;
import org.zaproxy.zap.view.JCheckBoxTree.CheckChangeEventListener;

public class FuzzerPayloadGeneratorUIHandler
        implements PayloadGeneratorUIHandler<
                DefaultPayload, FuzzerPayloadGenerator, FuzzerPayloadGeneratorUI> {

    private static final String PAYLOAD_GENERATOR_NAME =
            Constant.messages.getString("fuzz.payloads.generator.fileFuzzers.name");

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

    public static class FuzzerPayloadGeneratorUI
            implements PayloadGeneratorUI<DefaultPayload, FuzzerPayloadGenerator> {

        private final List<FuzzerPayloadSource> selectedFuzzers;
        private int numberOfPayloads;

        private Path file;
        private String description;
        private boolean temporary;

        public FuzzerPayloadGeneratorUI(Path file, String description, int numberOfPayloads) {
            this.file = file;
            this.description = description;
            this.temporary = true;
            this.selectedFuzzers = Collections.emptyList();
            this.numberOfPayloads = numberOfPayloads;
        }

        public FuzzerPayloadGeneratorUI(List<FuzzerPayloadSource> selectedFuzzers) {
            this.selectedFuzzers = Collections.unmodifiableList(new ArrayList<>(selectedFuzzers));
            this.numberOfPayloads = -1;
        }

        public List<FuzzerPayloadSource> getSelectedFuzzers() {
            return selectedFuzzers;
        }

        public Path getFile() {
            return file;
        }

        public boolean isTemporary() {
            return temporary;
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
            if (temporary) {
                return description;
            }

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
            if (temporary) {
                return new FuzzerPayloadGenerator(
                        Collections.<PayloadGenerator<DefaultPayload>>emptyList()) {

                    private FileStringPayloadGenerator delegate =
                            new FileStringPayloadGenerator(
                                    file,
                                    StandardCharsets.UTF_8,
                                    -1,
                                    "",
                                    false,
                                    false,
                                    numberOfPayloads);

                    @Override
                    public PayloadGenerator<DefaultPayload> copy() {
                        return delegate.copy();
                    }

                    @Override
                    public long getNumberOfPayloads() {
                        return delegate.getNumberOfPayloads();
                    }

                    @Override
                    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
                        return delegate.iterator();
                    }
                };
            }
            List<PayloadGenerator<DefaultPayload>> generators = new ArrayList<>();
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

    public static class FuzzerPayloadGeneratorUIPanel
            extends AbstractPersistentPayloadGeneratorUIPanel<
                    DefaultPayload, FuzzerPayloadGenerator, FuzzerPayloadGeneratorUI> {

        private static final String FILE_FUZZERS_FIELD_LABEL =
                Constant.messages.getString("fuzz.payloads.generator.fileFuzzers.files.label");
        private static final String PAYLOADS_PREVIEW_FIELD_LABEL =
                Constant.messages.getString(
                        "fuzz.payloads.generator.fileFuzzers.payloadsPreview.label");

        private static final int MAX_NUMBER_PAYLOAD_FUZZERS_PREVIEW = 35;
        private static final int MAX_NUMBER_PAYLOADS_PREVIEW = 30;

        private final ExtensionFuzz extensionFuzz;
        private final FuzzersDirChangeListener fuzzersDirChangeListener;

        private JPanel fieldsPanel;
        private GroupLayout mainLayout;

        private JPanel addPanel;
        private ModifyFileFuzzersPayloadsPanel modifyPanel;

        private FindBar findBar;
        private JCheckBoxTree fileFuzzersCheckBoxTree;
        private TreeSearchable treeSearchable;
        private TreePath defaultCategoryTreePath;
        private JTextArea payloadsPreviewTextArea;

        private boolean modifyFileContents;

        public FuzzerPayloadGeneratorUIPanel(ExtensionFuzz extensionFuzz) {
            this.extensionFuzz = extensionFuzz;

            this.fuzzersDirChangeListener =
                    new FuzzersDirChangeListener() {

                        @Override
                        public void fuzzersDirChanged(FuzzersDir fuzzersDir) {
                            createFileFuzzersCheckBoxTreeModel();
                        }
                    };

            addPanel = new JPanel();

            GroupLayout layoutAddPanel = new GroupLayout(addPanel);
            addPanel.setLayout(layoutAddPanel);
            layoutAddPanel.setAutoCreateGaps(true);

            JLabel fileFuzzersLabel = new JLabel(FILE_FUZZERS_FIELD_LABEL);
            fileFuzzersLabel.setLabelFor(getFileFuzzersCheckBoxTree());
            JLabel payloadsPreviewLabel = new JLabel(PAYLOADS_PREVIEW_FIELD_LABEL);
            payloadsPreviewLabel.setLabelFor(getPayloadsPreviewTextArea());

            JScrollPane scrollPane = new JScrollPane(getFileFuzzersCheckBoxTree());
            JScrollPane payloadsPreviewScrollPane = new JScrollPane(getPayloadsPreviewTextArea());

            layoutAddPanel.setHorizontalGroup(
                    layoutAddPanel
                            .createSequentialGroup()
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.TRAILING)
                                            .addComponent(fileFuzzersLabel)
                                            .addComponent(payloadsPreviewLabel))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.LEADING)
                                            .addGroup(
                                                    layoutAddPanel
                                                            .createParallelGroup(
                                                                    GroupLayout.Alignment.LEADING)
                                                            .addComponent(getFindBar())
                                                            .addComponent(scrollPane))
                                            .addComponent(payloadsPreviewScrollPane)));

            layoutAddPanel.setVerticalGroup(
                    layoutAddPanel
                            .createSequentialGroup()
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(fileFuzzersLabel)
                                            .addGroup(
                                                    layoutAddPanel
                                                            .createSequentialGroup()
                                                            .addComponent(getFindBar())
                                                            .addComponent(scrollPane)))
                            .addGroup(
                                    layoutAddPanel
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(payloadsPreviewLabel)
                                            .addComponent(payloadsPreviewScrollPane)));

            fieldsPanel = new JPanel();
            mainLayout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(mainLayout);

            mainLayout.setHorizontalGroup(
                    mainLayout.createSequentialGroup().addComponent(addPanel));
            mainLayout.setVerticalGroup(mainLayout.createSequentialGroup().addComponent(addPanel));
        }

        private ModifyFileFuzzersPayloadsPanel getModifyPanel() {
            if (modifyPanel == null) {
                modifyPanel = new ModifyFileFuzzersPayloadsPanel(createSaveButton());
            }
            return modifyPanel;
        }

        private FindBar getFindBar() {
            if (findBar == null) {
                findBar = new FindBar();
            }
            return findBar;
        }

        private JCheckBoxTree getFileFuzzersCheckBoxTree() {
            if (fileFuzzersCheckBoxTree == null) {
                fileFuzzersCheckBoxTree = new JCheckBoxTree();
                fileFuzzersCheckBoxTree.setRootVisible(false);
                fileFuzzersCheckBoxTree.setShowsRootHandles(true);
                fileFuzzersCheckBoxTree.setSelectionModel(new DefaultTreeSelectionModel());
                fileFuzzersCheckBoxTree.addCheckChangeEventListener(
                        new CheckChangeEventListener() {

                            @Override
                            public void checkStateChanged(CheckChangeEvent e) {
                                updatePayloadsPreviewTextArea();
                            }
                        });
                fileFuzzersCheckBoxTree.setVisibleRowCount(10);

                treeSearchable = new TreeSearchable(fileFuzzersCheckBoxTree);
                getFindBar().setSearchable(treeSearchable);

                fileFuzzersCheckBoxTree
                        .getActionMap()
                        .put(
                                "find",
                                new AbstractAction() {

                                    private static final long serialVersionUID =
                                            2509106064246847016L;

                                    @Override
                                    public void actionPerformed(ActionEvent e) {
                                        KeyboardFocusManager.getCurrentKeyboardFocusManager()
                                                .focusNextComponent(getFindBar());
                                    }
                                });

                KeyStroke findStroke = SearchFactory.getInstance().getSearchAccelerator();
                fileFuzzersCheckBoxTree
                        .getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)
                        .put(findStroke, "find");

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
            // Following two statements are a hack to make the check boxes of the nodes to render
            // correctly
            fileFuzzersCheckBoxTree.expandAll();
            fileFuzzersCheckBoxTree.collapseAll();

            TreePath treePath = null;
            String defaultCategory = extensionFuzz.getFuzzOptions().getDefaultCategoryName();
            if (defaultCategory != null
                    && !extensionFuzz.getFuzzOptions().isCustomDefaultCategory()) {
                root = (DefaultMutableTreeNode) fileFuzzersCheckBoxTree.getModel().getRoot();
                @SuppressWarnings("unchecked")
                Enumeration<TreeNode> nodes = root.breadthFirstEnumeration();
                while (nodes.hasMoreElements()) {
                    DefaultMutableTreeNode node = (DefaultMutableTreeNode) nodes.nextElement();
                    Object object = node.getUserObject();
                    if (object instanceof FuzzerPayloadCategory) {
                        if (defaultCategory.equals(
                                ((FuzzerPayloadCategory) object).getFullName())) {
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
            treeSearchable.reload();
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
                payloadsPreviewTextArea.setFont(FontUtils.getFont("Monospaced"));
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
                    try (ResettableAutoCloseableIterator<DefaultPayload> payloads =
                            payloadsSource
                                    .getPayloadGenerator(MAX_NUMBER_PAYLOADS_PREVIEW + 1)
                                    .iterator()) {
                        for (int i = 0;
                                i < MAX_NUMBER_PAYLOADS_PREVIEW && payloads.hasNext();
                                i++) {
                            contents.append("  ")
                                    .append(i + 1)
                                    .append(": ")
                                    .append(payloads.next().getValue())
                                    .append('\n');
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
                contents.append(
                        Constant.messages.getString(
                                "fuzz.payloads.generator.fileFuzzers.payloadsPreview.error"));
                getPayloadsPreviewTextArea().setEnabled(false);
            }
            getPayloadsPreviewTextArea().setText(contents.toString());
            getPayloadsPreviewTextArea().setCaretPosition(0);
        }

        @Override
        public void init(MessageLocation messageLocation) {
            extensionFuzz.addFuzzersDirChangeListener(fuzzersDirChangeListener);
            resetFileFuzzersCheckBoxTree();
            createFileFuzzersCheckBoxTreeModel();
            modifyFileContents = false;
            getFindBar().clear();
        }

        private void resetFileFuzzersCheckBoxTree() {
            DefaultMutableTreeNode root =
                    (DefaultMutableTreeNode) getFileFuzzersCheckBoxTree().getModel().getRoot();
            getFileFuzzersCheckBoxTree().checkSubTree(new TreePath(root.getPath()), false);
            getFileFuzzersCheckBoxTree().collapseAll();
        }

        @Override
        public JPanel getComponent() {
            return fieldsPanel;
        }

        @Override
        public void setPayloadGeneratorUI(FuzzerPayloadGeneratorUI payloadGeneratorUI) {
            modifyFileContents = true;
            mainLayout.replace(addPanel, getModifyPanel().getPanel());

            getModifyPanel()
                    .setPayloadGeneratorUI(
                            payloadGeneratorUI,
                            !payloadGeneratorUI.isTemporary(),
                            payloadGeneratorUI.getFile());
        }

        private void setSelectedFuzzers(List<FuzzerPayloadSource> fileFuzzers) {
            resetFileFuzzersCheckBoxTree();

            if (fileFuzzers.isEmpty()) {
                return;
            }

            List<FuzzerPayloadSource> selections = new ArrayList<>(fileFuzzers);
            DefaultMutableTreeNode root =
                    (DefaultMutableTreeNode) getFileFuzzersCheckBoxTree().getModel().getRoot();
            @SuppressWarnings("unchecked")
            Enumeration<TreeNode> nodes = root.depthFirstEnumeration();
            while (!selections.isEmpty() && nodes.hasMoreElements()) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) nodes.nextElement();
                if (selections.remove(node.getUserObject())) {
                    TreePath path = new TreePath(node.getPath());
                    getFileFuzzersCheckBoxTree().check(path, true);
                    getFileFuzzersCheckBoxTree().expandPath(path.getParentPath());
                }
            }
        }

        @Override
        public FuzzerPayloadGeneratorUI getPayloadGeneratorUI() {
            if (modifyFileContents) {
                return getModifyPanel().getFileStringPayloadGeneratorUI();
            }
            return new FuzzerPayloadGeneratorUI(getSelectedFuzzers());
        }

        @Override
        protected FuzzerPayloadGenerator getPayloadGenerator() {
            if (modifyFileContents) {
                if (getModifyPanel().isValidForPersistence()) {
                    return getModifyPanel().getPayloadGenerator();
                }
            }
            return null;
        }

        private List<FuzzerPayloadSource> getSelectedFuzzers() {
            TreePath[] paths = getFileFuzzersCheckBoxTree().getCheckedPaths();
            List<FuzzerPayloadSource> selectedFuzzers = new ArrayList<>(paths.length);
            for (TreePath selection : paths) {
                DefaultMutableTreeNode node =
                        ((DefaultMutableTreeNode) selection.getLastPathComponent());
                if (node.isLeaf() && (node.getUserObject() instanceof FuzzerPayloadSource)) {
                    selectedFuzzers.add((FuzzerPayloadSource) node.getUserObject());
                }
            }
            Collections.sort(selectedFuzzers);
            return selectedFuzzers;
        }

        @Override
        public void clear() {
            if (modifyFileContents) {
                getModifyPanel().clear();
                mainLayout.replace(getModifyPanel().getPanel(), addPanel);
                return;
            }
            getPayloadsPreviewTextArea().setText("");
            extensionFuzz.removeFuzzersDirChangeListener(fuzzersDirChangeListener);
        }

        @Override
        public boolean validate() {
            if (modifyFileContents) {
                return getModifyPanel().validate();
            }

            if (hasSelections()) {
                return true;
            }

            JOptionPane.showMessageDialog(
                    null,
                    Constant.messages.getString(
                            "fuzz.payloads.generator.fileFuzzers.warnNoFile.message"),
                    Constant.messages.getString(
                            "fuzz.payloads.generator.fileFuzzers.warnNoFile.title"),
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

        private static class ModifyFileFuzzersPayloadsPanel
                extends ModifyPayloadsPanel<
                        DefaultPayload, FuzzerPayloadGenerator, FuzzerPayloadGeneratorUI> {

            public ModifyFileFuzzersPayloadsPanel(JButton saveButton) {
                super(saveButton);
            }

            @Override
            public FuzzerPayloadGenerator getPayloadGenerator() {
                return new FuzzerPayloadGenerator(
                        Collections.<PayloadGenerator<DefaultPayload>>emptyList()) {

                    @Override
                    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
                        return new TextAreaPayloadIterator(getPayloadsTextArea());
                    }
                };
            }

            @Override
            protected FuzzerPayloadGeneratorUI createPayloadGeneratorUI(int numberOfPayloads) {
                return new FuzzerPayloadGeneratorUI(
                        getFile(), getPayloadGeneratorUI().getDescription(), numberOfPayloads);
            }
        }

        // Based on SwingX's (org.jdesktop.swingx.search.)TreeSearchable, but uses a plain JTree
        private static class TreeSearchable extends AbstractSearchable {

            private static final Highlighter[] EMPTY_HIGHLIGHTER = {};

            private final JTree tree;
            private final Map<Integer, TreePath> rows;

            public TreeSearchable(JTree tree) {
                this.tree = tree;
                this.rows = new HashMap<>();
            }

            public void reload() {
                rows.clear();

                DefaultMutableTreeNode rootNode =
                        (DefaultMutableTreeNode) tree.getModel().getRoot();
                @SuppressWarnings("unchecked")
                Enumeration<TreeNode> nodes = rootNode.preorderEnumeration();
                for (int i = 0; nodes.hasMoreElements(); i++) {
                    rows.put(
                            i,
                            new TreePath(((DefaultMutableTreeNode) nodes.nextElement()).getPath()));
                }
            }

            @Override
            protected void findMatchAndUpdateState(
                    Pattern pattern, int startRow, boolean backwards) {
                SearchResult searchResult = null;
                if (backwards) {
                    for (int index = startRow; index >= 0 && searchResult == null; index--) {
                        searchResult = findMatchAt(pattern, index);
                    }
                } else {
                    for (int index = startRow; index < getSize() && searchResult == null; index++) {
                        searchResult = findMatchAt(pattern, index);
                    }
                }
                updateState(searchResult);
            }

            @Override
            protected SearchResult findExtendedMatch(Pattern pattern, int row) {
                return findMatchAt(pattern, row);
            }

            private SearchResult findMatchAt(Pattern pattern, int row) {
                TreePath path = rows.get(row);
                if (path == null) {
                    return null;
                }

                String text = StringValues.TO_STRING.getString(path.getLastPathComponent());
                if (text == null || text.isEmpty()) {
                    return null;
                }

                Matcher matcher = pattern.matcher(text);
                if (matcher.find()) {
                    return createSearchResult(matcher, row, 0);
                }
                return null;
            }

            @Override
            protected int getSize() {
                return rows.size();
            }

            @Override
            public JTree getTarget() {
                return tree;
            }

            @Override
            protected void moveMatchMarker() {
                if (!hasMatch()) {
                    return;
                }
                TreePath path = rows.get(lastSearchResult.getFoundRow());
                tree.setSelectionPath(path);
                tree.scrollPathToVisible(path);
            }

            @Override
            protected void removeHighlighter(Highlighter searchHighlighter) {}

            @Override
            protected Highlighter[] getHighlighters() {
                return EMPTY_HIGHLIGHTER;
            }

            @Override
            protected void addHighlighter(Highlighter highlighter) {}
        }

        private static class FindBar extends JXFindBar {

            private static final long serialVersionUID = 2420176685611349205L;

            public void clear() {
                if (searchField == null) {
                    return;
                }
                searchField.setText("");
            }

            @Override
            protected void build() {
                setLayout(new BoxLayout(this, BoxLayout.LINE_AXIS));
                add(searchField);
                add(findNext);
                add(findPrevious);
            }
        }
    }
}
