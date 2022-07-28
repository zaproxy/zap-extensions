/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts;

import java.awt.CardLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Point;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.MalformedInputException;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DropMode;
import javax.swing.GroupLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.ToolTipManager;
import javax.swing.TransferHandler;
import javax.swing.filechooser.FileFilter;
import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptTreeModel;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.dialogs.CopyScriptDialog;
import org.zaproxy.zap.extension.scripts.dialogs.EditScriptDialog;
import org.zaproxy.zap.extension.scripts.dialogs.LoadScriptDialog;
import org.zaproxy.zap.extension.scripts.dialogs.NewScriptDialog;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapLabel;
import org.zaproxy.zap.view.AbstractFormDialog;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.ScanPanel2;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

@SuppressWarnings("serial")
public class ScriptsListPanel extends AbstractPanel {

    public static final String TREE = "ScriptListTree";

    private static final long serialVersionUID = 1L;
    private static final Logger logger = LogManager.getLogger(ScriptsListPanel.class);

    private ExtensionScriptsUI extension = null;

    private javax.swing.JPanel listPanel = null;
    private javax.swing.JToolBar panelToolbar = null;
    private JButton loadButton = null;
    private JButton saveButton = null;
    private JButton newScriptButton = null;
    private JButton optionsButton = null;

    private JScrollPane jScrollPane = null;
    private JTree tree = null;

    private NewScriptDialog newScriptDialog = null;
    private LoadScriptDialog loadScriptDialog = null;
    private EditScriptDialog editScriptDialog = null;
    private CopyScriptDialog copyScriptDialog = null;

    private HttpMessage lastMessageDisplayed = null;

    private List<Class<?>> disabledScriptDialogs = new ArrayList<>();

    private ScriptTreeTransferHandler stth = new ScriptTreeTransferHandler();

    public ScriptsListPanel(ExtensionScriptsUI extension) {
        super();
        this.extension = extension;

        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("scripts.list.panel.title"));
        this.setIcon(ExtensionScriptsUI.ICON);
        this.setDefaultAccelerator(
                extension
                        .getView()
                        .getMenuShortcutKeyStroke(
                                KeyEvent.VK_S,
                                KeyEvent.ALT_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK,
                                false));
        this.setMnemonic(Constant.messages.getChar("scripts.list.panel.mnemonic"));

        this.add(getListPanel(), getListPanel().getName());
    }

    private javax.swing.JPanel getListPanel() {
        if (listPanel == null) {

            listPanel = new javax.swing.JPanel();
            listPanel.setLayout(new GridBagLayout());
            listPanel.setName("ScriptsListPanel");

            listPanel.add(
                    this.getPanelToolbar(),
                    LayoutHelper.getGBC(0, 0, 1, 0, new Insets(2, 2, 2, 2)));
            listPanel.add(
                    getJScrollPane(),
                    LayoutHelper.getGBC(
                            0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(2, 2, 2, 2)));
        }
        return listPanel;
    }

    private javax.swing.JToolBar getPanelToolbar() {
        if (panelToolbar == null) {

            panelToolbar = new javax.swing.JToolBar();
            panelToolbar.setLayout(new GridBagLayout());
            panelToolbar.setEnabled(true);
            panelToolbar.setFloatable(false);
            panelToolbar.setRollover(true);
            panelToolbar.setPreferredSize(new Dimension(800, 30));
            panelToolbar.setFont(FontUtils.getFont("Dialog"));
            panelToolbar.setName("ScriptsListToolbar");

            int i = 1;
            panelToolbar.add(getLoadButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
            panelToolbar.add(getSaveButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
            panelToolbar.add(getNewScriptButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
            panelToolbar.add(new JLabel(), LayoutHelper.getGBC(i++, 0, 1, 1.0D)); // spacer
            panelToolbar.add(getOptionsButton(), LayoutHelper.getGBC(i++, 0, 1, 0.0D));
        }
        return panelToolbar;
    }

    private JButton getLoadButton() {
        if (loadButton == null) {
            loadButton = new JButton();
            loadButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    ZAP.class.getResource(
                                            "/resource/icon/16/047.png")))); // 'open folder' icon
            loadButton.setToolTipText(
                    Constant.messages.getString("scripts.list.toolbar.button.load"));

            loadButton.addActionListener(e -> loadScript());
        }
        return loadButton;
    }

    private JButton getSaveButton() {
        if (saveButton == null) {
            saveButton = new JButton();
            saveButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    ZAP.class.getResource(
                                            "/resource/icon/16/096.png")))); // 'diskette' icon
            saveButton.setToolTipText(
                    Constant.messages.getString("scripts.list.toolbar.button.save"));
            saveButton.setEnabled(false);

            saveButton.addActionListener(
                    e -> {
                        ScriptWrapper script = getSelectedScript();
                        if (script == null) {
                            return;
                        }
                        saveScript(script);
                    });
        }
        return saveButton;
    }

    private JButton getNewScriptButton() {
        if (newScriptButton == null) {
            newScriptButton = new JButton();
            newScriptButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    ScriptsListPanel.class.getResource(
                                            "/org/zaproxy/zap/extension/scripts/resources/icons/script-add.png"))));
            newScriptButton.setToolTipText(
                    Constant.messages.getString("scripts.list.toolbar.button.new"));

            newScriptButton.addActionListener(e -> showNewScriptDialog((ScriptWrapper) null));
        }
        return newScriptButton;
    }

    private JButton getOptionsButton() {
        if (optionsButton == null) {
            optionsButton = new JButton();
            optionsButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    ScanPanel2.class.getResource("/resource/icon/16/041.png"))));
            optionsButton.setToolTipText(
                    Constant.messages.getString("scripts.list.toolbar.button.options"));

            optionsButton.addActionListener(
                    e ->
                            Control.getSingleton()
                                    .getMenuToolsControl()
                                    .options(Constant.messages.getString("scripts.options.title")));
        }
        return optionsButton;
    }

    public void showCopyScriptDialog(ScriptWrapper script) {
        if (copyScriptDialog == null) {
            copyScriptDialog =
                    new CopyScriptDialog(
                            extension,
                            View.getSingleton().getMainFrame(),
                            new Dimension(500, 250),
                            script);
        } else {
            copyScriptDialog.init(script);
        }
        copyScriptDialog.setVisible(true);
    }

    public void showNewScriptDialog(ScriptWrapper template) {
        if (newScriptDialog == null) {
            newScriptDialog =
                    new NewScriptDialog(
                            extension,
                            View.getSingleton().getMainFrame(),
                            new Dimension(500, 400),
                            template);
        } else {
            newScriptDialog.init(template);
        }
        newScriptDialog.setVisible(true);
    }

    public void showNewScriptDialog(ScriptType type) {
        if (newScriptDialog == null) {
            newScriptDialog =
                    new NewScriptDialog(
                            extension,
                            View.getSingleton().getMainFrame(),
                            new Dimension(500, 400),
                            null);
        }
        newScriptDialog.init(type);
        newScriptDialog.setVisible(true);
    }

    private void showLoadScriptDialog(ScriptWrapper script) {
        if (loadScriptDialog == null) {
            loadScriptDialog =
                    new LoadScriptDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(500, 400));
        }
        loadScriptDialog.reset(script);
        loadScriptDialog.setVisible(true);
    }

    private void showEditScriptDialog(ScriptWrapper script) {
        if (editScriptDialog == null) {
            editScriptDialog =
                    new EditScriptDialog(
                            extension, View.getSingleton().getMainFrame(), new Dimension(500, 400));
        }
        editScriptDialog.init(script);
        editScriptDialog.setVisible(true);
    }

    private File getDefaultScriptsDir(String type) {
        File dir;
        if (type != null) {
            dir =
                    new File(
                            Constant.getZapHome()
                                    + File.separator
                                    + "scripts"
                                    + File.separator
                                    + "scripts"
                                    + File.separator
                                    + type);
        } else {
            dir =
                    new File(
                            Constant.getZapHome()
                                    + File.separator
                                    + "scripts"
                                    + File.separator
                                    + "scripts");
        }
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    protected void saveScript(ScriptWrapper script) {
        if (script.getFile() != null) {
            try {
                extension.getExtScript().saveScript(script);
                this.setButtonStates();
                ((ScriptTreeModel) this.getTree().getModel())
                        .nodeChanged(this.getSelectedScriptNode());

            } catch (IOException e1) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString("file.save.error")
                                        + " "
                                        + script.getFile().getAbsolutePath()
                                        + ".");
            }
        } else {
            JFileChooser chooser =
                    new WritableFileChooser(getDefaultScriptsDir(script.getTypeName())) {

                        private static final long serialVersionUID = 1L;

                        @Override
                        public void approveSelection() {
                            File file = getSelectedFile();
                            if (file != null) {
                                setSelectedFile(
                                        new File(createScriptFileName(file, script.getEngine())));
                            }
                            super.approveSelection();
                        }
                    };
            chooser.setSelectedFile(new File(script.getName()));
            chooser.setFileFilter(
                    getScriptFilter(
                            script.getEngine().getExtensions().get(0), script.getEngineName()));
            File file = null;
            int rc = chooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                file = chooser.getSelectedFile();
                if (file == null) {
                    return;
                }
                file = new File(createScriptFileName(file, script.getEngine()));
                script.setFile(file);

                try {
                    extension.getExtScript().saveScript(script);
                    this.setButtonStates();
                    ((ScriptTreeModel) this.getTree().getModel())
                            .nodeChanged(this.getSelectedScriptNode());

                } catch (IOException e1) {
                    View.getSingleton()
                            .showWarningDialog(
                                    Constant.messages.getString("file.save.error")
                                            + " "
                                            + file.getAbsolutePath()
                                            + ".");
                }
            }
        }
    }

    private static String createScriptFileName(File file, ScriptEngineWrapper scriptEngine) {
        String fileName = file.getAbsolutePath();
        String fileExtension = scriptEngine.getExtensions().get(0);
        if (fileExtension != null) {
            fileExtension = "." + fileExtension;
            if (!fileName.endsWith(fileExtension)) {
                fileName += fileExtension;
            }
        }
        return fileName;
    }

    private void loadScript() {
        JFileChooser chooser = new JFileChooser(getDefaultScriptsDir(null));
        File file = null;
        int rc = chooser.showOpenDialog(this);
        if (rc == JFileChooser.APPROVE_OPTION) {
            file = chooser.getSelectedFile();
            if (file == null) {
                return;
            }
            ScriptWrapper script = new ScriptWrapper();
            script.setFile(file);
            try {
                extension.getExtScript().loadScript(script);
            } catch (MalformedInputException e) {
                LoadScriptWithCharsetDialog dialog =
                        new LoadScriptWithCharsetDialog(extension.getExtScript(), script);
                dialog.setVisible(true);
                if (!dialog.isScriptLoaded()) {
                    return;
                }
            } catch (Exception e) {
                handleExceptionLoadingScript(e, file);
                return;
            }
            // TODO Not ideal, but will require some core changes to do properly
            showLoadScriptDialog(script);
        }
    }

    private static void handleExceptionLoadingScript(Exception e, File file) {
        logger.error(e.getMessage(), e);
        View.getSingleton()
                .showWarningDialog(
                        Constant.messages.getString("file.load.error")
                                + " "
                                + file.getAbsolutePath());
    }

    private FileFilter getScriptFilter(final String extension, final String description) {
        return new FileFilter() {
            @Override
            public boolean accept(File file) {
                if (file.isDirectory()) {
                    return true;
                } else if (file.isFile()
                        && (extension == null || file.getName().endsWith(extension))) {
                    return true;
                }
                return false;
            }

            @Override
            public String getDescription() {
                return description;
            }
        };
    }

    protected ScriptWrapper getSelectedScript() {
        ScriptNode node = this.getSelectedScriptNode();
        if (node != null) {
            return (ScriptWrapper) node.getUserObject();
        }
        return null;
    }

    protected ScriptNode getSelectedNode() {
        return (ScriptNode) tree.getLastSelectedPathComponent();
    }

    private ScriptNode getSelectedScriptNode() {
        ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();
        while (node != null && node.getUserObject() != null) {
            if (node.getUserObject() instanceof ScriptWrapper) {
                return node;
            }
            node = node.getParent();
        }
        return null;
    }

    protected List<ScriptNode> getSelectedNodes() {
        List<ScriptNode> nodes = new ArrayList<>();

        if (tree.getSelectionPaths() != null) {
            for (TreePath t : tree.getSelectionPaths()) {
                nodes.add((ScriptNode) t.getLastPathComponent());
            }
        }

        return nodes;
    }

    protected void setButtonStates() {
        ScriptNode node = (ScriptNode) tree.getLastSelectedPathComponent();

        // Loop up to support tree based scripts
        ScriptWrapper script = null;
        while (node != null) {
            if (node.getUserObject() instanceof ScriptWrapper) {
                script = (ScriptWrapper) node.getUserObject();
                break;
            }
            node = node.getParent();
        }

        if (script != null) {
            this.getSaveButton().setEnabled(script.isChanged() && script.getEngine() != null);
        } else {
            this.getSaveButton().setEnabled(false);
        }
    }

    private JScrollPane getJScrollPane() {
        if (jScrollPane == null) {
            jScrollPane = new JScrollPane();
            jScrollPane.setFont(FontUtils.getFont("Dialog"));
            jScrollPane.setHorizontalScrollBarPolicy(
                    javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            jScrollPane.setViewportView(getTree());
        }
        return jScrollPane;
    }

    public void addScriptTreeTransferHandler(Class<?> c, TransferHandler th) {
        this.stth.addTransferHandler(c, th);
    }

    public void removeScriptTreeTransferHandler(Class<?> c) {
        this.stth.removeTransferHandler(c);
    }

    JTree getTree() {
        if (tree == null) {
            tree =
                    new JTree() {

                        private static final long serialVersionUID = 1L;

                        @Override
                        public Point getPopupLocation(final MouseEvent event) {
                            // Select the node before showing the pop up menu when invoked using the
                            // mouse.
                            if (event != null) {
                                TreePath tp = tree.getPathForLocation(event.getX(), event.getY());
                                if (tp != null) {
                                    boolean select = true;
                                    // Only select a new node if the current node is not
                                    // already selected - this is to allow multiple nodes
                                    // to be selected
                                    if (tree.getSelectionPaths() != null) {
                                        for (TreePath t : tree.getSelectionPaths()) {
                                            if (t.equals(tp)) {
                                                select = false;
                                                break;
                                            }
                                        }
                                    }
                                    if (select) {
                                        tree.getSelectionModel().setSelectionPath(tp);
                                    }
                                }
                            }
                            return super.getPopupLocation(event);
                        }
                    };
            tree.setComponentPopupMenu(ZapPopupMenu.INSTANCE);
            tree.setModel(extension.getExtScript().getTreeModel());
            tree.setName(TREE);
            tree.setShowsRootHandles(true);
            tree.setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 0, 0, 0));
            tree.setCellRenderer(this.extension.getScriptsTreeCellRenderer());
            tree.setDragEnabled(true);
            tree.setDropMode(DropMode.ON_OR_INSERT);
            tree.setTransferHandler(this.stth);
            tree.getSelectionModel().setSelectionMode(TreeSelectionModel.CONTIGUOUS_TREE_SELECTION);

            // Have to register the tree otherwise tooltips dont work
            ToolTipManager.sharedInstance().registerComponent(tree);

            TreeNode firstChild = extension.getExtScript().getTreeModel().getRoot().getFirstChild();
            if (firstChild != null && firstChild instanceof ScriptNode) {
                // Nasty way of expanding the Scripts node - should tidy up
                TreeNode[] path = ((ScriptNode) firstChild).getPath();
                TreePath tp = new TreePath(path);
                getTree().setExpandsSelectedPaths(true);
                getTree().setSelectionPath(tp);
                getTree().scrollPathToVisible(tp);
                getTree().expandPath(tp);
            }

            tree.addMouseListener(
                    new java.awt.event.MouseAdapter() {

                        @Override
                        public void mouseReleased(java.awt.event.MouseEvent e) {
                            mouseClicked(e);
                        }

                        @Override
                        public void mouseClicked(java.awt.event.MouseEvent e) {
                            if (e.getClickCount() > 1) {
                                // Its a double click - edit a script if selected (but not a
                                // template)
                                ScriptNode node = getSelectedNode();
                                if (node != null
                                        && !node.isTemplate()
                                        && node.getUserObject() != null) {
                                    if (node.getUserObject() instanceof ScriptWrapper) {
                                        boolean edit = true;
                                        // Only show edit dialog if another add-on hasnt disabled it
                                        // for the class(es)
                                        // they manage
                                        for (Class<?> c : disabledScriptDialogs) {
                                            if (c.isInstance(node.getUserObject())) {
                                                edit = false;
                                                break;
                                            }
                                        }
                                        if (edit) {
                                            showEditScriptDialog(
                                                    (ScriptWrapper) node.getUserObject());
                                        }
                                    }
                                }
                            }
                        }
                    });
            tree.addTreeSelectionListener(e -> selectionChanged());
        }
        return tree;
    }

    private void selectionChanged() {
        setButtonStates();
        ScriptNode node = getSelectedNode();
        while (node != null) {
            if (node.getUserObject() != null) {
                if (node.getUserObject() instanceof ScriptWrapper) {
                    // Only display the script if its not already displayed -
                    // down want to keep switching to the Script Console tab
                    if (!extension.isScriptDisplayed((ScriptWrapper) node.getUserObject())) {
                        if (node.isTemplate()) {
                            extension.displayTemplate((ScriptWrapper) node.getUserObject());
                        } else {
                            extension.displayScript((ScriptWrapper) node.getUserObject());
                        }
                    }
                    break;
                }
            } else if (!node.isRoot()
                    && !node.getParent().isRoot()
                    && node.getParent().getParent().isRoot()
                    && node.getType() != null) {
                // This is a 'type' node, display help (if any)
                if (node.isTemplate()) {
                    extension.displayTemplateType(node.getType());
                } else {
                    extension.displayType(node.getType());
                }
                break;
            }
            // Keep going up until we find something
            node = node.getParent();
        }
    }

    public void select(ScriptNode node) {
        this.getTree().setSelectionPath(new TreePath(node.getPath()));
    }

    public boolean isSelectedMessage(Message message) {
        return message != null
                && lastMessageDisplayed != null
                && (message.hashCode() == lastMessageDisplayed.hashCode());
    }

    public void showInTree(ScriptNode node) {
        this.showInTree(node, false);
    }

    public void showInTree(ScriptNode node, boolean expand) {
        TreeNode[] path = node.getPath();
        TreePath tp = new TreePath(path);
        getTree().setExpandsSelectedPaths(true);
        getTree().setSelectionPath(tp);
        getTree().scrollPathToVisible(tp);
        if (expand) {
            getTree().expandPath(tp);
        }
    }

    public void disableScriptDialog(Class<?> klass) {
        if (ScriptWrapper.class.equals(klass) || !ScriptWrapper.class.isAssignableFrom(klass)) {
            throw new InvalidParameterException("Must specify a subclass of ScriptWrapper");
        }
        this.disabledScriptDialogs.add(klass);
    }

    public void removeDisableScriptDialog(Class<?> klass) {
        if (ScriptWrapper.class.equals(klass) || !ScriptWrapper.class.isAssignableFrom(klass)) {
            throw new InvalidParameterException("Must specify a subclass of ScriptWrapper");
        }
        this.disabledScriptDialogs.remove(klass);
    }

    void unload() {
        if (tree != null) {
            tree.setModel(null);
        }

        if (newScriptDialog != null) {
            newScriptDialog.dispose();
        }

        if (loadScriptDialog != null) {
            loadScriptDialog.dispose();
        }

        if (editScriptDialog != null) {
            editScriptDialog.dispose();
        }

        if (copyScriptDialog != null) {
            copyScriptDialog.dispose();
        }
    }

    /**
     * A {@code JDialog} that allows to load the script with one of the character encodings
     * supported by the JVM.
     *
     * @see #isScriptLoaded()
     */
    private static class LoadScriptWithCharsetDialog extends AbstractFormDialog {

        private static final long serialVersionUID = 1L;

        private final ExtensionScript extension;
        private final ScriptWrapper script;
        private boolean scriptLoaded;

        private JLabel charsetLabel;
        private JComboBox<Charset> charsetComboBox;

        public LoadScriptWithCharsetDialog(ExtensionScript extension, ScriptWrapper script) {
            super(
                    View.getSingleton().getMainFrame(),
                    Constant.messages.getString("scripts.script.load.charset.title"),
                    false);

            this.extension = extension;
            this.script = script;

            initView();
            setConfirmButtonEnabled(true);

            pack();
        }

        @Override
        protected JPanel getFieldsPanel() {
            JPanel fieldsPanel = new JPanel();

            GroupLayout groupLayout = new GroupLayout(fieldsPanel);
            fieldsPanel.setLayout(groupLayout);
            groupLayout.setAutoCreateGaps(true);
            groupLayout.setAutoCreateContainerGaps(true);

            Charset jvmCharset = Charset.defaultCharset();
            Charset defaultCharset = ExtensionScript.DEFAULT_CHARSET;

            ZapLabel messageLabel =
                    new ZapLabel(
                            Constant.messages.getString(
                                    "scripts.script.load.charset.message",
                                    jvmCharset != defaultCharset
                                            ? jvmCharset + ", " + defaultCharset
                                            : defaultCharset));
            messageLabel.setLineWrap(true);
            messageLabel.setWrapStyleWord(true);
            messageLabel.setColumns(20);
            messageLabel.setRows(5);

            JScrollPane pane = new JScrollPane(messageLabel);
            pane.setBorder(BorderFactory.createEmptyBorder());

            groupLayout.setHorizontalGroup(
                    groupLayout
                            .createParallelGroup()
                            .addComponent(pane)
                            .addGroup(
                                    groupLayout
                                            .createSequentialGroup()
                                            .addComponent(getCharsetLabel())
                                            .addComponent(getCharsetComboBox())));

            groupLayout.setVerticalGroup(
                    groupLayout
                            .createSequentialGroup()
                            .addComponent(pane)
                            .addGroup(
                                    groupLayout
                                            .createParallelGroup(GroupLayout.Alignment.BASELINE)
                                            .addComponent(getCharsetLabel())
                                            .addComponent(getCharsetComboBox())));

            return fieldsPanel;
        }

        @Override
        protected String getConfirmButtonLabel() {
            return Constant.messages.getString("scripts.script.load.charset.confirmbutton");
        }

        private JLabel getCharsetLabel() {
            if (charsetLabel == null) {
                charsetLabel =
                        new JLabel(
                                Constant.messages.getString("scripts.script.load.charset.label"));
                charsetLabel.setLabelFor(getCharsetComboBox());
            }
            return charsetLabel;
        }

        private JComboBox<Charset> getCharsetComboBox() {
            if (charsetComboBox == null) {
                DefaultComboBoxModel<Charset> charsetsNames = new DefaultComboBoxModel<>();
                Charset.availableCharsets().values().forEach(charsetsNames::addElement);
                charsetComboBox = new JComboBox<>(charsetsNames);
            }
            return charsetComboBox;
        }

        @Override
        public boolean validateFields() {
            try {
                extension.loadScript(script, (Charset) getCharsetComboBox().getSelectedItem());
            } catch (MalformedInputException e) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "scripts.script.load.charset.selected.error"));
                return false;
            } catch (Exception e) {
                handleExceptionLoadingScript(e, script.getFile());
                return true;
            }
            scriptLoaded = true;
            return true;
        }

        /**
         * Tells whether or not the script was loaded.
         *
         * @return {@code true} if the script was loaded, {@code false} otherwise.
         * @see ExtensionScript#loadScript(ScriptWrapper, Charset)
         */
        boolean isScriptLoaded() {
            return scriptLoaded;
        }
    }
}
