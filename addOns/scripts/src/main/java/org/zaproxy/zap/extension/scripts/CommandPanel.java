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
package org.zaproxy.zap.extension.scripts;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.event.KeyListener;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.zaproxy.zap.extension.scripts.autocomplete.ScriptAutoCompleteKeyListener;
import org.zaproxy.zap.utils.FontUtils;

@SuppressWarnings("serial")
public class CommandPanel extends AbstractPanel {

    private static final long serialVersionUID = -947074835463140074L;
    /** Max amount of data(byte) before editor usage is disable */
    private static final int EDITOR_SCRIPT_MAX_SIZE_THRESHOLD = 1_000_000;
    /** Max amount of data(byte) before highlight feature is deactivated */
    private static final int HIGHLIGHT_SCRIPT_MAX_SIZE_THRESHOLD = 500_000;

    private JScrollPane jScrollPane = null;
    private SyntaxHighlightTextArea syntaxTxtArea = null;
    private KeyListener listener = null;
    private ScriptAutoCompleteKeyListener autocompleteListener;

    private boolean largeScriptContentSet = false;
    private String largeScriptContent = "";
    private JPanel largeScriptPanel = new JPanel(new BorderLayout());
    private JLabel largeScriptLabel = new JLabel();

    /** */
    public CommandPanel(KeyListener listener) {
        super();
        this.listener = listener;

        this.setLayout(new CardLayout());
        this.setName("ConsoleCommandPanel");

        this.add(getJScrollPane(), getJScrollPane().getName());
        largeScriptPanel.add(largeScriptLabel);
    }
    /**
     * This method initializes jScrollPane
     *
     * @return javax.swing.JScrollPane
     */
    private JScrollPane getJScrollPane() {
        if (jScrollPane == null) {
            jScrollPane = new RTextScrollPane((Component) getTxtOutput(), false);

            ((RTextScrollPane) jScrollPane).setLineNumbersEnabled(true);

            jScrollPane.setName("ConsoleCommandjScrollPane");
            jScrollPane.setFont(FontUtils.getFont("Dialog"));
        }
        return jScrollPane;
    }

    private SyntaxHighlightTextArea getTxtOutput() {
        if (this.syntaxTxtArea == null) {
            this.syntaxTxtArea = new SyntaxHighlightTextArea();

            this.syntaxTxtArea.setComponentPopupMenu(ZapPopupMenu.INSTANCE);

            this.autocompleteListener = new ScriptAutoCompleteKeyListener(this.syntaxTxtArea);
            this.syntaxTxtArea.addKeyListener(this.autocompleteListener);
            if (listener != null) {
                this.syntaxTxtArea.addKeyListener(listener);
            }
        }
        return this.syntaxTxtArea;
    }

    @Override
    public synchronized void addKeyListener(KeyListener l) {
        // Don't do anything, the (only) listener is specified through the constructor.
    }

    public void setSyntax(String syntax) {
        boolean highlightEnabled =
                getTxtOutput().getDocument().getLength() < HIGHLIGHT_SCRIPT_MAX_SIZE_THRESHOLD
                        && !largeScriptContentSet;
        getTxtOutput()
                .setSyntaxEditingStyle(
                        highlightEnabled ? syntax : SyntaxConstants.SYNTAX_STYLE_NONE);
    }

    public void clear() {
        setCommandScriptContent("");
        getTxtOutput().discardAllEdits();
        setSyntax(SyntaxConstants.SYNTAX_STYLE_NONE);
    }

    public String getCommandScript() {
        return largeScriptContentSet ? largeScriptContent : getTxtOutput().getText();
    }

    protected void setCommandScript(String str) {
        setCommandScriptContent(str);
        getTxtOutput().discardAllEdits();
        getTxtOutput().requestFocus();
    }

    protected void setCommandCursorPosition(int offset) {
        try {
            getTxtOutput().setCaretPosition(offset);
        } catch (IllegalArgumentException e) {
            // Ignore
        }
    }

    protected int getCommandCursorPosition() {
        return getTxtOutput().getCaretPosition();
    }

    void unload() {
        getTxtOutput().unload();
    }

    public void setEditable(boolean editable) {
        getTxtOutput().setEditable(editable);
    }

    public void setScriptType(String typeName) {
        if (this.autocompleteListener != null) {
            this.autocompleteListener.setScriptType(typeName);
        }
    }

    public void setAutoCompleteEnabled(boolean enable) {
        if (this.autocompleteListener != null) {
            this.autocompleteListener.setEnabled(enable);
        }
    }

    private void setCommandScriptContent(String str) {
        if (str.length() > EDITOR_SCRIPT_MAX_SIZE_THRESHOLD) {
            getTxtOutput().setText("");
            largeScriptContent = str;
            largeScriptContentSet = true;
        } else {
            getTxtOutput().setText(str);
            largeScriptContent = "";
            largeScriptContentSet = false;
        }
        if (largeScriptContentSet) {
            this.remove(getJScrollPane());
            this.add(largeScriptPanel, largeScriptPanel.getName());
            largeScriptLabel.setText(
                    Constant.messages.getString(
                            "scripts.dialog.script.large.warning", largeScriptContent.length()));
        } else {
            this.remove(largeScriptPanel);
            this.add(getJScrollPane(), getJScrollPane().getName());
        }
    }
}
