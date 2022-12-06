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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;
import javax.swing.ButtonGroup;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.text.JTextComponent;
import javax.swing.text.TextAction;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.ExtensionPopupMenu;
import org.zaproxy.zap.extension.scripts.SyntaxHighlightTextArea.SyntaxStyle;

@SuppressWarnings("serial")
public class SyntaxMenu extends ExtensionPopupMenu {

    private static final long serialVersionUID = 8472491919281117716L;

    private static final String MENU_LABEL =
            Constant.messages.getString("http.panel.view.syntaxtext.popup.syntax.label");

    private ButtonGroup syntaxStylesButtonGroup;
    private Map<String, JRadioButtonMenuItem> syntaxOptions;
    private JPopupMenu.Separator plainSyntaxSeparator;

    public SyntaxMenu() {
        super(MENU_LABEL);

        syntaxStylesButtonGroup = new ButtonGroup();
        syntaxOptions = new HashMap<>();

        // Create plain syntax as all SyntaxHighlightTextArea will have this style
        addSyntaxOption(
                SyntaxHighlightTextArea.PLAIN_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_NONE);
        syntaxOptions.get(SyntaxConstants.SYNTAX_STYLE_NONE).setSelected(true);

        plainSyntaxSeparator = new JPopupMenu.Separator();
        add(plainSyntaxSeparator);
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (invoker instanceof SyntaxHighlightTextArea) {
            SyntaxHighlightTextArea httpPanelTextArea = (SyntaxHighlightTextArea) invoker;

            updateState(httpPanelTextArea);
            return true;
        }
        return false;
    }

    @Override
    public boolean precedeWithSeparator() {
        return true;
    }

    public void updateState(SyntaxHighlightTextArea httpPanelTextArea) {

        Vector<SyntaxStyle> styles = httpPanelTextArea.getSyntaxStyles();

        boolean hasMultipleStyles = true;
        if (hasMultipleStyles && styles.size() == 1) {
            hasMultipleStyles = false;
        }

        plainSyntaxSeparator.setVisible(hasMultipleStyles);

        if (hasMultipleStyles) {
            String styleKey;
            JRadioButtonMenuItem radioButton;
            Iterator<SyntaxStyle> it = styles.iterator();
            while (it.hasNext()) {
                SyntaxStyle syntaxStyle = it.next();
                styleKey = syntaxStyle.getStyleKey();
                radioButton = syntaxOptions.get(styleKey);
                if (radioButton != null) {
                    radioButton.setVisible(true);
                } else {
                    addSyntaxOption(syntaxStyle.getLabel(), styleKey);
                    syntaxOptions.get(styleKey).setVisible(true);
                }
            }
        }

        final String style = httpPanelTextArea.getSyntaxEditingStyle();
        final JRadioButtonMenuItem radioButton = syntaxOptions.get(style);
        if (radioButton != null) {
            radioButton.setSelected(true);
        } else if (!SyntaxConstants.SYNTAX_STYLE_NONE.equals(style)) {
            // Some style that is not on the pop up menu, but it is on the RSyntaxTextArea.
            // Shouldn't happen.
        } else {
            // Some style that is not recognized by RSyntaxTextArea, select plain
            // as it is the default action taken in RSyntaxTextArea
            syntaxOptions.get(SyntaxConstants.SYNTAX_STYLE_NONE).setSelected(true);
        }
    }

    private void addSyntaxOption(String text, String styleKey) {
        JRadioButtonMenuItem syntaxOption =
                new JRadioButtonMenuItem(new ChangeSyntaxAction(text, styleKey));
        syntaxStylesButtonGroup.add(syntaxOption);
        add(syntaxOption);
        syntaxOptions.put(styleKey, syntaxOption);
    }

    private static class ChangeSyntaxAction extends TextAction {

        private static final long serialVersionUID = 5136037355346821365L;

        private final String styleKey;

        public ChangeSyntaxAction(String text, String styleKey) {
            super(text);
            this.styleKey = styleKey;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            final JTextComponent textComponent = getTextComponent(e);
            if (textComponent instanceof SyntaxHighlightTextArea) {
                final SyntaxHighlightTextArea httpPanelTextArea =
                        ((SyntaxHighlightTextArea) textComponent);
                httpPanelTextArea.setSyntaxEditingStyle(styleKey);
            }
        }
    }
}
