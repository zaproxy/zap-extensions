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
import java.awt.Font;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Vector;
import javax.swing.Action;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import org.fife.ui.rsyntaxtextarea.AbstractTokenMakerFactory;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextArea;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;

public class SyntaxHighlightTextArea extends RSyntaxTextArea {

    private static final long serialVersionUID = -9082089105656842054L;

    public static final String PLAIN_SYNTAX_LABEL =
            Constant.messages.getString("scripts.syntaxtext.syntax.plain");
    public static final String CLOJURE_SYNTAX_LABEL =
            Constant.messages.getString("scripts.syntaxtext.syntax.clojure");
    public static final String GROOVY_SYNTAX_LABEL =
            Constant.messages.getString("scripts.syntaxtext.syntax.groovy");
    public static final String JAVASCRIPT_SYNTAX_LABEL =
            Constant.messages.getString("scripts.syntaxtext.syntax.javascript");
    public static final String PYTHON_SYNTAX_LABEL =
            Constant.messages.getString("scripts.syntaxtext.syntax.python");
    public static final String RUBY_SYNTAX_LABEL =
            Constant.messages.getString("scripts.syntaxtext.syntax.ruby");
    public static final String SCALA_SYNTAX_LABEL =
            Constant.messages.getString("scripts.syntaxtext.syntax.scala");
    public static final String HTML_SYNTAX_LABEL =
            Constant.messages.getString("scripts.syntaxtext.syntax.html");
    public static final String CSS_SYNTAX_LABEL =
            Constant.messages.getString("scripts.syntaxtext.syntax.css");

    private Vector<SyntaxStyle> syntaxStyles;

    private SyntaxMenu syntaxMenu = null;
    private ViewMenu viewMenu = null;
    private TextAreaMenuItem cutAction = null;
    private TextAreaMenuItem copyAction = null;
    private TextAreaMenuItem pasteAction = null;
    private TextAreaMenuItem deleteAction = null;
    private TextAreaMenuItem undoAction = null;
    private TextAreaMenuItem redoAction = null;
    private TextAreaMenuItem selectAllAction = null;

    private static final String RESOURCE_DARK = "/org/fife/ui/rsyntaxtextarea/themes/dark.xml";
    private static final String RESOURCE_LIGHT = "/org/fife/ui/rsyntaxtextarea/themes/default.xml";

    private Boolean supportsDarkLaF;
    private Method isDarkLookAndFeelMethod;
    private Boolean darkLaF;

    public SyntaxHighlightTextArea() {
        setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);

        syntaxStyles = new Vector<>();
        addSyntaxStyle(PLAIN_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_NONE);
        addSyntaxStyle(CLOJURE_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_CLOJURE);
        addSyntaxStyle(GROOVY_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_GROOVY);
        addSyntaxStyle(JAVASCRIPT_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        addSyntaxStyle(PYTHON_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_PYTHON);
        addSyntaxStyle(RUBY_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_RUBY);
        addSyntaxStyle(SCALA_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_SCALA);
        addSyntaxStyle(HTML_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_HTML);
        addSyntaxStyle(CSS_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_CSS);

        initActions();

        setPopupMenu(null);

        setHyperlinksEnabled(false);

        setAntiAliasingEnabled(true);

        // XXX Changed to `false` to avoid scrolling performance degradation due to wrapped text
        // (Issue 1160).
        setLineWrap(false);

        setHighlightCurrentLine(false);
        setFadeCurrentLineHighlight(false);

        setWhitespaceVisible(false);
        setEOLMarkersVisible(false);

        setMarkOccurrences(false);

        setBracketMatchingEnabled(false);
        setAnimateBracketMatching(false);

        setAutoIndentEnabled(false);
        setCloseCurlyBraces(false);
        setCloseMarkupTags(false);
        setClearWhitespaceLinesEnabled(false);

        Font font;
        if (!FontUtils.isDefaultFontSet()) {
            // Use default RSyntaxTextArea font instead but with correct font size.
            font = FontUtils.getFont(this.getFont().getFontName());
        } else {
            font = FontUtils.getFont(Font.PLAIN);
        }
        this.setFont(font);

        if (isDarkLaF()) {
            darkLaF = true;
            setLookAndFeel(true);
        } else {
            darkLaF = false;
        }
    }

    @Override
    protected JPopupMenu createPopupMenu() {
        return null;
    }

    public Vector<SyntaxStyle> getSyntaxStyles() {
        return syntaxStyles;
    }

    protected void addSyntaxStyle(String label, String styleKey) {
        syntaxStyles.add(new SyntaxStyle(label, styleKey));
    }

    private void initActions() {
        if (syntaxMenu == null) {
            syntaxMenu = new SyntaxMenu();
            viewMenu = new ViewMenu();

            undoAction = new TextAreaMenuItem(RTextArea.UNDO_ACTION, true, false);
            redoAction = new TextAreaMenuItem(RTextArea.REDO_ACTION, false, true);

            cutAction = new TextAreaMenuItem(RTextArea.CUT_ACTION, false, false);
            copyAction = new TextAreaMenuItem(RTextArea.COPY_ACTION, false, false);
            pasteAction = new TextAreaMenuItem(RTextArea.PASTE_ACTION, false, false);
            deleteAction = new TextAreaMenuItem(RTextArea.DELETE_ACTION, false, true);

            selectAllAction = new TextAreaMenuItem(RTextArea.SELECT_ALL_ACTION, false, false);
            final List<JMenuItem> mainPopupMenuItems = View.getSingleton().getPopupList();

            mainPopupMenuItems.add(syntaxMenu);
            mainPopupMenuItems.add(viewMenu);

            mainPopupMenuItems.add(undoAction);
            mainPopupMenuItems.add(redoAction);

            mainPopupMenuItems.add(cutAction);
            mainPopupMenuItems.add(copyAction);
            mainPopupMenuItems.add(pasteAction);
            mainPopupMenuItems.add(deleteAction);

            mainPopupMenuItems.add(selectAllAction);
        }
    }

    private void setLookAndFeel(boolean dark) {
        try {
            Theme theme =
                    Theme.load(
                            this.getClass()
                                    .getResourceAsStream(dark ? RESOURCE_DARK : RESOURCE_LIGHT));

            theme.apply(this);
        } catch (IOException e) {
            // Ignore
        }
    }

    private boolean isDarkLaF() {
        // TODO Update to calling the DisplayUtils.isDarkLookAndFeel() method directly once it is
        // available
        if (supportsDarkLaF == null) {
            supportsDarkLaF = false;
            try {
                Class<DisplayUtils> cls = DisplayUtils.class;
                isDarkLookAndFeelMethod = cls.getMethod("isDarkLookAndFeel");
                if (isDarkLookAndFeelMethod != null) {
                    supportsDarkLaF = true;
                }
            } catch (Exception e) {
                // Ignore
            }
        }
        if (isDarkLookAndFeelMethod != null) {
            try {
                Object obj = isDarkLookAndFeelMethod.invoke(null);
                if (obj instanceof Boolean) {
                    return (Boolean) obj;
                }
            } catch (Exception e) {
                // Ignore
            }
        }
        return false;
    }

    @Override
    public void updateUI() {
        super.updateUI();
        if (darkLaF != null && darkLaF != isDarkLaF()) {
            if (isDarkLaF()) {
                darkLaF = true;
            } else {
                darkLaF = false;
            }
            setLookAndFeel(darkLaF);
        }
    }

    void unload() {
        final List<JMenuItem> mainPopupMenuItems = View.getSingleton().getPopupList();
        mainPopupMenuItems.remove(syntaxMenu);
        mainPopupMenuItems.remove(viewMenu);

        mainPopupMenuItems.remove(undoAction);
        mainPopupMenuItems.remove(redoAction);

        mainPopupMenuItems.remove(cutAction);
        mainPopupMenuItems.remove(copyAction);
        mainPopupMenuItems.remove(pasteAction);
        mainPopupMenuItems.remove(deleteAction);

        mainPopupMenuItems.remove(selectAllAction);
    }

    public static class SyntaxStyle {
        private String label;
        private String styleKey;

        public SyntaxStyle(String label, String styleKey) {
            this.label = label;
            this.styleKey = styleKey;
        }

        public String getLabel() {
            return label;
        }

        public String getStyleKey() {
            return styleKey;
        }
    }

    protected static class CustomTokenMakerFactory extends AbstractTokenMakerFactory {

        @Override
        protected void initTokenMakerMap() {
            String pkg = "org.fife.ui.rsyntaxtextarea.modes.";
            putMapping(SYNTAX_STYLE_NONE, pkg + "PlainTextTokenMaker");
        }
    }

    private static class TextAreaMenuItem extends ExtensionPopupMenuItem {

        private static final long serialVersionUID = -8369459846515841057L;

        private int actionId;
        private boolean precedeWithSeparator;
        private boolean succeedWithSeparator;

        public TextAreaMenuItem(
                int actionId, boolean precedeWithSeparator, boolean succeedWithSeparator)
                throws IllegalArgumentException {
            this.actionId = actionId;
            this.precedeWithSeparator = precedeWithSeparator;
            this.succeedWithSeparator = succeedWithSeparator;
            Action action = RTextArea.getAction(actionId);
            if (action == null) {
                throw new IllegalArgumentException("Action not found with id: " + actionId);
            }
            setAction(action);
        }

        @Override
        public boolean isEnableForComponent(Component invoker) {
            if (invoker instanceof SyntaxHighlightTextArea) {
                SyntaxHighlightTextArea httpPanelTextArea = (SyntaxHighlightTextArea) invoker;

                switch (actionId) {
                    case RTextArea.CUT_ACTION:
                        if (!httpPanelTextArea.isEditable()) {
                            this.setEnabled(false);
                        }
                        break;
                    case RTextArea.DELETE_ACTION:
                    case RTextArea.PASTE_ACTION:
                        this.setEnabled(httpPanelTextArea.isEditable());
                        break;
                    case RTextArea.SELECT_ALL_ACTION:
                        this.setEnabled(httpPanelTextArea.getDocument().getLength() != 0);
                        break;
                }

                return true;
            }
            return false;
        }

        @Override
        public boolean precedeWithSeparator() {
            return precedeWithSeparator;
        }

        @Override
        public boolean succeedWithSeparator() {
            return succeedWithSeparator;
        }

        @Override
        public boolean isSafe() {
            return true;
        }
    }
}
