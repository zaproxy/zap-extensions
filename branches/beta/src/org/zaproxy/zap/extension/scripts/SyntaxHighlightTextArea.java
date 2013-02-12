/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.scripts;

import java.awt.Component;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.swing.Action;
import javax.swing.JPopupMenu;
import javax.swing.JViewport;

import org.apache.commons.configuration.FileConfiguration;
import org.fife.ui.rsyntaxtextarea.AbstractTokenMakerFactory;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextArea;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionPopupMenuItem;
import org.parosproxy.paros.view.View;

public class SyntaxHighlightTextArea extends RSyntaxTextArea {

	private static final long serialVersionUID = -9082089105656842054L;

	public static final String PLAIN_SYNTAX_LABEL = Constant.messages.getString("scripts.syntaxtext.syntax.plain");
	public static final String CLOJURE_SYNTAX_LABEL = Constant.messages.getString("scripts.syntaxtext.syntax.clojure");
	public static final String GROOVY_SYNTAX_LABEL = Constant.messages.getString("scripts.syntaxtext.syntax.groovy");
	public static final String JAVASCRIPT_SYNTAX_LABEL = Constant.messages.getString("scripts.syntaxtext.syntax.javascript");
	public static final String PYTHON_SYNTAX_LABEL = Constant.messages.getString("scripts.syntaxtext.syntax.python");
	public static final String RUBY_SYNTAX_LABEL = Constant.messages.getString("scripts.syntaxtext.syntax.ruby");
	public static final String SCALA_SYNTAX_LABEL = Constant.messages.getString("scripts.syntaxtext.syntax.scala");

	private static final String ANTI_ALIASING = "aa";
	private static final String SHOW_LINE_NUMBERS = "linenumbers";
	private static final String WORD_WRAP = "wordwrap";
	private static final String HIGHLIGHT_CURRENT_LINE = "highlightline";
	private static final String FADE_CURRENT_HIGHLIGHT_LINE = "fadehighlightline";
	private static final String SHOW_WHITESPACE_CHARACTERS = "whitespaces";
	private static final String SHOW_NEWLINE_CHARACTERS = "newlines";
	private static final String MARK_OCCURRENCES = "markocurrences";
	private static final String ROUNDED_SELECTION_EDGES = "roundedselection";
	private static final String BRACKET_MATCHING = "bracketmatch";
	private static final String ANIMATED_BRACKET_MATCHING = "animatedbracketmatch";

	
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
	
	static {
		//Hack to set the language that is used by ZAP.
		RTextArea.setLocaleI18n(Constant.getLocale());
	}
	
	public SyntaxHighlightTextArea() {
		// TODO hacking...
		setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		
		syntaxStyles = new Vector<>();
		addSyntaxStyle(PLAIN_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_NONE);
		addSyntaxStyle(CLOJURE_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_CLOJURE);
		addSyntaxStyle(GROOVY_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_GROOVY);
		addSyntaxStyle(JAVASCRIPT_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
		addSyntaxStyle(PYTHON_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_PYTHON);
		addSyntaxStyle(RUBY_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_RUBY);
		addSyntaxStyle(SCALA_SYNTAX_LABEL, SyntaxConstants.SYNTAX_STYLE_SCALA);
		
		initActions();
		
		setPopupMenu(null);
		
		setHyperlinksEnabled(false);

		setAntiAliasingEnabled(true);

		setLineWrap(true);
		
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
	}
	
	@Override
	protected JPopupMenu createPopupMenu() {
		return null;
	}
	
	public void loadConfiguration(String key, FileConfiguration fileConfiguration) {
		setAntiAliasingEnabled(fileConfiguration.getBoolean(key + ANTI_ALIASING, this.getAntiAliasingEnabled()));
		
		Component c = getParent();
		if (c instanceof JViewport) {
			c = c.getParent();
			if (c instanceof RTextScrollPane) {
				final RTextScrollPane scrollPane = (RTextScrollPane)c;
				scrollPane.setLineNumbersEnabled(fileConfiguration.getBoolean(key + SHOW_LINE_NUMBERS, scrollPane.getLineNumbersEnabled()));
			}
		}
		
		setLineWrap(fileConfiguration.getBoolean(key + WORD_WRAP, this.getLineWrap()));
		
		setHighlightCurrentLine(fileConfiguration.getBoolean(key + HIGHLIGHT_CURRENT_LINE, this.getHighlightCurrentLine()));
		setFadeCurrentLineHighlight(fileConfiguration.getBoolean(key + FADE_CURRENT_HIGHLIGHT_LINE, this.getFadeCurrentLineHighlight()));
		
		setWhitespaceVisible(fileConfiguration.getBoolean(key + SHOW_WHITESPACE_CHARACTERS, this.isWhitespaceVisible()));
		setEOLMarkersVisible(fileConfiguration.getBoolean(key + SHOW_NEWLINE_CHARACTERS, this.getEOLMarkersVisible()));
		
		setMarkOccurrences(fileConfiguration.getBoolean(key + MARK_OCCURRENCES, this.getMarkOccurrences()));
		
		setRoundedSelectionEdges(fileConfiguration.getBoolean(key + ROUNDED_SELECTION_EDGES, this.getRoundedSelectionEdges()));
		
		setBracketMatchingEnabled(fileConfiguration.getBoolean(key + BRACKET_MATCHING, this.isBracketMatchingEnabled()));
		setAnimateBracketMatching(fileConfiguration.getBoolean(key + ANIMATED_BRACKET_MATCHING, this.getAnimateBracketMatching()));
		
	}
	
	public void saveConfiguration(String key, FileConfiguration fileConfiguration) {
		fileConfiguration.setProperty(key + ANTI_ALIASING, Boolean.valueOf(this.getAntiAliasingEnabled()));
		
		Component c = getParent();
		if (c instanceof JViewport) {
			c = c.getParent();
			if (c instanceof RTextScrollPane) {
				final RTextScrollPane scrollPane = (RTextScrollPane)c;
				fileConfiguration.setProperty(key + SHOW_LINE_NUMBERS, Boolean.valueOf(scrollPane.getLineNumbersEnabled()));
			}
		}
		
		fileConfiguration.setProperty(key + WORD_WRAP, Boolean.valueOf(this.getLineWrap()));
		
		fileConfiguration.setProperty(key + HIGHLIGHT_CURRENT_LINE, Boolean.valueOf(this.getHighlightCurrentLine()));
		fileConfiguration.setProperty(key + FADE_CURRENT_HIGHLIGHT_LINE, Boolean.valueOf(this.getFadeCurrentLineHighlight()));
		
		fileConfiguration.setProperty(key + SHOW_WHITESPACE_CHARACTERS, Boolean.valueOf(this.isWhitespaceVisible()));
		fileConfiguration.setProperty(key + SHOW_NEWLINE_CHARACTERS, Boolean.valueOf(this.getEOLMarkersVisible()));
		
		fileConfiguration.setProperty(key + MARK_OCCURRENCES, Boolean.valueOf(this.getMarkOccurrences()));
		
		fileConfiguration.setProperty(key + ROUNDED_SELECTION_EDGES, Boolean.valueOf(this.getRoundedSelectionEdges()));
		
		fileConfiguration.setProperty(key + BRACKET_MATCHING, Boolean.valueOf(this.isBracketMatchingEnabled()));
		fileConfiguration.setProperty(key + ANIMATED_BRACKET_MATCHING, Boolean.valueOf(this.getAnimateBracketMatching()));
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
			
			View.getSingleton().getPopupMenu().addMenu(syntaxMenu);
			View.getSingleton().getPopupMenu().addMenu(viewMenu);
			
			View.getSingleton().getPopupMenu().addMenu(undoAction);
			View.getSingleton().getPopupMenu().addMenu(redoAction);
			
			View.getSingleton().getPopupMenu().addMenu(cutAction);
			View.getSingleton().getPopupMenu().addMenu(copyAction);
			View.getSingleton().getPopupMenu().addMenu(pasteAction);
			View.getSingleton().getPopupMenu().addMenu(deleteAction);
			
			View.getSingleton().getPopupMenu().addMenu(selectAllAction);
		}
	}
	
	void unload() {
		View.getSingleton().getPopupMenu().removeMenu(syntaxMenu);
		View.getSingleton().getPopupMenu().removeMenu(viewMenu);
		
		View.getSingleton().getPopupMenu().removeMenu(undoAction);
		View.getSingleton().getPopupMenu().removeMenu(redoAction);
		
		View.getSingleton().getPopupMenu().removeMenu(cutAction);
		View.getSingleton().getPopupMenu().removeMenu(copyAction);
		View.getSingleton().getPopupMenu().removeMenu(pasteAction);
		View.getSingleton().getPopupMenu().removeMenu(deleteAction);
		
		View.getSingleton().getPopupMenu().removeMenu(selectAllAction);
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
		protected Map<String, String> createTokenMakerKeyToClassNameMap() {
			HashMap<String, String> map = new HashMap<>();

			String pkg = "org.fife.ui.rsyntaxtextarea.modes.";
			map.put(SYNTAX_STYLE_NONE, pkg + "PlainTextTokenMaker");
			
			return map;
		}
	}
	
	private static class TextAreaMenuItem extends ExtensionPopupMenuItem {
		
		private static final long serialVersionUID = -8369459846515841057L;
		
		private int actionId;
		private boolean precedeWithSeparator;
		private boolean succeedWithSeparator;
		
		public TextAreaMenuItem(int actionId, boolean precedeWithSeparator, boolean succeedWithSeparator) throws IllegalArgumentException {
			this.actionId = actionId;
			this.precedeWithSeparator = precedeWithSeparator;
			this.succeedWithSeparator = succeedWithSeparator;
			Action action = RTextArea.getAction(actionId);
			if(action == null) {
				throw new IllegalArgumentException("Action not found with id: " + actionId);
			}
			setAction(action);
		}
		
		@Override
		public boolean isEnableForComponent(Component invoker) {
			if (invoker instanceof SyntaxHighlightTextArea) {
				SyntaxHighlightTextArea httpPanelTextArea = (SyntaxHighlightTextArea)invoker;
				
				switch(actionId) {
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
	}

}
