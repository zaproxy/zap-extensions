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
package org.zaproxy.zap.extension.websocket.ui.httppanel.views;

import java.awt.Color;
import java.awt.Component;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.text.BadLocationException;
import org.apache.log4j.Logger;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextView;
import org.zaproxy.zap.extension.httppanel.view.util.CaretVisibilityEnforcerOnFocusGain;
import org.zaproxy.zap.extension.search.SearchMatch;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.messagelocations.TextWebSocketMessageLocation;
import org.zaproxy.zap.extension.websocket.ui.httppanel.SelectableContentWebSocketMessageContainer;
import org.zaproxy.zap.extension.websocket.ui.httppanel.models.StringWebSocketPanelViewModel;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.model.TextHttpMessageLocation;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlight;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlightsManager;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducerFocusListener;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducerFocusListenerAdapter;
import org.zaproxy.zap.view.messagelocation.TextMessageLocationHighlight;
import org.zaproxy.zap.view.messagelocation.TextMessageLocationHighlightsManager;

public class WebSocketSyntaxHighlightTextView extends HttpPanelSyntaxHighlightTextView
        implements SelectableContentWebSocketMessageContainer {

    public static final String NAME = "WebSocketSyntaxHighlightTextView";

    private MessageLocationProducerFocusListenerAdapter focusListenerAdapter;

    public WebSocketSyntaxHighlightTextView(StringWebSocketPanelViewModel model) {
        super(model);

        getHttpPanelTextArea()
                .setComponentPopupMenu(
                        new CustomPopupMenu() {

                            private static final long serialVersionUID = 377256890518967680L;

                            @Override
                            public void show(Component invoker, int x, int y) {
                                if (!getHttpPanelTextArea().isFocusOwner()) {
                                    getHttpPanelTextArea().requestFocusInWindow();
                                }

                                View.getSingleton()
                                        .getPopupMenu()
                                        .show(WebSocketSyntaxHighlightTextView.this, x, y);
                            }
                        });
    }

    @Override
    protected WebSocketSyntaxHighlightTextArea createHttpPanelTextArea() {
        return new WebSocketSyntaxHighlightTextArea();
    }

    @Override
    public void setEditable(boolean editable) {
        super.setEditable(editable);
        ((StringWebSocketPanelViewModel) getModel()).setEditable(editable);
    }

    @Override
    protected WebSocketSyntaxHighlightTextArea getHttpPanelTextArea() {
        return (WebSocketSyntaxHighlightTextArea) super.getHttpPanelTextArea();
    }

    protected static class WebSocketSyntaxHighlightTextArea
            extends HttpPanelSyntaxHighlightTextArea {

        private static final long serialVersionUID = -6469629120424801024L;

        private static final Logger LOGGER =
                Logger.getLogger(WebSocketSyntaxHighlightTextArea.class);

        private static final String CSS =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.css");
        private static final String HTML =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.html");
        private static final String JAVASCRIPT =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.javascript");
        private static final String JSON =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.json");
        private static final String XML =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.xml");

        private static WebSocketTokenMakerFactory tokenMakerFactory = null;

        private CaretVisibilityEnforcerOnFocusGain caretVisiblityEnforcer;

        public WebSocketSyntaxHighlightTextArea() {
            addSyntaxStyle(CSS, SyntaxConstants.SYNTAX_STYLE_CSS);
            addSyntaxStyle(HTML, SyntaxConstants.SYNTAX_STYLE_HTML);
            addSyntaxStyle(JAVASCRIPT, SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
            addSyntaxStyle(JSON, SyntaxConstants.SYNTAX_STYLE_JSON);
            addSyntaxStyle(XML, SyntaxConstants.SYNTAX_STYLE_XML);

            caretVisiblityEnforcer = new CaretVisibilityEnforcerOnFocusGain(this);
        }

        @Override
        public WebSocketMessageDTO getMessage() {
            return (WebSocketMessageDTO) super.getMessage();
        }

        @Override
        public void setMessage(Message aMessage) {
            super.setMessage(aMessage);

            caretVisiblityEnforcer.setEnforceVisibilityOnFocusGain(aMessage != null);
        }

        @Override
        public void search(Pattern p, List<SearchMatch> matches) {
            Matcher m = p.matcher(getText());
            while (m.find()) {
                matches.add(new SearchMatch(null, m.start(), m.end()));
            }
        }

        @Override
        public void highlight(SearchMatch sm) {
            int len = getText().length();
            if (sm.getStart() > len || sm.getEnd() > len) {
                return;
            }

            highlight(sm.getStart(), sm.getEnd());
        }

        protected MessageLocation getSelection() {
            try {
                int start = getSelectionStart();
                int end = getSelectionEnd();

                return new TextWebSocketMessageLocation(start, end, getText(start, end - start));
            } catch (BadLocationException e) {
                // Shouldn't happen, but in case it does log it and return...
                LOGGER.error(e.getMessage(), e);
                return new TextWebSocketMessageLocation(0);
            }
        }

        protected MessageLocationHighlightsManager create() {
            return new TextMessageLocationHighlightsManager();
        }

        protected MessageLocationHighlight highlightImpl(
                TextWebSocketMessageLocation textLocation,
                TextMessageLocationHighlight textHighlight) {
            if (getMessage() == null) {
                return null;
            }

            int start = textLocation.getStart();
            int end = textLocation.getEnd();

            textHighlight.setHighlightReference(highlight(start, end, textHighlight));

            return textHighlight;
        }

        @Override
        protected synchronized CustomTokenMakerFactory getTokenMakerFactory() {
            if (tokenMakerFactory == null) {
                tokenMakerFactory = new WebSocketTokenMakerFactory();
            }
            return tokenMakerFactory;
        }

        private static class WebSocketTokenMakerFactory extends CustomTokenMakerFactory {

            public WebSocketTokenMakerFactory() {
                String pkg = "org.fife.ui.rsyntaxtextarea.modes.";

                putMapping(SYNTAX_STYLE_CSS, pkg + "CSSTokenMaker");
                putMapping(SYNTAX_STYLE_HTML, pkg + "HTMLTokenMaker");
                putMapping(SYNTAX_STYLE_JAVASCRIPT, pkg + "JavaScriptTokenMaker");
                putMapping(SYNTAX_STYLE_JSON, pkg + "JsonTokenMaker");
                putMapping(SYNTAX_STYLE_XML, pkg + "XMLTokenMaker");
            }
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Class<WebSocketMessageDTO> getMessageClass() {
        return WebSocketMessageDTO.class;
    }

    @Override
    public Class<? extends MessageLocation> getMessageLocationClass() {
        return TextHttpMessageLocation.class;
    }

    @Override
    public MessageLocation getSelection() {
        return getHttpPanelTextArea().getSelection();
    }

    @Override
    public MessageLocationHighlightsManager create() {
        return getHttpPanelTextArea().create();
    }

    @Override
    public MessageLocationHighlight highlight(MessageLocation location) {
        if (!supports(location)) {
            return null;
        }
        TextWebSocketMessageLocation textLocation = (TextWebSocketMessageLocation) location;

        return getHttpPanelTextArea()
                .highlightImpl(textLocation, new TextMessageLocationHighlight(Color.LIGHT_GRAY));
    }

    @Override
    public MessageLocationHighlight highlight(
            MessageLocation location, MessageLocationHighlight highlight) {
        if (!supports(location) || !(highlight instanceof TextMessageLocationHighlight)) {
            return null;
        }
        TextWebSocketMessageLocation textLocation = (TextWebSocketMessageLocation) location;
        TextMessageLocationHighlight textHighlight = (TextMessageLocationHighlight) highlight;

        return getHttpPanelTextArea().highlightImpl(textLocation, textHighlight);
    }

    @Override
    public void removeHighlight(
            MessageLocation location, MessageLocationHighlight highlightReference) {
        if (!(highlightReference instanceof TextMessageLocationHighlight)) {
            return;
        }
        getHttpPanelTextArea()
                .removeHighlight(
                        ((TextMessageLocationHighlight) highlightReference)
                                .getHighlightReference());
    }

    @Override
    public boolean supports(MessageLocation location) {
        if (!(location instanceof TextWebSocketMessageLocation)) {
            return false;
        }
        return true;
    }

    @Override
    public boolean supports(Class<? extends MessageLocation> classLocation) {
        return (TextHttpMessageLocation.class.isAssignableFrom(classLocation));
    }

    @Override
    public void addFocusListener(MessageLocationProducerFocusListener focusListener) {
        getFocusListenerAdapter().addFocusListener(focusListener);
    }

    @Override
    public void removeFocusListener(MessageLocationProducerFocusListener focusListener) {
        getFocusListenerAdapter().removeFocusListener(focusListener);

        if (!getFocusListenerAdapter().hasFocusListeners()) {
            getHttpPanelTextArea().removeFocusListener(focusListenerAdapter);
            focusListenerAdapter = null;
        }
    }

    @Override
    public WebSocketMessageDTO getMessage() {
        return getHttpPanelTextArea().getMessage();
    }

    @Override
    public Component getComponent() {
        return getHttpPanelTextArea();
    }

    @Override
    public boolean isEmpty() {
        return getHttpPanelTextArea().getMessage() == null;
    }

    private MessageLocationProducerFocusListenerAdapter getFocusListenerAdapter() {
        if (focusListenerAdapter == null) {
            focusListenerAdapter = new MessageLocationProducerFocusListenerAdapter(this);
            getHttpPanelTextArea().addFocusListener(focusListenerAdapter);
        }
        return focusListenerAdapter;
    }
}
