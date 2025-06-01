/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.addon.requester.internal;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.HeadlessException;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import javax.swing.SwingConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.requester.ExtensionRequester;
import org.zaproxy.addon.requester.MessageEditorPanel;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.httppanel.HttpPanel.OptionsLocation;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.search.SearchMatch;
import org.zaproxy.zap.extension.search.SearchMatch.Location;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.HttpPanelManager;

@SuppressWarnings("serial")
public class ManualHttpRequestEditorPanel extends MessageEditorPanel
        implements OptionsChangedListener, LayoutChangedListener {

    private static final long serialVersionUID = -5830450800029295419L;
    private static final Logger LOGGER = LogManager.getLogger(ManualHttpRequestEditorPanel.class);
    private static final String CONFIG_KEY = "requesterpanel";
    private static final String HELP_KEY = "addon.requester.tab";

    private HttpPanelSender sender;

    private RequestResponsePanel requestResponsePanel;
    private CustomHttpPanelRequest requestPanel;
    private CustomHttpPanelResponse responsePanel;

    private JToolBar footerToolbar = null;
    // footer elements
    private JLabel labelTimeElapse = null;
    private JLabel labelContentLength = null;
    private JLabel labelTotalLength = null;
    private String helpKey = null;
    private int defaultView;

    // Find elements
    private JLabel matchLabel;
    private ZapTextField findField;
    private JButton prevButton;
    private JButton nextButton;

    private Location lastLocation;
    private int matchIndex;
    private List<SearchMatch> matches = new ArrayList<>();

    public ManualHttpRequestEditorPanel() {
        this(CONFIG_KEY, HELP_KEY, RequestResponsePanel.SIDE_BY_SIDE_VIEW);
    }

    public ManualHttpRequestEditorPanel(String configurationKey) throws HeadlessException {
        this(configurationKey, "addon.requester.dialogs", RequestResponsePanel.TABS_VIEW);
    }

    private ManualHttpRequestEditorPanel(String configurationKey, String helpKey, int defaultView)
            throws HeadlessException {
        super(true, configurationKey);
        this.defaultView = defaultView;
        this.helpKey = helpKey;
        sender = new HttpPanelSender(getMessagePanel(), getResponsePanel());

        initialize();
    }

    @Override
    protected void initialize() {
        super.initialize();

        // add footer status bar
        getWindowPanel().add(getFooterStatusBar(), BorderLayout.SOUTH);

        getFindField()
                .getDocument()
                .addDocumentListener(
                        new DocumentListener() {

                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                find();
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                find();
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                find();
                            }
                        });

        getFooterStatusBar()
                .add(new JLabel(Constant.messages.getString("requester.httppanel.find.find")));
        getFooterStatusBar().add(getFindField());
        getFooterStatusBar().add(getPrevButton());
        getFooterStatusBar().add(getNextButton());
        getFooterStatusBar().add(getMatchLabel());

        getFooterStatusBar().add(Box.createHorizontalGlue());

        // setting footer status bar label and separator
        getFooterStatusBar().add(getLabelTimeLapse());
        getFooterStatusBar().addSeparator();
        getFooterStatusBar().add(getLabelContentLength());
        getFooterStatusBar().addSeparator();
        getFooterStatusBar().add(getLabelTotalLength());
    }

    private JButton getPrevButton() {
        if (prevButton == null) {
            prevButton = new JButton(ExtensionRequester.createIcon("fugue/arrow-090-medium.png"));
            prevButton.setToolTipText(Constant.messages.getString("requester.httppanel.find.prev"));
            prevButton.addActionListener(a -> prev());
        }
        return prevButton;
    }

    private JButton getNextButton() {
        if (nextButton == null) {
            nextButton = new JButton(ExtensionRequester.createIcon("fugue/arrow-270-medium.png"));
            nextButton.setToolTipText(Constant.messages.getString("requester.httppanel.find.next"));
            nextButton.addActionListener(a -> next());
        }
        return nextButton;
    }

    private ZapTextField getFindField() {
        if (findField == null) {
            findField = new ZapTextField(20);
            findField.setMaximumSize(findField.getPreferredSize());
        }
        return findField;
    }

    private JLabel getMatchLabel() {
        if (matchLabel == null) {
            matchLabel = new JLabel();
        }
        return matchLabel;
    }

    private void highlight() {
        clearHighlight();
        if (matches.size() > 0) {
            SearchMatch sm = matches.get(matchIndex);
            // For some reason the message is not set in the matches :/
            SearchMatch sm2 =
                    new SearchMatch(
                            (HttpMessage) this.getMessage(),
                            sm.getLocation(),
                            sm.getStart(),
                            sm.getEnd());
            this.setHighlight(sm2);
            lastLocation = sm2.getLocation();
            if (matches.size() == 1) {
                getMatchLabel()
                        .setText(
                                Constant.messages.getString(
                                        "requester.httppanel.find.find.match.1"));
            } else {
                getMatchLabel()
                        .setText(
                                Constant.messages.getString(
                                        "requester.httppanel.find.find.match.x",
                                        matchIndex + 1,
                                        matches.size()));
            }
        } else {
            getMatchLabel()
                    .setText(Constant.messages.getString("requester.httppanel.find.find.match.0"));
            lastLocation = null;
        }
        getPrevButton().setEnabled(matches.size() > 1);
        getNextButton().setEnabled(matches.size() > 1);
    }

    private void prev() {
        matchIndex--;
        if (matchIndex < 0) {
            matchIndex = matches.size() - 1;
        }
        highlight();
    }

    private void next() {
        matchIndex++;
        if (matchIndex >= matches.size()) {
            matchIndex = 0;
        }
        highlight();
    }

    @Override
    public void layoutChanged() {
        find();
    }

    private void find() {
        matches.clear();
        clearHighlight();
        lastLocation = null;
        matchIndex = 0;
        String str = getFindField().getText();
        if (str.isEmpty()) {
            getMatchLabel().setText("");
        } else {
            Pattern p = Pattern.compile(Pattern.quote(str), Pattern.CASE_INSENSITIVE);
            requestPanel.headerSearch(p, matches);
            if (!requestPanel.isCombinedView()) {
                requestPanel.bodySearch(p, matches);
            }
            responsePanel.headerSearch(p, matches);
            if (!responsePanel.isCombinedView()) {
                responsePanel.bodySearch(p, matches);
            }
        }
        highlight();
    }

    private void clearHighlight() {
        if (lastLocation != null) {
            setHighlight(
                    new SearchMatch((HttpMessage) requestPanel.getMessage(), lastLocation, 0, 0));
        }
    }

    private void setHighlight(SearchMatch sm) {
        switch (sm.getLocation()) {
            case REQUEST_BODY:
                requestPanel.highlightBody(sm);
                requestPanel.setTabFocus();
                break;
            case REQUEST_HEAD:
                requestPanel.highlightHeader(sm);
                requestPanel.setTabFocus();
                break;
            case RESPONSE_BODY:
                responsePanel.highlightBody(sm);
                responsePanel.setTabFocus();
                break;
            case RESPONSE_HEAD:
                responsePanel.highlightHeader(sm);
                responsePanel.setTabFocus();
                break;
            default:
                break;
        }
    }

    @Override
    public void setVisible(boolean show) {
        super.setVisible(show);

        switchToTab(0);
    }

    @Override
    public Message getMessage() {
        return getMessagePanel().getMessage();
    }

    @Override
    public void setMessage(Message aMessage) {
        if (aMessage == null) {
            this.lastLocation = null;
            this.matches.clear();
            this.matchIndex = 0;
            return;
        }

        getMessagePanel().setMessage(aMessage);
        getResponsePanel().setMessage(aMessage);
        setFooterStatus(null);
        switchToTab(0);
        find();
    }

    @Override
    protected void sendMessage(Message message) throws IOException {
        sender.sendMessage(message);
    }

    @Override
    protected CustomHttpPanelRequest getMessagePanel() {
        if (requestPanel == null) {
            requestPanel = new CustomHttpPanelRequest(true, configurationKey);
            requestPanel.setEnableViewSelect(true);
            requestPanel.loadConfig(Model.getSingleton().getOptionsParam().getConfig());
        }
        return requestPanel;
    }

    private CustomHttpPanelResponse getResponsePanel() {
        if (responsePanel == null) {
            responsePanel = new CustomHttpPanelResponse(false, configurationKey);
            responsePanel.setEnableViewSelect(true);

            responsePanel.loadConfig(Model.getSingleton().getOptionsParam().getConfig());
        }
        return responsePanel;
    }

    @Override
    protected Component getManualSendPanel() {
        if (requestResponsePanel == null) {
            requestResponsePanel =
                    new RequestResponsePanel(
                            configurationKey,
                            getMessagePanel(),
                            getResponsePanel(),
                            this::sendButtonTriggered,
                            this,
                            defaultView);

            if (helpKey != null) {
                JButton helpButton = new JButton();
                helpButton.setIcon(ExtensionHelp.getHelpIcon());
                helpButton.setToolTipText(
                        Constant.messages.getString("help.dialog.button.tooltip"));
                helpButton.addActionListener(e -> ExtensionHelp.showHelp(helpKey));
                if (!helpKey.equals(HELP_KEY)) {
                    requestResponsePanel.addToolbarButton(helpButton);
                } else {
                    requestResponsePanel.addResponseToolbarButton(
                            helpButton, HttpPanel.OptionsLocation.END);
                }

                requestResponsePanel.addEndButton(getBtnSend());
                requestResponsePanel.addSeparator();
            }

            requestResponsePanel.loadConfig();
        }
        return requestResponsePanel;
    }

    @Override
    protected void btnSendAction() {

        send(requestPanel.getMessage());
    }

    @Override
    protected void postSend() {
        super.postSend();

        switchToTab(1);
        setFooterStatus((HttpMessage) getResponsePanel().getMessage());
        find();
    }

    /**
     * Return the footer status bar object
     *
     * @return
     */
    protected JToolBar getFooterStatusBar() {
        if (footerToolbar == null) {
            footerToolbar = new JToolBar();
            footerToolbar.setEnabled(true);
            footerToolbar.setFloatable(false);
            footerToolbar.setRollover(true);
            footerToolbar.setName("Footer Toolbar Left");
            footerToolbar.setBorder(BorderFactory.createEtchedBorder());
        }
        return footerToolbar;
    }

    private void setFooterStatus(HttpMessage msg) {
        long timeLapse = 0;
        long contentLength = 0;
        long totalLength = 0;
        if (msg != null) {
            contentLength = msg.getResponseBody().length();
            totalLength = msg.getResponseHeader().toString().length() + contentLength;
            timeLapse = msg.getTimeElapsedMillis();
        }
        getLabelTimeLapse()
                .setText(
                        Constant.messages.getString(
                                "requester.httppanel.label.timelapse", timeLapse));
        getLabelContentLength()
                .setText(
                        Constant.messages.getString(
                                "requester.httppanel.label.contentlength", contentLength));
        getLabelTotalLength()
                .setText(
                        Constant.messages.getString(
                                "requester.httppanel.label.totallength", totalLength));
    }

    private void switchToTab(int i) {
        if (requestResponsePanel != null) {
            requestResponsePanel.switchToTab(i);
        }
    }

    @Override
    public void saveConfig() {
        requestResponsePanel.saveConfig();
    }

    @Override
    public void reset() {
        matches.clear();
        lastLocation = null;
        matchIndex = 0;
        getFindField().discardAllEdits();
        getMessagePanel().clearView();
        getResponsePanel().clearView();
        setDefaultMessage();
    }

    @Override
    public void setDefaultMessage() {
        HttpMessage msg = new HttpMessage();
        try {
            URI uri = new URI("http://www.any_domain_name.org/path", true);
            msg.setRequestHeader(
                    new HttpRequestHeader(HttpRequestHeader.GET, uri, HttpHeader.HTTP11));
            setMessage(msg);
        } catch (HttpMalformedHeaderException | URIException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Get Label status time lapse
     *
     * @return
     */
    private JLabel getLabelTimeLapse() {
        if (labelTimeElapse == null) {
            labelTimeElapse = new JLabel("", SwingConstants.LEADING);
        }
        return labelTimeElapse;
    }

    /**
     * Get Label status Content Length
     *
     * @return
     */
    private JLabel getLabelContentLength() {
        if (labelContentLength == null) {
            labelContentLength = new JLabel("", SwingConstants.LEADING);
        }
        return labelContentLength;
    }

    /**
     * Get Label status Total Length
     *
     * @return
     */
    private JLabel getLabelTotalLength() {
        if (labelTotalLength == null) {
            labelTotalLength = new JLabel("", SwingConstants.LEADING);
        }
        return labelTotalLength;
    }

    public static final class RequestResponsePanel extends JPanel {

        private static final String REQUEST_CAPTION =
                Constant.messages.getString("requester.httppanel.tab.request");
        private static final String RESPONSE_CAPTION =
                Constant.messages.getString("requester.httppanel.tab.response");

        private static final String TABS_VIEW_TOOL_TIP =
                Constant.messages.getString("requester.httppanel.display.tabs");
        private static final String ABOVE_VIEW_TOOL_TIP =
                Constant.messages.getString("requester.httppanel.display.above");
        private static final String SIDE_BY_SIDE_VIEW_TOOL_TIP =
                Constant.messages.getString("requester.httppanel.display.sidebyside");

        private static final String SELECTEDLAYOUT_CONFIG_KEY = "selectedlayout";
        private static final String HORIZONTAL_DIVIDER_LOCATION_CONFIG_KEY =
                "horizontalDividerLocation";
        private static final String VERTICAL_DIVIDER_LOCATION_CONFIG_KEY =
                "verticalDividerLocation";

        private static final long serialVersionUID = -3335708932021769432L;

        private static final int TABS_VIEW = 0;
        private static final int ABOVE_VIEW = 1;
        private static final int SIDE_BY_SIDE_VIEW = 2;

        private final CustomHttpPanelRequest requestPanel;
        private final CustomHttpPanelResponse responsePanel;
        private final int defaultView;

        private int currentView;
        private JComponent currentViewPanel;
        private JToggleButton currentButtonView;

        private JToggleButton tabsButtonView;
        private JToggleButton aboveButtonView;
        private JToggleButton sideBySideButtonView;

        private String configurationKey;

        private int verticalDividerLocation;
        private int horizontalDividerLocation;

        private JButton responseSendButton;

        private Runnable sendAction;

        private LayoutChangedListener listener;

        public RequestResponsePanel(
                String configurationKey,
                CustomHttpPanelRequest request,
                CustomHttpPanelResponse response,
                Runnable sendAction,
                LayoutChangedListener listener,
                int defaultView)
                throws IllegalArgumentException {
            super(new BorderLayout());
            if (request == null || response == null) {
                throw new IllegalArgumentException(
                        "The request and response panels cannot be null.");
            }
            this.defaultView = defaultView;

            this.configurationKey = configurationKey;

            this.requestPanel = request;
            this.responsePanel = response;
            this.sendAction = sendAction;
            this.listener = listener;

            this.currentView = -1;

            tabsButtonView = new JToggleButton(ExtensionRequester.createIcon("layout-tabbed.png"));
            tabsButtonView.setToolTipText(TABS_VIEW_TOOL_TIP);

            tabsButtonView.addActionListener(e -> changeView(TABS_VIEW));

            addToolbarButton(tabsButtonView);

            aboveButtonView =
                    new JToggleButton(ExtensionRequester.createIcon("layout-vertical-split.png"));
            aboveButtonView.setToolTipText(ABOVE_VIEW_TOOL_TIP);

            aboveButtonView.addActionListener(e -> changeView(ABOVE_VIEW));

            addToolbarButton(aboveButtonView);

            sideBySideButtonView =
                    new JToggleButton(ExtensionRequester.createIcon("layout-horizontal-split.png"));
            sideBySideButtonView.setToolTipText(SIDE_BY_SIDE_VIEW_TOOL_TIP);

            sideBySideButtonView.addActionListener(e -> changeView(SIDE_BY_SIDE_VIEW));

            addToolbarButton(sideBySideButtonView);

            responsePanel.addOptions(getResponseSendButton(), HttpPanel.OptionsLocation.END);
        }

        public void loadConfig() {
            verticalDividerLocation =
                    Model.getSingleton()
                            .getOptionsParam()
                            .getConfig()
                            .getInt(configurationKey + VERTICAL_DIVIDER_LOCATION_CONFIG_KEY, -1);
            horizontalDividerLocation =
                    Model.getSingleton()
                            .getOptionsParam()
                            .getConfig()
                            .getInt(configurationKey + HORIZONTAL_DIVIDER_LOCATION_CONFIG_KEY, -1);

            changeView(
                    Model.getSingleton()
                            .getOptionsParam()
                            .getConfig()
                            .getInt(configurationKey + SELECTEDLAYOUT_CONFIG_KEY, defaultView));

            requestPanel.loadConfig(Model.getSingleton().getOptionsParam().getConfig());
            responsePanel.loadConfig(Model.getSingleton().getOptionsParam().getConfig());
        }

        public void saveConfig() {
            switch (currentView) {
                case ABOVE_VIEW:
                    verticalDividerLocation = ((JSplitPane) currentViewPanel).getDividerLocation();
                    break;
                case SIDE_BY_SIDE_VIEW:
                    horizontalDividerLocation =
                            ((JSplitPane) currentViewPanel).getDividerLocation();
                    break;
                default:
            }

            Model.getSingleton()
                    .getOptionsParam()
                    .getConfig()
                    .setProperty(
                            configurationKey + VERTICAL_DIVIDER_LOCATION_CONFIG_KEY,
                            Integer.valueOf(verticalDividerLocation));
            Model.getSingleton()
                    .getOptionsParam()
                    .getConfig()
                    .setProperty(
                            configurationKey + HORIZONTAL_DIVIDER_LOCATION_CONFIG_KEY,
                            Integer.valueOf(horizontalDividerLocation));

            Model.getSingleton()
                    .getOptionsParam()
                    .getConfig()
                    .setProperty(
                            configurationKey + SELECTEDLAYOUT_CONFIG_KEY,
                            Integer.valueOf(currentView));

            requestPanel.saveConfig(Model.getSingleton().getOptionsParam().getConfig());
            responsePanel.saveConfig(Model.getSingleton().getOptionsParam().getConfig());
        }

        public void addToolbarButton(JToggleButton button) {
            requestPanel.addOptions(button, HttpPanel.OptionsLocation.AFTER_COMPONENTS);
        }

        public void addToolbarButton(JButton button) {
            requestPanel.addOptions(button, HttpPanel.OptionsLocation.AFTER_COMPONENTS);
        }

        public void addResponseToolbarButton(JButton button, OptionsLocation location) {
            responsePanel.addOptions(button, location);
        }

        public void addSeparator() {
            requestPanel.addOptionsSeparator();
        }

        public void addEndButton(JButton button) {
            requestPanel.addOptions(button, HttpPanel.OptionsLocation.END);
        }

        public void switchToTab(int i) {
            if (currentView == TABS_VIEW) {
                ((JTabbedPane) currentViewPanel).setSelectedIndex(i);
            }
        }

        public void changeView(int newView) {
            if (newView != currentView) {
                final int oldView = currentView;
                currentView = newView;

                if (oldView != -1) {
                    this.removeAll();
                    currentButtonView.setSelected(false);

                    switch (oldView) {
                        case ABOVE_VIEW:
                            verticalDividerLocation =
                                    ((JSplitPane) currentViewPanel).getDividerLocation();
                            break;
                        case SIDE_BY_SIDE_VIEW:
                            horizontalDividerLocation =
                                    ((JSplitPane) currentViewPanel).getDividerLocation();
                            break;
                        default:
                    }
                }

                switch (newView) {
                    case TABS_VIEW:
                        switchToTabsView();
                        break;
                    case ABOVE_VIEW:
                        switchToAboveView();
                        break;
                    case SIDE_BY_SIDE_VIEW:
                        switchToSideBySideView();
                        break;
                    default:
                        switchToTabsView();
                        break;
                }

                currentButtonView.setSelected(true);

                this.add(currentViewPanel);

                this.validate();
                this.repaint();
                if (this.listener != null) {
                    this.listener.layoutChanged();
                }
            }
        }

        private void switchToTabsView() {
            currentView = TABS_VIEW;
            currentButtonView = tabsButtonView;

            final JTabbedPane tabbedPane = new JTabbedPane();
            tabbedPane.addTab(REQUEST_CAPTION, null, requestPanel, null);
            tabbedPane.addTab(RESPONSE_CAPTION, null, responsePanel, null);
            tabbedPane.setSelectedIndex(0);
            getResponseSendButton().setVisible(true);

            currentViewPanel = tabbedPane;
        }

        private void switchToAboveView() {
            currentView = ABOVE_VIEW;
            currentButtonView = aboveButtonView;
            getResponseSendButton().setVisible(false);

            currentViewPanel = createSplitPane(JSplitPane.VERTICAL_SPLIT);
        }

        private void switchToSideBySideView() {
            currentView = SIDE_BY_SIDE_VIEW;
            currentButtonView = sideBySideButtonView;
            getResponseSendButton().setVisible(false);

            currentViewPanel = createSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        }

        private JSplitPane createSplitPane(int orientation) {
            final JTabbedPane tabbedPaneRequest = new JTabbedPane();
            tabbedPaneRequest.addTab(REQUEST_CAPTION, null, requestPanel, null);

            final JTabbedPane tabbedPaneResponse = new JTabbedPane();
            tabbedPaneResponse.addTab(RESPONSE_CAPTION, null, responsePanel, null);

            final JSplitPane splitPane =
                    new JSplitPane(orientation, tabbedPaneRequest, tabbedPaneResponse);
            splitPane.setDividerSize(3);
            splitPane.setResizeWeight(0.5d);
            splitPane.setContinuousLayout(false);
            splitPane.setDoubleBuffered(true);

            int dividerLocation;
            if (orientation == JSplitPane.HORIZONTAL_SPLIT) {
                dividerLocation = horizontalDividerLocation;
            } else {
                dividerLocation = verticalDividerLocation;
            }
            splitPane.setDividerLocation(dividerLocation);

            return splitPane;
        }

        private JButton getResponseSendButton() {
            if (responseSendButton == null) {
                responseSendButton =
                        new JButton(Constant.messages.getString("requester.button.send"));
                responseSendButton.setMnemonic(KeyEvent.VK_ENTER);
                responseSendButton.setToolTipText(getBtnSendTooltip());
                responseSendButton.addActionListener(
                        e -> {
                            responseSendButton.setEnabled(false);
                            sendAction.run();
                            responseSendButton.setEnabled(true);
                        });
            }
            return responseSendButton;
        }
    }

    @Override
    public void unload() {
        super.unload();

        HttpPanelManager.getInstance().removeResponsePanel(getResponsePanel());
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        sender.updateButtonTrackingSessionState();
    }
}

interface LayoutChangedListener {

    void layoutChanged();
}
