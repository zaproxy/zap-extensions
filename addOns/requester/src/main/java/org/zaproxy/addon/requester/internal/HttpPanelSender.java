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

import java.awt.EventQueue;
import java.awt.event.ItemEvent;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SSLException;
import javax.swing.JButton;
import javax.swing.JToggleButton;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.requester.ExtensionRequester;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.httppanel.HttpPanelResponse;
import org.zaproxy.zap.extension.httppanel.InvalidMessageDataException;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.HttpPanelViewModelUtils;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;

/** Knows how to send {@link HttpMessage} objects. */
public class HttpPanelSender {

    private static final Logger LOGGER = LogManager.getLogger(HttpPanelSender.class);

    private final HttpPanelResponse responsePanel;
    private ExtensionHistory extension;
    private ExtensionAntiCSRF extAntiCSRF;

    private HttpSender delegate;

    private JToggleButton fixContentLength;
    private JToggleButton followRedirect;
    private JToggleButton useTrackingSessionState;
    private JToggleButton useCookies;
    private JToggleButton useCsrf;
    private JToggleButton hostHeader;
    private JButton lowerCaseHeaderNames;

    private CustomHttpPanelRequest customHttpPanelRequest;

    public HttpPanelSender(CustomHttpPanelRequest requestPanel, HttpPanelResponse responsePanel) {
        this.responsePanel = responsePanel;
        this.customHttpPanelRequest = requestPanel;

        extAntiCSRF =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAntiCSRF.class);

        delegate = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestPanel.addOptions(
                getButtonUseTrackingSessionState(), HttpPanel.OptionsLocation.AFTER_COMPONENTS);
        requestPanel.addOptions(getButtonUseCookies(), HttpPanel.OptionsLocation.AFTER_COMPONENTS);
        requestPanel.addOptions(
                getButtonFollowRedirects(), HttpPanel.OptionsLocation.AFTER_COMPONENTS);
        requestPanel.addOptions(
                getButtonFixContentLength(), HttpPanel.OptionsLocation.AFTER_COMPONENTS);
        requestPanel.addOptions(getButtonHostHeader(), HttpPanel.OptionsLocation.AFTER_COMPONENTS);
        requestPanel.addOptions(
                getButtonLowerCaseHeaderNames(), HttpPanel.OptionsLocation.AFTER_COMPONENTS);
        if (extAntiCSRF != null) {
            requestPanel.addOptions(getButtonUseCsrf(), HttpPanel.OptionsLocation.AFTER_COMPONENTS);
        }

        updateButtonTrackingSessionState();
    }

    void sendMessage(Message aMessage) throws IOException {
        final HttpMessage httpMessage = (HttpMessage) aMessage;
        // Reset the user before sending (e.g. Forced User mode sets the user, if needed).
        httpMessage.setRequestingUser(null);

        Map<String, Object> properties = new HashMap<>();
        properties.put("connection.manual.persistent", Boolean.TRUE);
        if (!getButtonHostHeader().isSelected()) {
            properties.put("host.normalization", Boolean.FALSE);
        }
        httpMessage.setUserObject(properties);

        if (getButtonFixContentLength().isSelected()) {
            HttpPanelViewModelUtils.updateRequestContentLength(httpMessage);
        }
        try {
            final ModeRedirectionValidator redirectionValidator = new ModeRedirectionValidator();
            boolean followRedirects = getButtonFollowRedirects().isSelected();

            if (extAntiCSRF != null && getButtonUseCsrf().isSelected()) {
                extAntiCSRF.regenerateAntiCsrfToken(httpMessage, delegate::sendAndReceive);
            }

            if (followRedirects) {
                delegate.sendAndReceive(
                        httpMessage,
                        HttpRequestConfig.builder()
                                .setRedirectionValidator(redirectionValidator)
                                .build());
            } else {
                delegate.sendAndReceive(httpMessage, false);
            }

            EventQueue.invokeAndWait(
                    () -> {
                        if (!httpMessage.getResponseHeader().isEmpty()) {
                            // Indicate UI new response arrived
                            responsePanel.updateContent();

                            if (!followRedirects) {
                                persistAndShowMessage(httpMessage);
                            } else if (!redirectionValidator.isRequestValid()) {
                                View.getSingleton()
                                        .showWarningDialog(
                                                responsePanel,
                                                Constant.messages.getString(
                                                        "requester.httpsender.outofscope.redirection.warning",
                                                        redirectionValidator
                                                                .getInvalidRedirection()));
                            }
                        }
                    });

        } catch (final HttpMalformedHeaderException mhe) {
            throw new IllegalArgumentException("Malformed header error.", mhe);

        } catch (final UnknownHostException uhe) {
            throw new IOException("Error forwarding to an Unknown host: " + uhe.getMessage(), uhe);

        } catch (final SSLException sslEx) {
            throw sslEx;
        } catch (final IOException ioe) {
            throw new IOException(
                    "IO error in sending request: " + ioe.getClass() + ": " + ioe.getMessage(),
                    ioe);

        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private void persistAndShowMessage(HttpMessage httpMessage) {
        if (!EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(() -> persistAndShowMessage(httpMessage));
            return;
        }

        try {
            Session session = Model.getSingleton().getSession();
            HistoryReference ref =
                    new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, httpMessage);
            final ExtensionHistory extHistory = getHistoryExtension();
            if (extHistory != null) {
                extHistory.addHistory(ref);
            }
            SessionStructure.addPath(Model.getSingleton(), ref, httpMessage);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.warn("Failed to persist message sent:", e);
        }
    }

    protected ExtensionHistory getHistoryExtension() {
        if (extension == null) {
            extension =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
        }
        return extension;
    }

    private JToggleButton getButtonFollowRedirects() {
        if (followRedirect == null) {
            followRedirect =
                    new JToggleButton(ExtensionRequester.createIcon("follow-redirect.png"));
            followRedirect.setToolTipText(
                    Constant.messages.getString("requester.httpsender.checkbox.followredirect"));
            followRedirect.setSelected(true);
        }
        return followRedirect;
    }

    private JToggleButton getButtonUseTrackingSessionState() {
        if (useTrackingSessionState == null) {
            useTrackingSessionState =
                    new JToggleButton(ExtensionRequester.createIcon("fugue/globe-green.png"));
            useTrackingSessionState.setToolTipText(
                    Constant.messages.getString("requester.httpsender.checkbox.usesession"));
            useTrackingSessionState.addItemListener(
                    e -> delegate.setUseGlobalState(e.getStateChange() == ItemEvent.SELECTED));
        }
        return useTrackingSessionState;
    }

    private JToggleButton getButtonUseCookies() {
        if (useCookies == null) {
            useCookies = new JToggleButton(ExtensionRequester.createIcon("fugue/cookie.png"), true);
            useCookies.setToolTipText(
                    Constant.messages.getString("requester.httpsender.checkbox.usecookies"));
            useCookies.addItemListener(
                    e -> delegate.setUseCookies(e.getStateChange() == ItemEvent.SELECTED));
        }
        return useCookies;
    }

    private JToggleButton getButtonUseCsrf() {
        if (useCsrf == null) {
            useCsrf = new JToggleButton(ExtensionRequester.createIcon("csrf-button.png"));
            useCsrf.setToolTipText(
                    Constant.messages.getString("requester.httpsender.checkbox.usecsrf"));
        }
        return useCsrf;
    }

    private JToggleButton getButtonFixContentLength() {
        if (fixContentLength == null) {
            fixContentLength =
                    new JToggleButton(
                            ExtensionRequester.createIcon("fugue/application-resize.png"), true);
            fixContentLength.setToolTipText(
                    Constant.messages.getString("requester.httpsender.checkbox.fixlength"));
        }
        return fixContentLength;
    }

    private JToggleButton getButtonHostHeader() {
        if (hostHeader == null) {
            hostHeader = new JToggleButton(ExtensionRequester.createIcon("fugue/server.png"), true);
            hostHeader.setToolTipText(
                    Constant.messages.getString("requester.httpsender.checkbox.hostheader"));
        }
        return hostHeader;
    }

    private JButton getButtonLowerCaseHeaderNames() {
        if (lowerCaseHeaderNames == null) {
            lowerCaseHeaderNames =
                    new JButton(ExtensionRequester.createIcon("lowercase-header-button.png"));
            lowerCaseHeaderNames.setToolTipText(
                    Constant.messages.getString(
                            "requester.httpsender.button.lowerCaseHeaderNames"));
            lowerCaseHeaderNames.addActionListener(
                    e -> {
                        try {
                            customHttpPanelRequest.saveData();
                        } catch (InvalidMessageDataException er) {
                            StringBuilder warnMessage = new StringBuilder(150);
                            warnMessage.append(
                                    Constant.messages.getString(
                                            "requester.httppanel.lowercaseHeaderNames.warn"));

                            String exceptionMessage = er.getLocalizedMessage();
                            if (exceptionMessage != null && !exceptionMessage.isEmpty()) {
                                warnMessage.append('\n').append(exceptionMessage);
                            }
                            View.getSingleton().showWarningDialog(warnMessage.toString());
                            return;
                        }
                        HttpMessage msg = (HttpMessage) customHttpPanelRequest.getMessage();
                        lowerCaseHeaderNames(msg);
                        customHttpPanelRequest.updateContent();
                    });
        }
        return lowerCaseHeaderNames;
    }

    static void lowerCaseHeaderNames(HttpMessage msg) {
        HttpRequestHeader httpRequestHeader = msg.getRequestHeader();
        List<HttpHeaderField> fields = httpRequestHeader.getHeaders();
        for (HttpHeaderField field : fields) {
            httpRequestHeader.setHeader(field.getName(), null);
        }
        for (HttpHeaderField field : fields) {
            httpRequestHeader.addHeader(field.getName().toLowerCase(Locale.ROOT), field.getValue());
        }
    }

    /**
     * A {@link HttpRedirectionValidator} that enforces the {@link
     * org.parosproxy.paros.control.Control.Mode Mode} when validating the {@code URI} of
     * redirections.
     *
     * @see #isRequestValid()
     */
    private class ModeRedirectionValidator implements HttpRedirectionValidator {

        private boolean isRequestValid;
        private URI invalidRedirection;

        public ModeRedirectionValidator() {
            isRequestValid = true;
        }

        @Override
        public void notifyMessageReceived(HttpMessage message) {
            persistAndShowMessage(message);
        }

        @Override
        public boolean isValid(URI redirection) {
            if (!isValidForCurrentMode(redirection)) {
                isRequestValid = false;
                invalidRedirection = redirection;
                return false;
            }
            return true;
        }

        private boolean isValidForCurrentMode(URI uri) {
            switch (Control.getSingleton().getMode()) {
                case safe:
                    return false;
                case protect:
                    return Model.getSingleton().getSession().isInScope(uri.toString());
                default:
                    return true;
            }
        }

        /**
         * Tells whether or not the request is valid, that is, all redirections were valid for the
         * current {@code Mode}.
         *
         * @return {@code true} is the request is valid, {@code false} otherwise.
         * @see #getInvalidRedirection()
         */
        public boolean isRequestValid() {
            return isRequestValid;
        }

        /**
         * Gets the invalid redirection, if any.
         *
         * @return the invalid redirection, {@code null} if there was none.
         * @see #isRequestValid()
         */
        public URI getInvalidRedirection() {
            return invalidRedirection;
        }
    }

    void updateButtonTrackingSessionState() {
        setButtonTrackingSessionStateEnabled(delegate.isGlobalStateEnabled());
    }

    void setButtonTrackingSessionStateEnabled(boolean enabled) {
        getButtonUseTrackingSessionState().setEnabled(enabled);
        getButtonUseTrackingSessionState().setSelected(enabled);
        delegate.setUseGlobalState(enabled);
    }
}
