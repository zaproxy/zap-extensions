/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.ZapGetMethod;
import org.zaproxy.zap.extension.websocket.WebSocketException;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.WebSocketSenderListener;
import org.zaproxy.zap.extension.websocket.utility.WebSocketUtils;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;

/** Sends a HandShake upgrade protocol request in order to establish a WebSocket connection. */
public class ServerConnectionEstablisher {

    private static final Logger LOGGER = LogManager.getLogger(ServerConnectionEstablisher.class);

    /** Used to send HttpMessage */
    private HttpSender delegate;

    /** Used to shorten the time, a listener is started on a WebSocket channel. */
    private ExecutorService listenerThreadPool;

    /**
     * Sends an Http Handshake request and waiting for the response. When the response received
     * create a WebSocket Channel and returns a WebSocketProxy instance. The WebSocketProxy instance
     * acts as a WebSocket Client.
     *
     * @return Either a new WebSocketProxy which is acts as a client or null if something went wrong
     * @throws Exception Extensive description for the reason it is not able to establish the
     *     connection
     */
    public WebSocketProxy send(HandshakeConfig handshakeConfig)
            throws IOException, RequestOutOfScopeException {
        WebSocketProxy webSocketProxy;
        try {
            webSocketProxy = handleSendMessage(handshakeConfig);
        } catch (SSLException sslEx) {
            String sslExString = sslExceptionBuilder(sslEx, handshakeConfig.getHttpMessage());
            LOGGER.warn(sslExString);
            LOGGER.debug(sslEx, sslEx);
            throw sslEx;
        }
        cleanup();
        return webSocketProxy;
    }

    /**
     * Sends and receives the handshake and sets up a new WebSocket channel with method {@link
     * ServerConnectionEstablisher#setUpChannel}
     *
     * @param handshakeConfig Wrap the Http Handshake and the other available options
     * @return Either a new WebSocketProxy which is acts as a client or null if something went wrong
     */
    private WebSocketProxy handleSendMessage(HandshakeConfig handshakeConfig)
            throws RequestOutOfScopeException, IOException {

        // Reset the user before sending (e.g. Forced User mode sets the user, if needed).
        handshakeConfig.getHttpMessage().setRequestingUser(null);
        WebSocketProxy webSocketProxy;

        try {
            final ModeRedirectionValidator redirectionValidator = new ModeRedirectionValidator();
            if (handshakeConfig.isFollowRedirects()) {
                getDelegate(handshakeConfig)
                        .sendAndReceive(
                                handshakeConfig.getHttpMessage(),
                                HttpRequestConfig.builder()
                                        .setRedirectionValidator(redirectionValidator)
                                        .build());
            } else {
                getDelegate(handshakeConfig)
                        .sendAndReceive(handshakeConfig.getHttpMessage(), false);
            }
            if (!handshakeConfig.getHttpMessage().getResponseHeader().isEmpty()) {
                if (!redirectionValidator.isRequestValid()) {
                    throw new RequestOutOfScopeException(
                            Constant.messages.getString("manReq.outofscope.redirection.warning"),
                            redirectionValidator.getInvalidRedirection());
                }
            }
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
        }

        ZapGetMethod method = (ZapGetMethod) handshakeConfig.getHttpMessage().getUserObject();
        webSocketProxy = setUpChannel(handshakeConfig, method);

        return webSocketProxy;
    }

    private WebSocketProxy setUpChannel(HandshakeConfig handshakeConfig, ZapGetMethod method)
            throws IOException {

        WebSocketProxy webSocketProxy;

        if (handshakeConfig.getHttpMessage().isWebSocketUpgrade()) {
            LOGGER.debug(
                    "Got WebSockets upgrade request. Handle socket connection over to WebSockets extension.");
            if (method != null) {
                Socket outSocket = method.getUpgradedConnection();
                InputStream outReader = method.getUpgradedInputStream();

                webSocketProxy = createChannel(handshakeConfig, outSocket, outReader);
            } else {
                throw new IOException("Unable to retrieve upgraded outgoing channel");
            }
        } else {
            throw new IOException(
                    "Http message not be able to upgrade protocol. Status code of Http Response: "
                            + handshakeConfig.getHttpMessage().getResponseHeader().getStatusCode());
        }
        return webSocketProxy;
    }

    /**
     * Create a WebSocket Client with {@link WebSocketProxy#create(String, Socket, Socket, String,
     * int, String, Map)}
     *
     * @param handshakeConfig Handshake Configuration
     * @param remoteSocket Current connection channel from ZAP to the server.
     * @param remoteReader Current {@link InputStream} of remote connection.
     */
    private WebSocketProxy createChannel(
            HandshakeConfig handshakeConfig, Socket remoteSocket, InputStream remoteReader)
            throws WebSocketException {
        WebSocketProxy webSocketProxy = null;
        HttpMessage handshakeMessage = handshakeConfig.getHttpMessage();
        try {

            HttpRequestHeader requestHeader = handshakeMessage.getRequestHeader();
            String targetHost = requestHeader.getHostName();
            int targetPort = requestHeader.getHostPort();

            LOGGER.debug("Got WebSockets channel to {}:{}", targetHost, targetPort);

            // parse HTTP handshake
            Map<String, String> wsExtensions =
                    WebSocketUtils.parseWebSocketExtensions(handshakeMessage);
            String wsProtocol = WebSocketUtils.parseWebSocketSubProtocol(handshakeMessage);
            String wsVersion = WebSocketUtils.parseWebSocketVersion(handshakeMessage);

            webSocketProxy =
                    WebSocketProxy.create(
                            wsVersion,
                            null,
                            remoteSocket,
                            handshakeMessage.getHistoryRef(),
                            targetHost,
                            targetPort,
                            wsProtocol,
                            wsExtensions);

            addChannelObserversIfAny(webSocketProxy, handshakeConfig);
            addChannelSenderListenerIfAny(webSocketProxy, handshakeConfig);

            webSocketProxy.startListeners(getListenerThreadPool(), remoteReader);

        } catch (WebSocketException e) {
            try {
                remoteReader.close();
                if (remoteSocket != null && !remoteSocket.isClosed()) {
                    remoteSocket.close();
                }
            } catch (IOException e1) {
                LOGGER.warn(e.getMessage(), e1);
            }
            throw e;
        }
        return webSocketProxy;
    }

    private void cleanup() {
        if (delegate != null) {
            delegate.shutdown();
            delegate = null;
        }
    }

    // TODO State depends on the global state. That should be fixed if we want to refer also at the
    // specifically state
    private HttpSender getDelegate(HandshakeConfig handshakeConfig) {
        if (delegate == null) {
            delegate =
                    new HttpSender(
                            Model.getSingleton().getOptionsParam().getConnectionParam(),
                            handshakeConfig.isUseSessionState(),
                            HttpSender.MANUAL_REQUEST_INITIATOR);
        }
        return delegate;
    }

    private ExecutorService getListenerThreadPool() {
        if (listenerThreadPool == null) {
            listenerThreadPool = Executors.newCachedThreadPool();
        }
        return listenerThreadPool;
    }

    /**
     * Set other observers and handshake reference, before starting listeners
     *
     * @param webSocketProxy
     * @param handshakeConfig
     */
    private void addChannelObserversIfAny(
            WebSocketProxy webSocketProxy, HandshakeConfig handshakeConfig) {
        List<WebSocketObserver> observerList = handshakeConfig.getWebsocketObservers();
        if (observerList != null) {
            for (WebSocketObserver observer : handshakeConfig.getWebsocketObservers()) {
                webSocketProxy.addObserver(observer);
            }
        }
    }

    /**
     * Set other sender listeners and handshake reference, before starting listeners
     *
     * @param webSocketProxy
     * @param handshakeConfig
     */
    private void addChannelSenderListenerIfAny(
            WebSocketProxy webSocketProxy, HandshakeConfig handshakeConfig) {
        List<WebSocketSenderListener> webSocketSenderListenerList =
                handshakeConfig.getWebSocketSenderListeners();
        if (webSocketSenderListenerList != null) {
            for (WebSocketSenderListener senderListener : webSocketSenderListenerList) {
                webSocketProxy.addSenderListener(senderListener);
            }
        }
    }

    /**
     * Build a descriptive exception message about SSLException
     *
     * @param sslEx the ssl exception
     * @param httpMessage message cause the exception
     * @return descriptive message
     */
    private String sslExceptionBuilder(SSLException sslEx, HttpMessage httpMessage) {
        StringBuilder strBuilder = new StringBuilder();
        strBuilder.append(Constant.messages.getString("network.ssl.error.connect"));
        strBuilder.append(httpMessage.getRequestHeader().getURI().toString()).append('\n');
        strBuilder
                .append(Constant.messages.getString("network.ssl.error.exception"))
                .append(sslEx.getMessage())
                .append('\n');
        strBuilder
                .append(Constant.messages.getString("network.ssl.error.exception.rootcause"))
                .append(ExceptionUtils.getRootCauseMessage(sslEx))
                .append('\n');
        strBuilder.append(
                Constant.messages.getString(
                        "network.ssl.error.help",
                        Constant.messages.getString("network.ssl.error.help.url")));
        return strBuilder.toString();
    }

    private class ModeRedirectionValidator implements HttpRedirectionValidator {
        private boolean isRequestValid;
        private URI invalidRedirection;

        public ModeRedirectionValidator() {
            isRequestValid = true;
        }

        @Override
        public void notifyMessageReceived(HttpMessage message) {}

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
         * current {@link WebSocketProxy.Mode}.
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
}
