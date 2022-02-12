/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.server.http.handlers;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import javax.net.ssl.SSLException;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.network.HttpRequestConfig;

/** A {@link HttpMessageHandler} that sends and receives a HTTP message. */
public class HttpSenderHandler implements HttpMessageHandler {

    private static final Logger LOGGER = LogManager.getLogger(HttpSenderHandler.class);

    private static final String BAD_GATEWAY_REASON_PHRASE = "Bad Gateway";
    private static final String GATEWAY_TIMEOUT_REASON_PHRASE = "Gateway Timeout";

    /** A {@code HttpRequestConfig} that does not allow notification of events to listeners. */
    private static final HttpRequestConfig EXCLUDED_REQ_CONFIG =
            HttpRequestConfig.builder().setNotifyListeners(false).build();

    private ConnectionParam connectionParam;
    private HttpSender httpSender;

    /**
     * Constructs a {@code HttpSenderHandler} with the given connection configuration and HTTP
     * sender.
     *
     * @param connectionParam the connection configuration.
     * @param httpSender the HTTP sender.
     * @throws NullPointerException if the HTTP sender and given handler are {@code null}.
     */
    public HttpSenderHandler(ConnectionParam connectionParam, HttpSender httpSender) {
        this.connectionParam = Objects.requireNonNull(connectionParam);
        this.httpSender = Objects.requireNonNull(httpSender);
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!ctx.isFromClient() || !msg.getResponseHeader().isEmpty()) {
            return;
        }

        try {
            if (ctx.isExcluded()) {
                httpSender.sendAndReceive(msg, EXCLUDED_REQ_CONFIG);
                ctx.overridden();
            } else {
                httpSender.sendAndReceive(msg);
            }

        } catch (HttpException e) {
            LOGGER.error(e.getMessage(), e);
            ctx.close();

        } catch (SocketTimeoutException e) {
            String message =
                    Constant.messages.getString(
                            "network.httpsender.error.readtimeout",
                            msg.getRequestHeader().getURI(),
                            connectionParam.getTimeoutInSecs());
            LOGGER.warn(message);
            setErrorResponse(
                    ctx,
                    msg,
                    HttpStatusCode.GATEWAY_TIMEOUT,
                    GATEWAY_TIMEOUT_REASON_PHRASE,
                    message);

        } catch (IOException e) {
            setErrorResponse(ctx, msg, HttpStatusCode.BAD_GATEWAY, BAD_GATEWAY_REASON_PHRASE, e);
        }
    }

    private void setErrorResponse(
            HttpMessageHandlerContext ctx,
            HttpMessage msg,
            int statusCode,
            String reasonPhrase,
            Exception cause) {
        StringBuilder strBuilder = new StringBuilder();

        if (cause instanceof SSLException) {
            strBuilder.append(Constant.messages.getString("network.httpsender.ssl.error.connect"));
            strBuilder.append(msg.getRequestHeader().getURI().toString()).append('\n');
            strBuilder
                    .append(Constant.messages.getString("network.httpsender.ssl.error.exception"))
                    .append(cause.getMessage())
                    .append('\n');
            strBuilder
                    .append(
                            Constant.messages.getString(
                                    "network.httpsender.ssl.error.exception.rootcause"))
                    .append(ExceptionUtils.getRootCauseMessage(cause))
                    .append('\n');
            strBuilder.append(
                    Constant.messages.getString(
                            "network.httpsender.ssl.error.help",
                            Constant.messages.getString("network.httpsender.ssl.error.help.url")));

            LOGGER.warn(strBuilder.toString());
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(cause, cause);
                strBuilder.append("\n\nStack Trace:\n");
                for (String stackTraceFrame : ExceptionUtils.getRootCauseStackTrace(cause)) {
                    strBuilder.append(stackTraceFrame).append('\n');
                }
            }
        } else {
            strBuilder
                    .append("ZAP Error")
                    .append(" [")
                    .append(cause.getClass().getName())
                    .append("]: ")
                    .append(cause.getLocalizedMessage())
                    .append("\n");
            if (cause instanceof UnknownHostException
                    && connectionParam.isUseProxyChain()
                    && connectionParam.getProxyChainName().equalsIgnoreCase(cause.getMessage())) {
                strBuilder.append(Constant.messages.getString("network.httpsender.error.proxy"));
            }
            strBuilder.append("\n\nStack Trace:\n");
            for (String stackTraceFrame : ExceptionUtils.getRootCauseStackTrace(cause)) {
                strBuilder.append(stackTraceFrame).append('\n');
            }
        }

        setErrorResponse(ctx, msg, statusCode, reasonPhrase, strBuilder.toString());
    }

    private static void setErrorResponse(
            HttpMessageHandlerContext ctx,
            HttpMessage msg,
            int statusCode,
            String reasonPhrase,
            String message) {
        HttpResponseHeader responseHeader = new HttpResponseHeader();
        responseHeader.setVersion(HttpHeader.HTTP11);
        responseHeader.setStatusCode(statusCode);
        responseHeader.setReasonPhrase(reasonPhrase);
        responseHeader.setHeader(HttpHeader.CONTENT_TYPE, "text/plain; charset=UTF-8");
        responseHeader.setHeader(
                HttpHeader.CONTENT_LENGTH,
                Integer.toString(message.getBytes(StandardCharsets.UTF_8).length));
        msg.setResponseHeader(responseHeader);

        if (!HttpRequestHeader.HEAD.equals(msg.getRequestHeader().getMethod())) {
            msg.setResponseBody(message);
        }
    }
}
