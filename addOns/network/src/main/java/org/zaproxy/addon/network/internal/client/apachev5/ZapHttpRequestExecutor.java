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
package org.zaproxy.addon.network.internal.client.apachev5;

import java.io.IOException;
import java.net.Socket;
import java.util.Locale;
import org.apache.hc.client5.http.io.ManagedHttpClientConnection;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.ProtocolException;
import org.apache.hc.core5.http.impl.io.DefaultClassicHttpResponseFactory;
import org.apache.hc.core5.http.impl.io.HttpRequestExecutor;
import org.apache.hc.core5.http.io.HttpClientConnection;
import org.apache.hc.core5.http.io.HttpResponseInformationCallback;
import org.apache.hc.core5.http.message.MessageSupport;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.apache.hc.core5.io.Closer;

/**
 * A {@link HttpRequestExecutor} that does not try to read the response if switching protocols or if
 * the response is an event stream.
 */
public class ZapHttpRequestExecutor extends HttpRequestExecutor {

    public static final String CONNECTION_SOCKET = "zap.connection.socket";
    public static final String CONNECTION_INPUT_STREAM = "zap.connection.inputstream";

    public ZapHttpRequestExecutor() {
        super(DEFAULT_WAIT_FOR_CONTINUE, null, null);
    }

    @Override
    public ClassicHttpResponse execute(
            ClassicHttpRequest request,
            HttpClientConnection conn,
            HttpResponseInformationCallback informationCallback,
            HttpContext context)
            throws IOException, HttpException {
        try {
            context.setAttribute(HttpCoreContext.SSL_SESSION, conn.getSSLSession());
            context.setAttribute(HttpCoreContext.CONNECTION_ENDPOINT, conn.getEndpointDetails());

            conn.sendRequestHeader(request);
            conn.sendRequestEntity(request);
            conn.flush();
            ClassicHttpResponse response = null;
            while (response == null) {
                response = conn.receiveResponseHeader();
                int status = response.getCode();
                if (status < HttpStatus.SC_INFORMATIONAL) {
                    throw new ProtocolException("Invalid response: " + new StatusLine(response));
                }
                if (status < HttpStatus.SC_SUCCESS) {
                    if (informationCallback != null && status != HttpStatus.SC_CONTINUE) {
                        informationCallback.execute(response, conn, context);
                    }
                    if (status != HttpStatus.SC_SWITCHING_PROTOCOLS) {
                        response = null;
                    }
                }
            }
            if (response.getCode() == HttpStatus.SC_SWITCHING_PROTOCOLS
                    || isEventStream(response)) {
                if (conn instanceof ManagedHttpClientConnection) {
                    HttpClientContext clientContext = HttpClientContext.adapt(context);
                    clientContext.setUserToken("zap.connection.stream");

                    Socket socket = ((ManagedHttpClientConnection) conn).getSocket();
                    context.setAttribute(CONNECTION_SOCKET, socket);

                    ClassicHttpResponse r =
                            DefaultClassicHttpResponseFactory.INSTANCE.newHttpResponse(200);
                    Header transferEncoding = response.getLastHeader(HttpHeaders.TRANSFER_ENCODING);
                    if (transferEncoding != null) {
                        r.addHeader(transferEncoding);
                    }
                    conn.receiveResponseEntity(r);
                    context.setAttribute(CONNECTION_INPUT_STREAM, r.getEntity().getContent());
                } else {
                    response = null;
                }

            } else if (MessageSupport.canResponseHaveBody(request.getMethod(), response)) {
                conn.receiveResponseEntity(response);
            }
            return response;

        } catch (final HttpException | IOException | RuntimeException ex) {
            Closer.closeQuietly(conn);
            throw ex;
        }
    }

    private static boolean isEventStream(ClassicHttpResponse response) {
        for (Header contentType : response.getHeaders(HttpHeaders.CONTENT_TYPE)) {
            if (contentType != null
                    && contentType.getValue() != null
                    && contentType.getValue().toLowerCase(Locale.ROOT).contains("event-stream")) {
                return true;
            }
        }
        return false;
    }
}
