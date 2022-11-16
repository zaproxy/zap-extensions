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
package org.zaproxy.addon.network.internal.client.apachev5.h2;

import java.io.IOException;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.nio.support.AbstractAsyncResponseConsumer;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;

public class HttpMessageResponseConsumer
        extends AbstractAsyncResponseConsumer<HttpMessage, byte[]> {

    private static final Logger LOGGER = LogManager.getLogger(HttpMessageResponseConsumer.class);

    private HttpMessage message;

    public HttpMessageResponseConsumer(HttpMessage message) {
        super(new SimpleAsyncEntityConsumer());

        this.message = message;
    }

    @Override
    public void informationResponse(HttpResponse response, HttpContext context)
            throws HttpException, IOException {
        // Nothing to do.
    }

    @Override
    protected HttpMessage buildResult(
            HttpResponse response, byte[] entity, ContentType contentType) {
        HttpResponseHeader header = message.getResponseHeader();
        try {
            header.setMessage("HTTP/2 " + response.getCode());
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error("Failed to set valid response header.", e);
        }
        for (Header headerField : response.getHeaders()) {
            header.addHeader(headerField.getName(), headerField.getValue());
        }
        message.setResponseBody(entity);
        return message;
    }
}
