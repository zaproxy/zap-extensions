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
import java.nio.ByteBuffer;
import java.nio.charset.UnsupportedCharsetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.apache.hc.core5.concurrent.CallbackContribution;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.function.Supplier;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.nio.AsyncEntityConsumer;
import org.apache.hc.core5.http.nio.AsyncResponseConsumer;
import org.apache.hc.core5.http.nio.CapacityChannel;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;

public class HttpMessageResponseConsumer implements AsyncResponseConsumer<HttpMessage> {

    private static final Logger LOGGER = LogManager.getLogger(HttpMessageResponseConsumer.class);

    private static final byte[] EMPTY_BODY = {};

    private final Supplier<AsyncEntityConsumer<byte[]>> dataConsumerSupplier;
    private final AtomicReference<AsyncEntityConsumer<byte[]>> dataConsumerRef;
    private final HttpMessage message;

    public HttpMessageResponseConsumer(HttpMessage message) {
        this.message = message;
        this.dataConsumerSupplier = SimpleAsyncEntityConsumer::new;
        this.dataConsumerRef = new AtomicReference<>();
    }

    @Override
    public final void consumeResponse(
            final HttpResponse response,
            final EntityDetails entityDetails,
            final HttpContext httpContext,
            final FutureCallback<HttpMessage> resultCallback)
            throws HttpException, IOException {
        if (entityDetails != null) {
            final AsyncEntityConsumer<byte[]> dataConsumer = dataConsumerSupplier.get();
            if (dataConsumer == null) {
                throw new HttpException("Supplied data consumer is null");
            }
            dataConsumerRef.set(dataConsumer);
            dataConsumer.streamStart(
                    entityDetails,
                    new CallbackContribution<byte[]>(resultCallback) {

                        @Override
                        public void completed(final byte[] entity) {
                            final ContentType contentType;
                            try {
                                contentType = ContentType.parse(entityDetails.getContentType());
                                final HttpMessage result =
                                        buildResult(response, entity, contentType);
                                if (resultCallback != null) {
                                    resultCallback.completed(result);
                                }
                            } catch (final UnsupportedCharsetException ex) {
                                if (resultCallback != null) {
                                    resultCallback.failed(ex);
                                }
                            }
                        }
                    });
        } else {
            final HttpMessage result = buildResult(response, null, null);
            if (resultCallback != null) {
                resultCallback.completed(result);
            }
        }
    }

    @Override
    public final void updateCapacity(final CapacityChannel capacityChannel) throws IOException {
        final AsyncEntityConsumer<byte[]> dataConsumer = dataConsumerRef.get();
        if (dataConsumer != null) {
            dataConsumer.updateCapacity(capacityChannel);
        } else {
            capacityChannel.update(Integer.MAX_VALUE);
        }
    }

    @Override
    public final void consume(final ByteBuffer src) throws IOException {
        final AsyncEntityConsumer<byte[]> dataConsumer = dataConsumerRef.get();
        if (dataConsumer != null) {
            dataConsumer.consume(src);
        }
    }

    @Override
    public void streamEnd(final List<? extends Header> trailers) throws HttpException, IOException {
        if (trailers != null) {
            getProperties(message)
                    .put(
                            "zap.h2.trailers.resp",
                            trailers.stream()
                                    .map(e -> new HttpHeaderField(e.getName(), e.getValue()))
                                    .collect(Collectors.toCollection(ArrayList::new)));
        }

        final AsyncEntityConsumer<byte[]> dataConsumer = dataConsumerRef.get();
        if (dataConsumer != null) {
            dataConsumer.streamEnd(trailers);
        }
    }

    @Override
    public final void failed(final Exception cause) {
        releaseResources();
    }

    @Override
    public final void releaseResources() {
        final AsyncEntityConsumer<byte[]> dataConsumer = dataConsumerRef.getAndSet(null);
        if (dataConsumer != null) {
            dataConsumer.releaseResources();
        }
    }

    @Override
    public void informationResponse(HttpResponse response, HttpContext context)
            throws HttpException, IOException {
        // Nothing to do.
    }

    HttpMessage buildResult(HttpResponse response, byte[] entity, ContentType contentType) {
        HttpResponseHeader header = message.getResponseHeader();
        try {
            header.setMessage("HTTP/2 " + response.getCode());
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error("Failed to set valid response header.", e);
        }
        for (Header headerField : response.getHeaders()) {
            header.addHeader(headerField.getName(), headerField.getValue());
        }
        message.setResponseBody(entity == null ? EMPTY_BODY : entity);
        return message;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> getProperties(HttpMessage message) {
        Object userObject = message.getUserObject();
        if (!(userObject instanceof Map)) {
            userObject = new HashMap<>();
            message.setUserObject(userObject);
        }
        return (Map<String, Object>) userObject;
    }
}
