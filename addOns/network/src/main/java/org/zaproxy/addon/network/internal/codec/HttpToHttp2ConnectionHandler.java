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
package org.zaproxy.addon.network.internal.codec;

import static io.netty.handler.codec.http2.Http2CodecUtil.DEFAULT_HEADER_LIST_SIZE;
import static io.netty.handler.codec.http2.Http2PromisedRequestVerifier.ALWAYS_VERIFY;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.channel.DefaultChannelPromise;
import io.netty.handler.codec.http2.DefaultHttp2ConnectionDecoder;
import io.netty.handler.codec.http2.DefaultHttp2ConnectionEncoder;
import io.netty.handler.codec.http2.DefaultHttp2FrameReader;
import io.netty.handler.codec.http2.DefaultHttp2FrameWriter;
import io.netty.handler.codec.http2.DefaultHttp2HeadersDecoder;
import io.netty.handler.codec.http2.Http2CodecUtil;
import io.netty.handler.codec.http2.Http2Connection;
import io.netty.handler.codec.http2.Http2ConnectionDecoder;
import io.netty.handler.codec.http2.Http2ConnectionEncoder;
import io.netty.handler.codec.http2.Http2ConnectionHandler;
import io.netty.handler.codec.http2.Http2FrameListener;
import io.netty.handler.codec.http2.Http2FrameLogger;
import io.netty.handler.codec.http2.Http2FrameReader;
import io.netty.handler.codec.http2.Http2FrameWriter;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2HeadersEncoder;
import io.netty.handler.codec.http2.Http2HeadersEncoder.SensitivityDetector;
import io.netty.handler.codec.http2.Http2InboundFrameLogger;
import io.netty.handler.codec.http2.Http2OutboundFrameLogger;
import io.netty.handler.codec.http2.Http2Settings;
import io.netty.util.concurrent.EventExecutor;
import java.util.Collections;
import java.util.Map;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.codec.netty.Http2ControlFrameLimitEncoder;
import org.zaproxy.addon.network.internal.codec.netty.Http2EmptyDataFrameConnectionDecoder;

/**
 * An {@link Http2ConnectionHandler} that writes {@link HttpMessage}, the request or response.
 *
 * <p>Based on the Netty class {@code HttpToHttp2ConnectionHandler}.
 */
public class HttpToHttp2ConnectionHandler extends Http2ConnectionHandler {

    private final boolean encodeRequest;
    private int currentStreamId;
    private String defaultScheme;

    public static HttpToHttp2ConnectionHandler create(
            Http2FrameListener frameListener,
            Http2FrameLogger frameLogger,
            Http2Connection connection,
            String httpScheme) {
        Http2Settings initialSettings = Http2Settings.defaultSettings();
        Long maxHeaderListSize = initialSettings.maxHeaderListSize();
        Http2FrameReader reader =
                new DefaultHttp2FrameReader(
                        new DefaultHttp2HeadersDecoder(
                                false,
                                maxHeaderListSize == null
                                        ? DEFAULT_HEADER_LIST_SIZE
                                        : maxHeaderListSize,
                                -1));

        SensitivityDetector headerSensitivityDetector = Http2HeadersEncoder.NEVER_SENSITIVE;
        Http2FrameWriter writer = new DefaultHttp2FrameWriter(headerSensitivityDetector);

        if (frameLogger != null) {
            reader = new Http2InboundFrameLogger(reader, frameLogger);
            writer = new Http2OutboundFrameLogger(writer, frameLogger);
        }

        Http2ConnectionEncoder encoder =
                new Http2ControlFrameLimitEncoder(
                        new DefaultHttp2ConnectionEncoder(connection, writer),
                        Http2CodecUtil.DEFAULT_MAX_QUEUED_CONTROL_FRAMES);

        Http2ConnectionDecoder decoder =
                new DefaultHttp2ConnectionDecoder(
                        connection, encoder, reader, ALWAYS_VERIFY, true, true);

        decoder = new Http2EmptyDataFrameConnectionDecoder(decoder, 2);
        HttpToHttp2ConnectionHandler handler;
        try {
            handler =
                    new HttpToHttp2ConnectionHandler(
                            connection.isServer(),
                            decoder,
                            encoder,
                            initialSettings,
                            false,
                            true,
                            httpScheme);
        } catch (Throwable t) {
            encoder.close();
            decoder.close();
            throw new IllegalStateException("failed to build an Http2ConnectionHandler", t);
        }

        handler.gracefulShutdownTimeoutMillis(
                Http2CodecUtil.DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_MILLIS);
        if (handler.decoder().frameListener() == null) {
            handler.decoder().frameListener(frameListener);
        }
        return handler;
    }

    private HttpToHttp2ConnectionHandler(
            boolean server,
            Http2ConnectionDecoder decoder,
            Http2ConnectionEncoder encoder,
            Http2Settings initialSettings,
            boolean decoupleCloseAndGoAway,
            boolean flushPreface,
            String httpScheme) {
        super(decoder, encoder, initialSettings, decoupleCloseAndGoAway, flushPreface);
        this.encodeRequest = !server;
        this.defaultScheme = httpScheme;
    }

    public String getDefaultScheme() {
        return defaultScheme;
    }

    private int getStreamId(HttpMessage msg) throws Exception {
        Integer streamId = getProperty(getProperties(msg), "zap.h2.stream.id", null);
        if (streamId == null) {
            return connection().local().incrementAndGetNextStreamId();
        }
        return streamId;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> getProperties(HttpMessage message) {
        Object userObject = message.getUserObject();
        if (!(userObject instanceof Map)) {
            return Collections.emptyMap();
        }
        return (Map<String, Object>) userObject;
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object obj, ChannelPromise promise) {
        if (!(obj instanceof HttpMessage)) {
            ctx.write(obj, promise);
            return;
        }

        HttpMessage msg = (HttpMessage) obj;
        HttpHeader header = encodeRequest ? msg.getRequestHeader() : msg.getResponseHeader();
        HttpBody body = encodeRequest ? msg.getRequestBody() : msg.getResponseBody();
        SimpleChannelPromiseAggregator promiseAggregator =
                new SimpleChannelPromiseAggregator(promise, ctx.channel(), ctx.executor());
        try {
            Http2ConnectionEncoder encoder = encoder();
            boolean endStream = false;

            currentStreamId = getStreamId(msg);

            Http2Headers http2Headers =
                    Http2MessageHelper.createHttp2Headers(defaultScheme, header);
            endStream = body.length() == 0;

            Map<String, Object> properties = getProperties(msg);
            int dependencyId = getProperty(properties, "zap.h2.stream.dependency.id", 0);
            short weight =
                    getProperty(
                            properties,
                            "zap.h2.stream.weight",
                            Http2CodecUtil.DEFAULT_PRIORITY_WEIGHT);

            encoder.writeHeaders(
                    ctx,
                    currentStreamId,
                    http2Headers,
                    dependencyId,
                    weight,
                    false,
                    0,
                    endStream,
                    promiseAggregator.newPromise());

            if (!endStream) {
                ByteBuf content = Unpooled.wrappedBuffer(body.getBytes());
                Http2Headers trailers =
                        Http2MessageHelper.createTrailerHttp2Headers(msg, encodeRequest);
                encoder.writeData(
                        ctx,
                        currentStreamId,
                        content,
                        0,
                        trailers.isEmpty(),
                        promiseAggregator.newPromise());

                if (!trailers.isEmpty()) {
                    encoder.writeHeaders(
                            ctx,
                            currentStreamId,
                            trailers,
                            dependencyId,
                            weight,
                            false,
                            0,
                            true,
                            promiseAggregator.newPromise());
                }
            }
        } catch (Throwable t) {
            onError(ctx, true, t);
            promiseAggregator.setFailure(t);
        } finally {
            promiseAggregator.doneAllocatingPromises();
        }
    }

    private static <T> T getProperty(Map<String, Object> properties, String name, T defaultValue) {
        @SuppressWarnings("unchecked")
        T value = (T) properties.get(name);
        if (value == null) {
            return defaultValue;
        }
        return value;
    }

    private static class SimpleChannelPromiseAggregator extends DefaultChannelPromise {
        private final ChannelPromise promise;
        private int expectedCount;
        private int doneCount;
        private Throwable aggregateFailure;
        private boolean doneAllocating;

        SimpleChannelPromiseAggregator(ChannelPromise promise, Channel c, EventExecutor e) {
            super(c, e);
            assert promise != null && !promise.isDone();
            this.promise = promise;
        }

        public ChannelPromise newPromise() {
            assert !doneAllocating : "Done allocating. No more promises can be allocated.";
            ++expectedCount;
            return this;
        }

        public ChannelPromise doneAllocatingPromises() {
            if (!doneAllocating) {
                doneAllocating = true;
                if (doneCount == expectedCount || expectedCount == 0) {
                    return setPromise();
                }
            }
            return this;
        }

        @Override
        public boolean tryFailure(Throwable cause) {
            if (allowFailure()) {
                ++doneCount;
                setAggregateFailure(cause);
                if (allPromisesDone()) {
                    return tryPromise();
                }
                return true;
            }
            return false;
        }

        @Override
        public ChannelPromise setFailure(Throwable cause) {
            if (allowFailure()) {
                ++doneCount;
                setAggregateFailure(cause);
                if (allPromisesDone()) {
                    return setPromise();
                }
            }
            return this;
        }

        @Override
        public ChannelPromise setSuccess(Void result) {
            if (awaitingPromises()) {
                ++doneCount;
                if (allPromisesDone()) {
                    setPromise();
                }
            }
            return this;
        }

        @Override
        public boolean trySuccess(Void result) {
            if (awaitingPromises()) {
                ++doneCount;
                if (allPromisesDone()) {
                    return tryPromise();
                }
                return true;
            }
            return false;
        }

        private boolean allowFailure() {
            return awaitingPromises() || expectedCount == 0;
        }

        private boolean awaitingPromises() {
            return doneCount < expectedCount;
        }

        private boolean allPromisesDone() {
            return doneCount == expectedCount && doneAllocating;
        }

        private ChannelPromise setPromise() {
            if (aggregateFailure == null) {
                promise.setSuccess();
                return super.setSuccess(null);
            }
            promise.setFailure(aggregateFailure);
            return super.setFailure(aggregateFailure);
        }

        private boolean tryPromise() {
            if (aggregateFailure == null) {
                promise.trySuccess();
                return super.trySuccess(null);
            }
            promise.tryFailure(aggregateFailure);
            return super.tryFailure(aggregateFailure);
        }

        private void setAggregateFailure(Throwable cause) {
            if (aggregateFailure == null) {
                aggregateFailure = cause;
            }
        }
    }
}
