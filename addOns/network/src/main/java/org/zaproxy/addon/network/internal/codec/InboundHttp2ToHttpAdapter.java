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

import static io.netty.handler.codec.http.HttpResponseStatus.OK;
import static io.netty.handler.codec.http2.Http2Error.PROTOCOL_ERROR;
import static io.netty.handler.codec.http2.Http2Exception.connectionError;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http2.Http2CodecUtil;
import io.netty.handler.codec.http2.Http2Connection;
import io.netty.handler.codec.http2.Http2Error;
import io.netty.handler.codec.http2.Http2EventAdapter;
import io.netty.handler.codec.http2.Http2Exception;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2Stream;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

/**
 * An {@link Http2EventAdapter} that creates an {@link HttpMessage}, with the request or response.
 *
 * <p>Based on the Netty class {@code InboundHttp2ToHttpAdapter}.
 */
public class InboundHttp2ToHttpAdapter extends Http2EventAdapter {

    private static final Logger LOGGER = LogManager.getLogger(InboundHttp2ToHttpAdapter.class);
    private static final String CONTENT_LENGTH = HttpHeader.CONTENT_LENGTH.toLowerCase(Locale.ROOT);

    private static final String EXPECT_HEADER = "Expect";

    private final Http2Connection.PropertyKey messageKey;
    private final Http2Connection connection;

    public InboundHttp2ToHttpAdapter(Http2Connection connection) {
        this.connection = Objects.requireNonNull(connection);
        messageKey = connection.newKey();

        this.connection.addListener(this);
    }

    private void removeMessage(Http2Stream stream) {
        stream.removeProperty(messageKey);
    }

    private HttpMessage getMessage(Http2Stream stream) {
        return (HttpMessage) stream.getProperty(messageKey);
    }

    @Override
    public void onStreamRemoved(Http2Stream stream) {
        removeMessage(stream);
    }

    @Override
    public void onRstStreamRead(ChannelHandlerContext ctx, int streamId, long errorCode) {
        Http2Stream stream = connection.stream(streamId);
        HttpMessage msg = getMessage(stream);
        if (msg != null) {
            removeMessage(stream);
        }
        LOGGER.debug("Stream {} reset, code: {}", streamId, Http2Error.valueOf(errorCode));
    }

    @Override
    public void onHeadersRead(
            ChannelHandlerContext ctx,
            int streamId,
            Http2Headers headers,
            int padding,
            boolean endOfStream)
            throws Http2Exception {
        Http2Stream stream = connection.stream(streamId);
        HttpMessage msg =
                processHeadersBegin(connection.isServer(), ctx, stream, headers, endOfStream);
        if (msg != null) {
            processHeadersEnd(ctx, stream, msg, endOfStream);
        }
    }

    @Override
    public void onHeadersRead(
            ChannelHandlerContext ctx,
            int streamId,
            Http2Headers headers,
            int streamDependency,
            short weight,
            boolean exclusive,
            int padding,
            boolean endOfStream)
            throws Http2Exception {
        Http2Stream stream = connection.stream(streamId);
        HttpMessage msg =
                processHeadersBegin(connection.isServer(), ctx, stream, headers, endOfStream);
        if (msg != null) {
            @SuppressWarnings("unchecked")
            Map<String, Object> properties = (Map<String, Object>) msg.getUserObject();
            if (streamDependency != Http2CodecUtil.CONNECTION_STREAM_ID) {
                properties.put("zap.h2.stream.dependency.id", streamDependency);
            }
            properties.put("zap.h2.stream.weight", weight);

            processHeadersEnd(ctx, stream, msg, endOfStream);
        }
    }

    private HttpMessage processHeadersBegin(
            boolean server,
            ChannelHandlerContext ctx,
            Http2Stream stream,
            Http2Headers headers,
            boolean endOfStream)
            throws Http2Exception {
        HttpMessage msg = getMessage(stream);
        if (msg == null) {
            msg = newMessage(server, stream, headers);
        } else {
            Http2MessageHelper.addTrailerHeaders(stream.id(), headers, msg, server);
        }

        if (mustSendImmediately(server, msg)) {
            fireChannelRead(ctx, msg, stream);
            return endOfStream || !server ? null : msg;
        }

        return msg;
    }

    private HttpMessage newMessage(boolean server, Http2Stream stream, Http2Headers headers)
            throws Http2Exception {
        HttpMessage msg = new HttpMessage();
        int streamId = stream.id();
        Map<String, Object> properties = new HashMap<>();
        properties.put("zap.h2", Boolean.TRUE);
        properties.put("zap.h2.stream.id", streamId);
        msg.setUserObject(properties);
        if (server) {
            Http2MessageHelper.setHttpRequest(streamId, headers, msg);
        } else {
            Http2MessageHelper.setHttpResponse(streamId, headers, msg);
        }
        return msg;
    }

    private static boolean mustSendImmediately(boolean server, HttpMessage msg) {
        if (server) {
            boolean send = msg.getRequestHeader().getHeader(EXPECT_HEADER) != null;
            msg.getRequestHeader().setHeader(EXPECT_HEADER, null);
            return send;
        }
        return HttpStatusCode.isInformational(msg.getResponseHeader().getStatusCode());
    }

    private void processHeadersEnd(
            ChannelHandlerContext ctx, Http2Stream stream, HttpMessage msg, boolean endOfStream) {
        if (endOfStream) {
            fireChannelRead(ctx, msg, stream);
        } else {
            stream.setProperty(messageKey, msg);
        }
    }

    private void fireChannelRead(ChannelHandlerContext ctx, HttpMessage msg, Http2Stream stream) {
        removeMessage(stream);
        if (connection.isServer()) {
            updateRequestContentLength(msg);
        } else {
            setContentLength(msg.getResponseHeader(), msg.getResponseBody().length());
        }
        ctx.fireChannelRead(msg);
    }

    private static void setContentLength(HttpHeader header, int length) {
        header.setContentLength(length);
        // Set it again to keep it lower case.
        header.setHeader(CONTENT_LENGTH, String.valueOf(length));
    }

    private static void updateRequestContentLength(HttpMessage msg) {
        int bodyLength = msg.getRequestBody().length();
        String method = msg.getRequestHeader().getMethod();
        if (bodyLength == 0
                && (HttpRequestHeader.GET.equalsIgnoreCase(method)
                        || HttpRequestHeader.CONNECT.equalsIgnoreCase(method)
                        || HttpRequestHeader.DELETE.equalsIgnoreCase(method)
                        || HttpRequestHeader.HEAD.equalsIgnoreCase(method)
                        || HttpRequestHeader.TRACE.equalsIgnoreCase(method))) {
            msg.getRequestHeader().setHeader(CONTENT_LENGTH, null);
            return;
        }
        setContentLength(msg.getRequestHeader(), bodyLength);
    }

    @Override
    public int onDataRead(
            ChannelHandlerContext ctx, int streamId, ByteBuf data, int padding, boolean endOfStream)
            throws Http2Exception {
        Http2Stream stream = connection.stream(streamId);
        HttpMessage msg = getMessage(stream);
        if (msg == null) {
            throw connectionError(
                    PROTOCOL_ERROR, "Data Frame received for unknown stream id %d", streamId);
        }

        HttpBody body = connection.isServer() ? msg.getRequestBody() : msg.getResponseBody();
        int dataReadableBytes = data.readableBytes();
        byte[] bodyData = new byte[dataReadableBytes];
        data.readBytes(bodyData, 0, dataReadableBytes);
        body.append(bodyData, dataReadableBytes);

        if (endOfStream) {
            fireChannelRead(ctx, msg, stream);
        }

        return dataReadableBytes + padding;
    }

    @Override
    public void onPushPromiseRead(
            ChannelHandlerContext ctx,
            int streamId,
            int promisedStreamId,
            Http2Headers headers,
            int padding)
            throws Http2Exception {
        Http2Stream promisedStream = connection.stream(promisedStreamId);
        if (getMessage(promisedStream) != null) {
            throw connectionError(
                    PROTOCOL_ERROR,
                    "Push Promise Frame received for pre-existing stream id %d",
                    promisedStreamId);
        }

        if (headers.status() == null) {
            headers.status(OK.codeAsText());
        }

        HttpMessage msg = processHeadersBegin(true, ctx, promisedStream, headers, false);

        @SuppressWarnings("unchecked")
        Map<String, Object> properties = (Map<String, Object>) msg.getUserObject();
        properties.put("zap.h2.stream.weight", Http2CodecUtil.DEFAULT_PRIORITY_WEIGHT);
        properties.put("zap.h2.stream.promise", Boolean.TRUE);

        processHeadersEnd(ctx, promisedStream, msg, false);
    }
}
