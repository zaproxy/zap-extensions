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
package org.zaproxy.addon.network.internal.handlers;

import static io.netty.handler.codec.base64.Base64Dialect.URL_SAFE;
import static io.netty.handler.codec.http2.Http2CodecUtil.FRAME_HEADER_LENGTH;
import static io.netty.handler.codec.http2.Http2CodecUtil.writeFrameHeader;
import static io.netty.handler.codec.http2.Http2FrameTypes.SETTINGS;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.base64.Base64;
import io.netty.handler.codec.http2.DefaultHttp2FrameReader;
import io.netty.handler.codec.http2.Http2Exception;
import io.netty.handler.codec.http2.Http2Flags;
import io.netty.handler.codec.http2.Http2FrameAdapter;
import io.netty.handler.codec.http2.Http2FrameReader;
import io.netty.handler.codec.http2.Http2Settings;
import io.netty.util.CharsetUtil;
import java.nio.CharBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.codec.HttpToHttp2ConnectionHandler;

/**
 * Handles h2c upgrade.
 *
 * <p>The handler removes itself after processing the HTTP message.
 */
@Sharable
public class Http2UpgradeHandler extends SimpleChannelInboundHandler<HttpMessage> {

    private static final String HTTP2_SETTINGS = "HTTP2-Settings";

    private static final String UPGRADE = "Upgrade";

    private static final Logger LOGGER = LogManager.getLogger(Http2UpgradeHandler.class);

    private static final String RESPONSE = "HTTP/1.1 101\r\nConnection: Upgrade\r\nUpgrade: h2c";

    private static final Http2UpgradeHandler INSTANCE = new Http2UpgradeHandler();

    /**
     * Gets the instance of this handler.
     *
     * @return the instance, never {@code null}.
     */
    public static Http2UpgradeHandler getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean isSharable() {
        return true;
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, HttpMessage msg) throws Exception {
        if (msg.getUserObject() instanceof Exception) {
            throw (Exception) msg.getUserObject();
        }

        ctx.pipeline().remove(this);

        Http2Settings settings = processUpgrade(ctx, msg);
        if (settings == null) {
            ctx.fireChannelRead(msg);
            return;
        }

        getProperties(msg).put("zap.h2", Boolean.TRUE);
        ctx.channel()
                .writeAndFlush(msg)
                .addListener(
                        e -> {
                            getProperties(msg).put("zap.h2.stream.id", 1);

                            msg.getRequestHeader().setHeader(HttpHeader.CONNECTION, null);
                            msg.getRequestHeader().setHeader(HttpHeader.PROXY_CONNECTION, null);
                            msg.getRequestHeader().setHeader(UPGRADE, null);
                            msg.getRequestHeader().setHeader(HTTP2_SETTINGS, null);
                            msg.setResponseHeader(new HttpResponseHeader());

                            PipelineConfigurator configurator =
                                    ctx.channel()
                                            .attr(ChannelAttributes.PIPELINE_CONFIGURATOR)
                                            .get();
                            if (configurator != null) {
                                configurator.configure(ctx, TlsUtils.APPLICATION_PROTOCOL_HTTP_2);
                                ctx.pipeline()
                                        .get(HttpToHttp2ConnectionHandler.class)
                                        .onHttpServerUpgrade(settings);
                            }
                            ctx.fireChannelRead(msg);
                        });
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

    private Http2Settings processUpgrade(ChannelHandlerContext ctx, HttpMessage msg) {
        HttpRequestHeader request = msg.getRequestHeader();
        if (!"h2c".equals(request.getHeader(UPGRADE))) {
            return null;
        }

        String connection = request.getHeader(HttpHeader.CONNECTION);
        if (connection == null || !hasExpectedConnectionValues(connection)) {
            return null;
        }

        List<String> http2Settings = request.getHeaderValues(HTTP2_SETTINGS);
        if (http2Settings.size() != 1) {
            return null;
        }

        try {
            Http2Settings settings = decodeSettingsHeader(ctx, http2Settings.get(0));
            msg.getResponseHeader().setMessage(RESPONSE);
            return settings;
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error("Failed to set valid response header.", e);
        } catch (Http2Exception e) {
            LOGGER.warn("An error occurred while decoding settings header frame:", e);
        }
        return null;
    }

    private static boolean hasExpectedConnectionValues(String connection) {
        List<String> values =
                Stream.of(connection.split(","))
                        .filter(e -> !e.isBlank())
                        .map(String::trim)
                        .collect(Collectors.toList());
        return values.size() == 2 && values.contains(UPGRADE) && values.contains(HTTP2_SETTINGS);
    }

    private static Http2Settings decodeSettingsHeader(
            ChannelHandlerContext ctx, CharSequence settingsHeader) throws Http2Exception {
        ByteBuf header =
                ByteBufUtil.encodeString(
                        ctx.alloc(), CharBuffer.wrap(settingsHeader), CharsetUtil.UTF_8);
        try {
            ByteBuf payload = Base64.decode(header, URL_SAFE);
            ByteBuf frame = createSettingsFrame(ctx, payload);
            return decodeSettings(ctx, frame);
        } finally {
            header.release();
        }
    }

    private static Http2Settings decodeSettings(ChannelHandlerContext ctx, ByteBuf frame)
            throws Http2Exception {
        try (Http2FrameReader frameReader = new DefaultHttp2FrameReader(false)) {
            Http2Settings decodedSettings = new Http2Settings();
            frameReader.readFrame(
                    ctx,
                    frame,
                    new Http2FrameAdapter() {
                        @Override
                        public void onSettingsRead(
                                ChannelHandlerContext ctx, Http2Settings settings) {
                            decodedSettings.copyFrom(settings);
                        }
                    });
            return decodedSettings;
        } finally {
            frame.release();
        }
    }

    private static ByteBuf createSettingsFrame(ChannelHandlerContext ctx, ByteBuf payload) {
        ByteBuf frame = ctx.alloc().buffer(FRAME_HEADER_LENGTH + payload.readableBytes());
        writeFrameHeader(frame, payload.readableBytes(), SETTINGS, new Http2Flags(), 0);
        frame.writeBytes(payload);
        payload.release();
        return frame;
    }
}
