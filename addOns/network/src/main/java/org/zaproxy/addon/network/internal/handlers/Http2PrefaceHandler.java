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

import static io.netty.buffer.Unpooled.unreleasableBuffer;
import static io.netty.handler.codec.http2.Http2CodecUtil.connectionPrefaceBuf;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import java.util.List;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.TlsUtils;

/**
 * Handles an HTTP/2 preface, by calling the pipeline configurator.
 *
 * <p>The handler removes itself after checking the data.
 *
 * @see ChannelAttributes#PIPELINE_CONFIGURATOR
 */
public class Http2PrefaceHandler extends ByteToMessageDecoder {

    private static final ByteBuf CONNECTION_PREFACE =
            unreleasableBuffer(connectionPrefaceBuf()).asReadOnly();

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
            throws Exception {
        int prefaceLength = CONNECTION_PREFACE.readableBytes();
        int bytesRead = Math.min(in.readableBytes(), prefaceLength);

        if (!ByteBufUtil.equals(
                CONNECTION_PREFACE,
                CONNECTION_PREFACE.readerIndex(),
                in,
                in.readerIndex(),
                bytesRead)) {
            ctx.pipeline().remove(this);
            return;
        }

        if (bytesRead == prefaceLength) {
            PipelineConfigurator configurator =
                    ctx.channel().attr(ChannelAttributes.PIPELINE_CONFIGURATOR).get();
            if (configurator != null) {
                configurator.configure(ctx, TlsUtils.APPLICATION_PROTOCOL_HTTP_2);
            }
            ctx.pipeline().remove(this);
        }
    }
}
