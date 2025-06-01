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
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.nio.entity.AbstractBinAsyncEntityConsumer;
import org.apache.hc.core5.util.ByteArrayBuffer;

class SimpleAsyncEntityConsumer extends AbstractBinAsyncEntityConsumer<byte[]> {

    private final ByteArrayBuffer buffer;

    public SimpleAsyncEntityConsumer() {
        super();
        this.buffer = new ByteArrayBuffer(1024);
    }

    @Override
    protected void streamStart(final ContentType contentType) throws HttpException, IOException {}

    @Override
    protected int capacityIncrement() {
        return Integer.MAX_VALUE;
    }

    @Override
    protected void data(final ByteBuffer src, final boolean endOfStream) throws IOException {
        if (src == null) {
            return;
        }
        if (src.hasArray()) {
            buffer.append(src.array(), src.arrayOffset() + src.position(), src.remaining());
        } else {
            while (src.hasRemaining()) {
                buffer.append(src.get());
            }
        }
    }

    @Override
    protected byte[] generateContent() throws IOException {
        return buffer.toByteArray();
    }

    @Override
    public void releaseResources() {
        buffer.clear();
    }
}
