/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.util.ByteProcessor;
import io.netty.util.internal.AppendableCharSequence;
import java.util.List;
import java.util.function.Function;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;

/**
 * Decodes a HTTP message, request or response into a {@link HttpMessage}.
 *
 * <p>Based on Netty's {@code HttpObjectDecoder}.
 */
public abstract class HttpMessageDecoder extends ByteToMessageDecoder {

    private static final HttpMalformedHeaderException MISSING_FULL_BODY =
            new HttpMalformedHeaderException("Connection closed before receiving full body.");

    private static final Exception MISSING_FULL_HEADER =
            new HttpMalformedHeaderException("Connection closed before receiving full header.");

    private static final int DEFAULT_INITIAL_BUFFER_SIZE = 128;

    private static final byte LF = 10;
    private static final byte CR = 13;

    static final int MAX_CHUNK_SIZE = 80;

    private final HeaderParser headerParser;
    private final LineParser lineParser;
    private final boolean decodingRequest;
    private final HeaderProvider headerProvider;
    private final Function<HttpMessage, HttpBody> bodyProvider;

    private HttpMessage message;
    private HttpHeader header;
    private HttpBody body;
    private byte[] chunkBuffer;

    private long chunkSize;

    private enum State {
        READ_HEADER,
        HANDLE_CONTENT,
        READ_VARIABLE_LENGTH_CONTENT,
        READ_FIXED_LENGTH_CONTENT,
        READ_CHUNK_SIZE,
        READ_CHUNKED_CONTENT,
        READ_CHUNK_DELIMITER,
        READ_CHUNK_FOOTER,
        BAD_MESSAGE,
        UPGRADED
    }

    private State currentState = State.READ_HEADER;

    protected HttpMessageDecoder(
            boolean decodingRequest,
            HeaderProvider headerProvider,
            Function<HttpMessage, HttpBody> bodyProvider) {
        AppendableCharSequence seq = new AppendableCharSequence(DEFAULT_INITIAL_BUFFER_SIZE);
        headerParser = new HeaderParser(seq);
        lineParser = new LineParser(seq);

        this.decodingRequest = decodingRequest;
        this.headerProvider = headerProvider;
        this.bodyProvider = bodyProvider;
        chunkBuffer = new byte[MAX_CHUNK_SIZE];
    }

    @Override
    @SuppressWarnings("fallthrough")
    protected void decode(ChannelHandlerContext ctx, ByteBuf buffer, List<Object> out)
            throws Exception {

        switch (currentState) {
            case READ_HEADER:
                AppendableCharSequence headerContent = headerParser.parse(buffer);
                if (headerContent == null) {
                    return;
                }

                headerParser.reset();
                try {
                    message = new HttpMessage();
                    header = headerProvider.get(ctx, message, headerContent.toString());
                    body = bodyProvider.apply(message);
                    body.setLength(0);

                    HttpMessage.setContentEncodings(header, body);

                    currentState = State.HANDLE_CONTENT;
                } catch (Exception e) {
                    out.add(invalidMessage(buffer, e));
                    return;
                }
            case HANDLE_CONTENT:
                if (isContentAlwaysEmpty(message)) {
                    out.add(message);
                    resetNow();
                    return;
                }

                if (isTransferEncodingChunked()) {
                    currentState = State.READ_CHUNK_SIZE;
                    return;
                }

                int contentLength = header.getContentLength();
                if (contentLength == 0) {
                    out.add(message);
                    resetNow();
                    return;
                }

                currentState =
                        contentLength > 0
                                ? State.READ_FIXED_LENGTH_CONTENT
                                : State.READ_VARIABLE_LENGTH_CONTENT;
                if (currentState == State.READ_FIXED_LENGTH_CONTENT) {
                    chunkSize = contentLength;
                }

                return;
            case READ_VARIABLE_LENGTH_CONTENT:
                {
                    int toRead = Math.min(buffer.readableBytes(), MAX_CHUNK_SIZE);
                    if (toRead > 0) {
                        appendToBody(buffer, toRead);
                    }
                    return;
                }
            case READ_FIXED_LENGTH_CONTENT:
                {
                    int toRead = Math.min(buffer.readableBytes(), MAX_CHUNK_SIZE);
                    if (toRead > chunkSize) {
                        toRead = (int) chunkSize;
                    }

                    chunkSize -= toRead;
                    appendToBody(buffer, toRead);

                    if (chunkSize == 0) {
                        out.add(message);
                        resetNow();
                    }
                    return;
                }

            case READ_CHUNK_SIZE:
                try {
                    AppendableCharSequence line = lineParser.parse(buffer);
                    if (line == null) {
                        return;
                    }
                    int chunkSize = getChunkSize(line.toString());
                    if (chunkSize < 0) {
                        throw new NumberFormatException("Invalid chunk size: " + chunkSize);
                    }

                    this.chunkSize = chunkSize;
                    if (chunkSize == 0) {
                        currentState = State.READ_CHUNK_FOOTER;
                        return;
                    }
                    currentState = State.READ_CHUNKED_CONTENT;
                } catch (Exception e) {
                    out.add(invalidMessage(buffer, e));
                    return;
                }
            case READ_CHUNKED_CONTENT:
                {
                    int toRead = Math.min((int) chunkSize, MAX_CHUNK_SIZE);
                    toRead = Math.min(toRead, buffer.readableBytes());
                    if (toRead == 0) {
                        return;
                    }

                    chunkSize -= toRead;
                    appendToBody(buffer, toRead);

                    if (chunkSize != 0) {
                        return;
                    }
                    currentState = State.READ_CHUNK_DELIMITER;
                }
            case READ_CHUNK_DELIMITER:
                {
                    final int wIdx = buffer.writerIndex();
                    int rIdx = buffer.readerIndex();
                    while (wIdx > rIdx) {
                        byte next = buffer.getByte(rIdx++);
                        if (next == LF) {
                            currentState = State.READ_CHUNK_SIZE;
                            break;
                        }
                    }
                    buffer.readerIndex(rIdx);
                    return;
                }
            case READ_CHUNK_FOOTER:
                try {
                    boolean done = readTrailingHeaders(buffer);
                    if (!done) {
                        return;
                    }

                    header.setHeader(HttpHeader.TRANSFER_ENCODING, null);
                    header.setContentLength(body.length());
                    out.add(message);
                    resetNow();
                    return;
                } catch (Exception e) {
                    out.add(invalidMessage(buffer, e));
                    return;
                }

            case BAD_MESSAGE:
                buffer.skipBytes(buffer.readableBytes());
                break;

            case UPGRADED:
                int readableBytes = buffer.readableBytes();
                if (readableBytes > 0) {
                    out.add(buffer.readBytes(readableBytes));
                }
                break;

            default:
                break;
        }
    }

    private void appendToBody(ByteBuf buffer, int length) {
        buffer.readBytes(chunkBuffer, 0, length);
        body.append(chunkBuffer, length);
    }

    private boolean isTransferEncodingChunked() {
        for (String transferEncoding : header.getHeaderValues(HttpHeader.TRANSFER_ENCODING)) {
            if (StringUtils.containsIgnoreCase(transferEncoding, HttpHeader._CHUNKED)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void decodeLast(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
            throws Exception {
        super.decodeLast(ctx, in, out);

        if (message == null) {
            if (headerParser.getSize() != 0) {
                out.add(invalidMessage(Unpooled.EMPTY_BUFFER, MISSING_FULL_HEADER));
            }
            resetNow();
            return;
        }

        boolean chunked = isTransferEncodingChunked();
        if (currentState == State.READ_VARIABLE_LENGTH_CONTENT && !in.isReadable() && !chunked) {
            out.add(message);
            resetNow();
            return;
        }

        boolean prematureClosure;
        if (decodingRequest || chunked) {
            prematureClosure = true;
        } else {
            prematureClosure = header.getContentLength() > 0;
        }

        if (prematureClosure) {
            message.setUserObject(MISSING_FULL_BODY);
        }
        out.add(message);
        resetNow();
    }

    protected boolean isContentAlwaysEmpty(HttpMessage msg) {
        if (decodingRequest) {
            return false;
        }

        int code = msg.getResponseHeader().getStatusCode();
        if (HttpStatusCode.isInformational(code) || code == 204 || code == 304) {
            return true;
        }
        return false;
    }

    private void resetNow() {
        message = null;
        HttpHeader header = this.header;
        this.header = null;
        body = null;

        headerParser.reset();
        lineParser.reset();

        if (!decodingRequest
                && header != null
                && isSwitchingToNonHttp1Protocol((HttpResponseHeader) header)) {
            currentState = State.UPGRADED;
            return;
        }

        currentState = State.READ_HEADER;
    }

    private static boolean isSwitchingToNonHttp1Protocol(HttpResponseHeader header) {
        if (header.getStatusCode() != HttpStatusCode.SWITCHING_Protocols) {
            return false;
        }
        String newProtocol = header.getHeader("Upgrade");
        return newProtocol != null
                && !newProtocol.contains(HttpHeader.HTTP10)
                && !newProtocol.contains(HttpHeader.HTTP11);
    }

    private HttpMessage invalidMessage(ByteBuf in, Exception cause) {
        currentState = State.BAD_MESSAGE;
        in.skipBytes(in.readableBytes());

        if (message == null) {
            message = new HttpMessage();
        }
        message.setUserObject(cause);

        HttpMessage ret = message;
        message = null;
        return ret;
    }

    private boolean readTrailingHeaders(ByteBuf buffer) throws HttpMalformedHeaderException {
        AppendableCharSequence line = lineParser.parse(buffer);
        if (line == null) {
            return false;
        }
        if (line.length() == 0) {
            return true;
        }

        int pos = -1;
        while (line.length() > 0) {
            String headerField = line.toString();
            if ((pos = headerField.indexOf(':')) < 0) {
                throw new HttpMalformedHeaderException(
                        "Missing name/value separator in header field: " + headerField);
            }

            String name = headerField.substring(0, pos).trim();
            String value = headerField.substring(pos + 1).trim();
            header.addHeader(name, value);

            line = lineParser.parse(buffer);
            if (line == null) {
                return false;
            }
        }

        return true;
    }

    private static int getChunkSize(String hex) {
        hex = hex.trim();
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            if (c == ';' || Character.isWhitespace(c) || Character.isISOControl(c)) {
                hex = hex.substring(0, i);
                break;
            }
        }

        return Integer.parseInt(hex, 16);
    }

    private static class HeaderParser implements ByteProcessor {
        protected final AppendableCharSequence seq;
        private int size;

        HeaderParser(AppendableCharSequence seq) {
            this.seq = seq;
        }

        public AppendableCharSequence parse(ByteBuf buffer) {
            seq.reset();
            int i = buffer.forEachByte(this);
            if (i == -1) {
                return null;
            }
            buffer.readerIndex(i + 1);
            return seq;
        }

        public int getSize() {
            return size;
        }

        public void reset() {
            size = 0;
        }

        @Override
        public boolean process(byte value) throws Exception {
            char currentByte = (char) (value & 0xFF);
            boolean headerEnd = isHeaderEnd(currentByte);
            seq.append(currentByte);
            size++;
            return !headerEnd;
        }

        private boolean isHeaderEnd(char currentByte) {
            if (currentByte != LF) {
                return false;
            }

            int len = seq.length();
            if (len < 1) {
                return false;
            }

            char lastChar = seq.charAtUnsafe(len - 1);
            if (lastChar == LF) {
                return true;
            }

            if (lastChar != CR || len < 2) {
                return false;
            }

            char previousChar = seq.charAtUnsafe(len - 2);
            if (previousChar == LF) {
                return true;
            }
            return false;
        }
    }

    private static class LineParser extends HeaderParser {

        LineParser(AppendableCharSequence seq) {
            super(seq);
        }

        @Override
        public boolean process(byte value) throws Exception {
            char nextByte = (char) (value & 0xFF);
            if (nextByte == LF) {
                int len = seq.length();
                if (len >= 1 && seq.charAtUnsafe(len - 1) == CR) {
                    seq.setLength(len - 1);
                }
                return false;
            }

            seq.append(nextByte);
            return true;
        }
    }

    protected interface HeaderProvider {

        HttpHeader get(ChannelHandlerContext ctx, HttpMessage msg, String content)
                throws HttpMalformedHeaderException;
    }
}
