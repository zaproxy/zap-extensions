/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads.generator;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * A {@code PayloadGenerator} that 'generates' payloads from a file.
 *
 * <p>It reads the contents of a file and returns a payload for each line read. Ignoring empty and
 * commented lines.
 */
public class FileStringPayloadGenerator implements StringPayloadGenerator {

    private static final Logger LOGGER = LogManager.getLogger(FileStringPayloadGenerator.class);

    public static final String DEFAULT_COMMENT_TOKEN = "#";

    /** The value that indicates there's no limit when reading the payloads from the file. */
    public static final int NO_LIMIT = 0;

    /** The source of payloads. */
    private final Path file;

    private final Charset charset;

    /** The number of payloads contained in the file. */
    private final long numberOfPayloads;

    private final boolean ignoreTrimmedEmptyLines;

    private final boolean ignoreFirstLine;

    private final String commentToken;

    public FileStringPayloadGenerator(Path file) {
        this(file, NO_LIMIT);
    }

    /**
     * Constructs a {@code FilePayload} which reads the payloads from the given {@code file}.
     *
     * @param file the path to the file containing the payloads
     * @param limit the maximum number of payloads that should be read from the file, zero or
     *     negative number indicates no limit
     */
    public FileStringPayloadGenerator(Path file, int limit) {
        this(file, limit, DEFAULT_COMMENT_TOKEN);
    }

    public FileStringPayloadGenerator(Path file, int limit, String commentToken) {
        this(file, StandardCharsets.UTF_8, limit, commentToken, true, false);
    }

    public FileStringPayloadGenerator(
            Path file,
            Charset charset,
            long limit,
            String commentToken,
            boolean ignoreTrimmedEmptyLines,
            boolean ignoreFirstLine) {
        this(file, charset, limit, commentToken, ignoreTrimmedEmptyLines, ignoreFirstLine, -1);
    }

    public FileStringPayloadGenerator(
            Path file,
            Charset charset,
            long limit,
            String commentToken,
            boolean ignoreTrimmedEmptyLines,
            boolean ignoreFirstLine,
            long numberOfPayloads) {
        if (file == null) {
            throw new IllegalArgumentException("Parameter file must not be null.");
        }
        if (!Files.isReadable(file)) {
            throw new IllegalArgumentException("Parameter file must be a file and readable.");
        }

        if (charset == null) {
            throw new IllegalArgumentException("Parameter charset must not be null.");
        }

        this.file = file;
        this.charset = charset;
        this.commentToken = commentToken;
        this.ignoreTrimmedEmptyLines = ignoreTrimmedEmptyLines;
        this.ignoreFirstLine = ignoreFirstLine;
        if (numberOfPayloads > 0) {
            this.numberOfPayloads = numberOfPayloads;
        } else {
            long calculatedNumberOfPayloads = 0;
            try {
                calculatedNumberOfPayloads =
                        calculateNumberOfPayloadsImpl(
                                file,
                                charset,
                                limit,
                                commentToken,
                                ignoreTrimmedEmptyLines,
                                ignoreFirstLine,
                                true);
            } catch (IOException ignore) {
                // Does not happen.
            }
            this.numberOfPayloads = calculatedNumberOfPayloads;
        }
    }

    public static int calculateNumberOfPayloads(
            Path file,
            Charset charset,
            long limit,
            String commentToken,
            boolean ignoreTrimmedEmptyLines,
            boolean ignoreFirstLine)
            throws IOException {
        return calculateNumberOfPayloadsImpl(
                file,
                charset,
                limit,
                commentToken,
                ignoreTrimmedEmptyLines,
                ignoreFirstLine,
                false);
    }

    private static int calculateNumberOfPayloadsImpl(
            Path file,
            Charset charset,
            long limit,
            String commentToken,
            boolean ignoreTrimmedEmptyLines,
            boolean ignoreFirstLine,
            boolean ignoreException)
            throws IOException {
        boolean checkCommentedLines = !commentToken.isEmpty();
        int count = 0;

        try (BufferedReader reader = Files.newBufferedReader(file, charset)) {
            if (ignoreFirstLine) {
                reader.readLine();
            }

            boolean lineValid;
            String line = null;
            while ((line = reader.readLine()) != null) {
                if (limit > NO_LIMIT && count >= limit) {
                    break;
                }

                lineValid = true;
                if (ignoreTrimmedEmptyLines && line.trim().isEmpty()) {
                    lineValid = false;
                } else if (checkCommentedLines) {
                    lineValid = !line.startsWith(commentToken);
                }

                if (lineValid) {
                    count++;
                }
            }
        } catch (IOException e) {
            if (!ignoreException) {
                throw e;
            }
        }
        return count;
    }

    @Override
    public long getNumberOfPayloads() {
        return numberOfPayloads;
    }

    @Override
    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
        return new FileIterator(
                file,
                charset,
                numberOfPayloads,
                commentToken,
                ignoreTrimmedEmptyLines,
                ignoreFirstLine);
    }

    @Override
    public FileStringPayloadGenerator copy() {
        return this;
    }

    private static class FileIterator implements ResettableAutoCloseableIterator<DefaultPayload> {

        private final Path file;
        private final Charset charset;
        private final long limit;
        private final String commentToken;
        private final boolean checkCommentedLines;
        private final boolean ignoreTrimmedEmptyLines;
        private final boolean ignoreFirstLine;
        private BufferedReader reader;
        private boolean initialised;
        private long current;

        public FileIterator(
                Path file,
                Charset charset,
                long limit,
                String commentToken,
                boolean ignoreTrimmedEmptyLines,
                boolean ignoreFirstLine) {
            this.file = file;
            this.charset = charset;
            this.limit = limit;
            this.commentToken = commentToken;
            this.checkCommentedLines = !commentToken.isEmpty();
            this.ignoreTrimmedEmptyLines = ignoreTrimmedEmptyLines;
            this.ignoreFirstLine = ignoreFirstLine;
        }

        @Override
        public boolean hasNext() {
            return current < limit;
        }

        @Override
        public DefaultPayload next() {
            try {
                init();

                return readNextPayload();
            } finally {
                current++;
            }
        }

        private void init() {
            if (initialised) {
                return;
            }
            try {
                reader = Files.newBufferedReader(file, charset);
                if (ignoreFirstLine) {
                    reader.readLine();
                }
            } catch (IOException e) {
                throw new PayloadGenerationException("Failed to read/initialise the file:", e);
            } finally {
                initialised = true;
            }
        }

        private DefaultPayload readNextPayload() {
            if (reader == null) {
                throw new PayloadGenerationException("Failed to read the file.");
            }

            try {
                boolean lineValid;
                String line = null;
                while ((line = reader.readLine()) != null) {
                    lineValid = true;
                    if (ignoreTrimmedEmptyLines && line.trim().isEmpty()) {
                        lineValid = false;
                    } else if (checkCommentedLines) {
                        lineValid = !line.startsWith(commentToken);
                    }

                    if (lineValid) {
                        return new DefaultPayload(line);
                    }
                }
            } catch (IOException e) {
                throw new PayloadGenerationException("Failed to read the file:", e);
            }

            throw new PayloadGenerationException("Failed to read the file.");
        }

        @Override
        public void remove() {}

        @Override
        public void reset() {
            current = 0;
            initialised = false;
            close();
        }

        @Override
        public void close() {
            if (reader == null) {
                return;
            }

            try {
                reader.close();
            } catch (IOException ignore) {
                LOGGER.debug("Failed to close file {}", file, ignore);
            }
        }
    }
}
