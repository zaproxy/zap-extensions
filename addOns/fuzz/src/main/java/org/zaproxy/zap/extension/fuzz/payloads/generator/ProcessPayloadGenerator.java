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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public class ProcessPayloadGenerator implements StringPayloadGenerator {

    private static final Logger LOGGER = LogManager.getLogger(ProcessPayloadGenerator.class);

    private final int numberOfInvocations;
    private final ProcessBuilder processBuilder;
    private final boolean failOnErrorOutput;

    public ProcessPayloadGenerator(
            Path command, int numberOfInvocations, boolean failOnErrorOutput) {
        this(
                command,
                Collections.<String>emptyList(),
                null,
                numberOfInvocations,
                failOnErrorOutput);
    }

    public ProcessPayloadGenerator(
            Path command,
            Path workingDirectory,
            int numberOfInvocations,
            boolean failOnErrorOutput) {
        this(
                command,
                Collections.<String>emptyList(),
                workingDirectory,
                numberOfInvocations,
                failOnErrorOutput);
    }

    public ProcessPayloadGenerator(
            Path command,
            List<String> commandParameters,
            Path workingDirectory,
            int numberOfInvocations,
            boolean failOnErrorOutput) {
        if (command == null) {
            throw new IllegalArgumentException("Parameter command must not be null.");
        }
        if (!Files.isExecutable(command)) {
            throw new IllegalArgumentException("Parameter command must be executable.");
        }

        if (commandParameters == null) {
            throw new IllegalArgumentException("Parameter commandParameters must not be null.");
        }

        if (numberOfInvocations <= 0) {
            throw new IllegalArgumentException(
                    "Parameter numberOfInvocations must be greater than zero.");
        }

        List<String> fullCommand = new ArrayList<>();
        fullCommand.add(command.toAbsolutePath().toString());
        for (String parameter : commandParameters) {
            fullCommand.add(parameter);
        }

        processBuilder = new ProcessBuilder(fullCommand);
        if (workingDirectory != null) {
            if (!Files.isDirectory(workingDirectory)) {
                throw new IllegalArgumentException(
                        "Parameter workingDirectory must represent a directory.");
            }
            processBuilder.directory(workingDirectory.toFile());
        }

        this.numberOfInvocations = numberOfInvocations;
        this.failOnErrorOutput = failOnErrorOutput;
    }

    @Override
    public long getNumberOfPayloads() {
        return numberOfInvocations;
    }

    @Override
    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
        return new ApplicationPayloadIterator(
                numberOfInvocations, processBuilder, failOnErrorOutput);
    }

    @Override
    public ProcessPayloadGenerator copy() {
        return this;
    }

    private static class ApplicationPayloadIterator
            implements ResettableAutoCloseableIterator<DefaultPayload> {

        private final int numberOfInvocations;
        private final ProcessBuilder processBuilder;
        private final boolean failOnProcessError;
        private int count;

        public ApplicationPayloadIterator(
                int numberOfInvocations, ProcessBuilder processBuilder, boolean failOnErrorOutput) {
            this.numberOfInvocations = numberOfInvocations;
            this.processBuilder = processBuilder;
            this.failOnProcessError = failOnErrorOutput;
        }

        @Override
        public boolean hasNext() {
            return count < numberOfInvocations;
        }

        @Override
        public DefaultPayload next() {
            count++;
            return new DefaultPayload(invokeProcess());
        }

        private String invokeProcess() {
            Process process = null;
            try {
                process = processBuilder.start();
                try (BufferedInputStream errorStream =
                                new BufferedInputStream(process.getErrorStream());
                        BufferedInputStream outputStream =
                                new BufferedInputStream(process.getInputStream())) {
                    processErrorStream(errorStream);
                    return readStream(outputStream).toString();
                }
            } catch (SecurityException | IOException e) {
                throw new PayloadGenerationException(
                        "An error occurred while obtaining the payload from the process\""
                                + processBuilder.command()
                                + "\": "
                                + e.toString(),
                        e);
            } finally {
                terminateProcess(process);
            }
        }

        private void processErrorStream(InputStream errorStream) throws IOException {
            StringBuilder errorStringBuilder = readStream(errorStream);

            if (errorStringBuilder.length() != 0) {
                if (failOnProcessError) {
                    throw new PayloadGenerationException(
                            "An error was outputted while obtaining the payload from the process\""
                                    + processBuilder.command()
                                    + "\": "
                                    + errorStringBuilder.toString());
                } else {
                    LOGGER.debug(
                            "Payload generator process \"{}\" returned an error: {}",
                            processBuilder.command(),
                            errorStringBuilder);
                }
            }
        }

        private StringBuilder readStream(InputStream inputStream) throws IOException {
            StringBuilder streamData = new StringBuilder();
            int b = -1;
            while ((b = inputStream.read()) != -1) {
                streamData.append((char) b);
            }
            return streamData;
        }

        private void terminateProcess(Process process) {
            if (process != null) {
                try {
                    int exitCode = process.exitValue();
                    if (exitCode != 0) {
                        if (failOnProcessError) {
                            throw new PayloadGenerationException(
                                    "Payload generator process \""
                                            + processBuilder.command()
                                            + "\" exit code is non-zero ["
                                            + exitCode
                                            + "], discarding any obtained content.");
                        } else {
                            LOGGER.debug(
                                    "Payload generator process \"{}\" exit code is non-zero: {}",
                                    processBuilder.command(),
                                    exitCode);
                        }
                    }
                } catch (IllegalThreadStateException e) {
                    LOGGER.debug(
                            "Forcibly terminating payload generator process: {}",
                            processBuilder.command());
                    process.destroy();
                }
            }
        }

        @Override
        public void remove() {}

        @Override
        public void reset() {
            count = 0;
        }

        @Override
        public void close() {}
    }
}
