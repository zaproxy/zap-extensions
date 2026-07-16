/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim;

import java.nio.file.Path;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.exim.har.HarImporterType;
import org.zaproxy.zap.model.Context;

/**
 * The options for the importer.
 *
 * @since 0.13.0
 * @see Importer
 */
public class ImporterOptions {

    private final Context context;
    private final String type;
    private final Path inputFile;
    private final MessageHandler messageHandler;
    private final boolean sendRequests;

    private ImporterOptions(
            Context context,
            String type,
            Path inputFile,
            MessageHandler messageHandler,
            boolean sendRequests) {
        this.context = context;
        this.type = type;
        this.inputFile = inputFile;
        this.messageHandler = messageHandler;
        this.sendRequests = sendRequests;
    }

    public Context getContext() {
        return context;
    }

    public String getType() {
        return type;
    }

    public Path getInputFile() {
        return inputFile;
    }

    public MessageHandler getMessageHandler() {
        return messageHandler;
    }

    /**
     * Tells whether or not the requests should be sent instead of importing recorded responses.
     *
     * @return {@code true} if the requests should be sent, {@code false} otherwise.
     */
    public boolean isSendRequests() {
        return sendRequests;
    }

    /**
     * Returns a new builder.
     *
     * @return the options builder.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder of options.
     *
     * @see #build()
     */
    public static class Builder {

        private Context context;
        private String type;
        private Path inputFile;
        private MessageHandler messageHandler;
        private boolean sendRequests;

        private Builder() {
            type = HarImporterType.ID;
        }

        /**
         * Sets the context.
         *
         * <p>Default value: {@code null}.
         *
         * @param context the context.
         * @return the builder for chaining.
         */
        public Builder setContext(Context context) {
            this.context = context;
            return this;
        }

        /**
         * Sets the type.
         *
         * <p>Default value: {@link HarImporterType#ID}.
         *
         * @param type the type identifier.
         * @return the builder for chaining.
         * @throws IllegalArgumentException if the type is {@code null}.
         */
        public Builder setType(String type) {
            if (type == null) {
                throw new IllegalArgumentException("The type must not be null.");
            }
            this.type = type;
            return this;
        }

        /**
         * Sets the input file.
         *
         * <p>Default value: {@code null}.
         *
         * @param inputFile the input file.
         * @return the builder for chaining.
         */
        public Builder setInputFile(Path inputFile) {
            this.inputFile = inputFile;
            return this;
        }

        /**
         * Sets the message handler.
         *
         * <p>Default value: {@code null}.
         *
         * @param messageHandler the message handler.
         * @return the builder for chaining.
         */
        public Builder setMessageHandler(MessageHandler messageHandler) {
            this.messageHandler = messageHandler;
            return this;
        }

        /**
         * Sets whether or not the requests should be sent instead of importing recorded responses.
         *
         * <p>Default value: {@code false}.
         *
         * @param sendRequests {@code true} to send the requests, {@code false} otherwise.
         * @return the builder for chaining.
         */
        public Builder setSendRequests(boolean sendRequests) {
            this.sendRequests = sendRequests;
            return this;
        }

        /**
         * Builds the options from the specified data.
         *
         * @return the options with specified data.
         * @throws IllegalStateException if built without {@link #setInputFile(Path) setting the
         *     input file} or {@link #setMessageHandler(MessageHandler) the message handler}.
         */
        public final ImporterOptions build() {
            if (inputFile == null) {
                throw new IllegalStateException("The inputFile must be set.");
            }
            if (messageHandler == null) {
                throw new IllegalStateException("The messageHandler must be set.");
            }
            return new ImporterOptions(context, type, inputFile, messageHandler, sendRequests);
        }
    }

    /** Handles the messages being imported. */
    public interface MessageHandler {

        /**
         * Handles the given imported message.
         *
         * @param message the message imported.
         * @throws Exception if an error occurred while handling the message and the import should
         *     be stopped.
         */
        void handle(HttpMessage message) throws Exception;
    }
}
