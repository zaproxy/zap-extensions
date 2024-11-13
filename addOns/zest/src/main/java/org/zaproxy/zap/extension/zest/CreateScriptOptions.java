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
package org.zaproxy.zap.extension.zest;

/**
 * The options for script creation.
 *
 * @since 48.0.0
 * @see ExtensionZest#createScript(String, org.zaproxy.zap.extension.script.ScriptType,
 *     java.util.List, CreateScriptOptions)
 */
public class CreateScriptOptions {

    /** The default options. */
    public static final CreateScriptOptions DEFAULT = builder().build();

    /** When should the responses be included in the corresponding Zest requests. */
    public enum IncludeResponses {
        NEVER,
        ALWAYS,
        /**
         * Uses the value defined in the global option.
         *
         * @see ZestParam#isIncludeResponses()
         */
        GLOBAL_OPTION,
    }

    private final boolean addStatusAssertion;
    private final boolean addLengthAssertion;
    private final int lengthApprox;
    private final IncludeResponses includeResponses;
    private final boolean replaceRequestValues;

    private CreateScriptOptions(
            boolean addStatusAssertion,
            boolean addLengthAssertion,
            int lengthApprox,
            IncludeResponses includeResponses,
            boolean replaceRequestValues) {

        this.addStatusAssertion = addStatusAssertion;
        this.addLengthAssertion = addLengthAssertion;
        this.lengthApprox = lengthApprox;
        this.includeResponses = includeResponses;
        this.replaceRequestValues = replaceRequestValues;
    }

    public boolean isAddStatusAssertion() {
        return addStatusAssertion;
    }

    public boolean isAddLengthAssertion() {
        return addLengthAssertion;
    }

    public int getLengthApprox() {
        return lengthApprox;
    }

    public IncludeResponses getIncludeResponses() {
        return includeResponses;
    }

    public boolean isReplaceRequestValues() {
        return replaceRequestValues;
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

        private boolean addStatusAssertion;
        private boolean addLengthAssertion;
        private int lengthApprox = 1;
        private IncludeResponses includeResponses = IncludeResponses.GLOBAL_OPTION;
        private boolean replaceRequestValues = true;

        private Builder() {}

        /**
         * Sets whether or not the status assertion should be added to the requests.
         *
         * <p>Default value: {@code false}.
         *
         * @param addStatusAssertion {@code true} if the assertion should be added, {@code false}
         *     otherwise.
         * @return the builder for chaining.
         */
        public Builder setAddStatusAssertion(boolean addStatusAssertion) {
            this.addStatusAssertion = addStatusAssertion;
            return this;
        }

        /**
         * Sets whether or not the length assertion should be added to the requests.
         *
         * <p>Default value: {@code false}.
         *
         * @param addLengthAssertion {@code true} if the assertion should be added, {@code false}
         *     otherwise.
         * @return the builder for chaining.
         */
        public Builder setAddLengthAssertion(boolean addLengthAssertion) {
            this.addLengthAssertion = addLengthAssertion;
            return this;
        }

        /**
         * Sets the approximate value for the length assertions.
         *
         * <p>Default value: {@code 1}.
         *
         * @param lengthApprox the approximate value.
         * @return the builder for chaining.
         * @throws IllegalArgumentException if the given value is negative.
         * @see #setAddLengthAssertion(boolean)
         */
        public Builder setLengthApprox(int lengthApprox) {
            if (lengthApprox < 0) {
                throw new IllegalArgumentException("The length must be zero or greater.");
            }
            this.lengthApprox = lengthApprox;
            return this;
        }

        /**
         * Sets the include responses option.
         *
         * <p>Default value: {@code GLOBAL_OPTION}.
         *
         * @param includeResponses the include responses option.
         * @return the builder for chaining.
         * @throws IllegalArgumentException if the given value is null.
         */
        public Builder setIncludeResponses(IncludeResponses includeResponses) {
            if (includeResponses == null) {
                throw new IllegalArgumentException("The include responses must not be null.");
            }
            this.includeResponses = includeResponses;
            return this;
        }

        /**
         * Sets whether or not the request values should be automatically replaced.
         *
         * <p>Values present in later requests that are found in earlier responses are automatically
         * replaced (e.g. anti-CSRF token).
         *
         * <p>Default value: {@code true}.
         *
         * @param replaceRequestValues {@code true} if the values should be replaced, {@code false}
         *     otherwise.
         * @return the builder for chaining.
         */
        public Builder setReplaceRequestValues(boolean replaceRequestValues) {
            this.replaceRequestValues = replaceRequestValues;
            return this;
        }

        /**
         * Builds the options from the specified data.
         *
         * @return the options with specified data.
         */
        public final CreateScriptOptions build() {
            return new CreateScriptOptions(
                    addStatusAssertion,
                    addLengthAssertion,
                    lengthApprox,
                    includeResponses,
                    replaceRequestValues);
        }
    }
}
