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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The result of the import.
 *
 * @see Importer#apply(ImporterOptions)
 * @since 0.13.0
 */
public class ImporterResult {

    private List<String> errors;
    private Throwable cause;
    private int count;

    /**
     * Gets the count of imported messages.
     *
     * @return the count.
     */
    public int getCount() {
        return count;
    }

    void incrementCount() {
        this.count++;
    }

    /**
     * Gets the errors that happened while importing, if any.
     *
     * @return the errors, never {@code null}.
     */
    public List<String> getErrors() {
        if (errors == null) {
            return List.of();
        }
        return Collections.unmodifiableList(errors);
    }

    /**
     * Gets the cause of the error, if any.
     *
     * @return the cause of the error, might be {@code null}.
     */
    public Throwable getCause() {
        return cause;
    }

    void addError(String error) {
        createErrors();
        errors.add(error);
    }

    private void createErrors() {
        if (errors == null) {
            errors = new ArrayList<>();
        }
    }

    void addError(String error, Throwable cause) {
        createErrors();
        errors.add(error);
        this.cause = cause;
    }
}
