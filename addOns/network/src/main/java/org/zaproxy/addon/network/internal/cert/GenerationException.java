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
package org.zaproxy.addon.network.internal.cert;

/** An exception that indicates an error during the generation of a certificate. */
public class GenerationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a {@code GenerationException} with the given cause.
     *
     * @param cause the cause of the exception.
     */
    public GenerationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a {@code GenerationException} with the given message and cause.
     *
     * @param message the detail message.
     * @param cause the cause of the exception.
     */
    public GenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
