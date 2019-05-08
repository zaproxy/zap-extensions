/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.jxbrowser;

/** Utility methods used/for JxBrowser classes/extensions. */
public final class Utils {

    private Utils() {}

    /**
     * Tells whether or not the current OS/JVM is 64bits arch.
     *
     * @return {@code true} if the OS/JVM is 64bits arch, {@code false} otherwise.
     */
    public static boolean isOs64Bits() {
        String arch = System.getProperty("os.arch");
        return arch.contains("amd64") || arch.contains("x86_64");
    }
}
