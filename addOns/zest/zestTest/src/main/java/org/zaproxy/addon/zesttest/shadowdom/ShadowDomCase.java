/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.zesttest.shadowdom;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/** The states of the Shadow DOM served by the test app, one directory per case. */
public enum ShadowDomCase {
    OPEN("open", 0, "open"),
    CLOSED("closed", 0, "closed"),
    OPEN_OPEN("open-open", 0, "open", "open"),
    CLOSED_CLOSED("closed-closed", 0, "closed", "closed"),
    OPEN_CLOSED("open-closed", 0, "open", "closed"),
    CLOSED_OPEN("closed-open", 0, "closed", "open"),
    DELAYED_OPEN("delayed-open", ShadowDomCase.DELAY_MS, "open"),
    DELAYED_CLOSED("delayed-closed", ShadowDomCase.DELAY_MS, "closed"),
    DELAYED_OPEN_CLOSED("delayed-open-closed", ShadowDomCase.DELAY_MS, "open", "closed"),
    DELAYED_CLOSED_OPEN("delayed-closed-open", ShadowDomCase.DELAY_MS, "closed", "open");

    /** The delay before attaching each shadow root, in the delayed cases. */
    static final int DELAY_MS = 2000;

    private final String dirName;
    private final int delayMs;
    private final List<String> modes;

    ShadowDomCase(String dirName, int delayMs, String... modes) {
        this.dirName = dirName;
        this.delayMs = delayMs;
        this.modes = List.of(modes);
    }

    public String getDirName() {
        return dirName;
    }

    public int getDelayMs() {
        return delayMs;
    }

    /**
     * Gets the modes of the shadow roots, outermost first.
     *
     * @return the modes, {@code open} or {@code closed}.
     */
    public List<String> getModes() {
        return modes;
    }

    /**
     * Gets the CSS selectors of the shadow hosts, outermost first, as used in the shadow path of
     * the Zest client elements.
     *
     * @return the shadow path.
     */
    public List<String> getShadowPath() {
        return IntStream.range(0, modes.size()).mapToObj(i -> "#host" + i).toList();
    }

    /**
     * Gets the configuration used by the page to create the shadow roots.
     *
     * @return the configuration, in JSON.
     */
    public String toJson() {
        return modes.stream()
                .map(m -> "\"" + m + "\"")
                .collect(Collectors.joining(",", "{\"modes\":[", "],\"delay\":" + delayMs + "}"));
    }
}
