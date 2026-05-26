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
package org.zaproxy.zap.extension.selenium;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import lombok.Builder;
import lombok.Getter;
import org.openqa.selenium.MutableCapabilities;

/**
 * Configuration for obtaining a WebDriver.
 *
 * <p>Allows specifying requester, proxy, browser extensions, and optional capability customisation.
 */
@Builder
@Getter
public class DriverConfiguration {

    /** Underlying browser/driver type for driver creation. */
    public enum DriverType {
        CHROMIUM,
        EDGE,
        FIREFOX,
        HTML_UNIT,
        SAFARI
    }

    private final int requester;
    private final String proxyAddress;
    private final int proxyPort;
    private final boolean enableExtensions;
    private final Consumer<MutableCapabilities> consumer;
    private final DriverType type;
    @Builder.Default private final boolean headless = false;
    @Builder.Default private final String binaryPath = null;
    @Builder.Default private final String driverPath = "";
    @Builder.Default private final List<String> arguments = Collections.emptyList();
    @Builder.Default private final Map<String, String> preferences = Collections.emptyMap();
    @Builder.Default private final List<String> includeExtensions = Collections.emptyList();
    @Builder.Default private final List<String> excludeExtensions = Collections.emptyList();
}
