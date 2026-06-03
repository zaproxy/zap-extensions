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
package org.zaproxy.zap.extension.zest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;

/** Captures browser screenshots for Zest failure diagnostics. */
final class ZestFailureScreenshotCapture {

    private static final Logger LOGGER = LogManager.getLogger(ZestFailureScreenshotCapture.class);

    private ZestFailureScreenshotCapture() {}

    static String captureBase64(WebDriver webDriver) {
        if (!(webDriver instanceof TakesScreenshot screenshot)) {
            return null;
        }
        try {
            return screenshot.getScreenshotAs(OutputType.BASE64);
        } catch (RuntimeException e) {
            LOGGER.debug("Failed to capture browser screenshot: {}", e.getMessage());
            return null;
        }
    }
}
