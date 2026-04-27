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
package org.zaproxy.zap.extension.scripts.automation;

import java.lang.reflect.Method;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public final class ScriptRunFailureDetail {

    private static final Logger LOGGER = LogManager.getLogger(ScriptRunFailureDetail.class);

    private ScriptRunFailureDetail() {}

    /**
     * {@link ScriptWrapper#getLastException()} when set, otherwise the first line of {@link
     * ScriptWrapper#getLastErrorDetails()}.
     */
    public static String compactScriptOutputDetailForPersistence(ScriptWrapper script) {
        if (script == null) {
            return "";
        }
        Exception ex = script.getLastException();
        if (ex != null) {
            return compactExceptionDetailForPersistence(ex);
        }
        String details = script.getLastErrorDetails();
        if (StringUtils.isBlank(details)) {
            return "";
        }
        int nl = details.indexOf('\n');
        return (nl > 0 ? details.substring(0, nl) : details).trim();
    }

    /**
     * Selenium {@code getRawMessage()} when present, otherwise the first line of {@code
     * getMessage()} on each cause, otherwise {@code getClass().getName()}.
     */
    public static String compactExceptionDetailForPersistence(Exception e) {
        Throwable t = e;
        while (t != null) {
            try {
                Method raw = t.getClass().getMethod("getRawMessage");
                Object r = raw.invoke(t);
                if (r instanceof String s && StringUtils.isNotBlank(s)) {
                    return s.trim();
                }
            } catch (NoSuchMethodException ignore) {
                // Not WebDriver-style
            } catch (ReflectiveOperationException | SecurityException ex) {
                LOGGER.debug("Could not read raw Selenium message", ex);
            }
            String msg = t.getMessage();
            if (StringUtils.isNotBlank(msg)) {
                int nl = msg.indexOf('\n');
                return (nl > 0 ? msg.substring(0, nl) : msg).trim();
            }
            t = t.getCause();
        }
        return e.getClass().getName();
    }
}
