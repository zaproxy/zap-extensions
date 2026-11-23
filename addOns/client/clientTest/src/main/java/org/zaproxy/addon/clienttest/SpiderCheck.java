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
package org.zaproxy.addon.clienttest;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.model.Model;

/**
 * Checks the outcome of a Client Spider scan, for example of the never loading test app.
 *
 * <p>It is meant to be called from scripts, in an Automation Framework plan, around the spider job:
 * {@code SpiderCheck.start()} before it and {@code SpiderCheck.check(canaryUrl, maxSeconds)} after
 * it.
 */
public final class SpiderCheck {

    private static volatile long startMs;

    private SpiderCheck() {}

    /** Starts the timer for the scan. */
    public static void start() {
        startMs = System.currentTimeMillis();
    }

    /**
     * Checks that the scan took no longer than the given time and that the given page, which can
     * only be reached by getting past the pages which do not load, was requested.
     *
     * @param pageUrl the URL of the page which has to have been requested.
     * @param maxSeconds the maximum time the scan can take, since {@link #start()}.
     * @return a report of the outcome.
     * @throws IllegalStateException if the scan took too long or the page was not requested.
     * @throws URIException if the URL is not valid.
     */
    public static String check(String pageUrl, long maxSeconds) throws URIException {
        long elapsedMs = System.currentTimeMillis() - startMs;
        boolean requested =
                Model.getSingleton().getSession().getSiteTree().findNode(new URI(pageUrl, true))
                        != null;
        return check(elapsedMs, maxSeconds, pageUrl, requested);
    }

    static String check(long elapsedMs, long maxSeconds, String pageUrl, boolean requested) {
        String report =
                "Scan took "
                        + elapsedMs / 1000
                        + "s (max "
                        + maxSeconds
                        + "s), "
                        + pageUrl
                        + (requested ? " was" : " was not")
                        + " requested.";
        if (elapsedMs > maxSeconds * 1000) {
            throw new IllegalStateException("The scan took too long. " + report);
        }
        if (!requested) {
            throw new IllegalStateException("The page was not found. " + report);
        }
        return report;
    }
}
