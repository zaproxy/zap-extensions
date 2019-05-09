/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.tokengen;

import org.zaproxy.zap.common.VersionedAbstractParam;

/**
 * Manages the options saved in the configuration file.
 *
 * <p>It allows to change, programmatically, the following options:
 *
 * <ul>
 *   <li>Number of threads for the token generation;
 *   <li>The request delay;
 * </ul>
 */
public class TokenParam extends VersionedAbstractParam {

    protected static final int DEFAULT_THREADS_PER_SCAN = 5;

    protected static final int DEFAULT_REQUEST_DELAY_IN_MS = 0;

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int PARAM_CURRENT_VERSION = 1;

    /** The base configuration key for all configurations. */
    private static final String PARAM_BASE_KEY = "tokengen";

    private static final String THREADS_PER_SCAN = PARAM_BASE_KEY + ".threadsPerScan";

    private static final String REQUEST_DELAY_IN_MS = PARAM_BASE_KEY + ".requestDelayInMs";

    private int threadsPerScan = DEFAULT_THREADS_PER_SCAN;

    private int requestDelayInMs = DEFAULT_REQUEST_DELAY_IN_MS;

    public TokenParam() {}

    @Override
    protected int getCurrentVersion() {
        return PARAM_CURRENT_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return PARAM_BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to update.
    }

    @Override
    protected void parseImpl() {
        setThreadsPerScanImpl(getConfig().getInt(THREADS_PER_SCAN, DEFAULT_THREADS_PER_SCAN));

        requestDelayInMs = getConfig().getInt(REQUEST_DELAY_IN_MS, DEFAULT_REQUEST_DELAY_IN_MS);
    }

    private void setThreadsPerScanImpl(int threadsPerScan) {
        this.threadsPerScan = threadsPerScan <= 0 ? DEFAULT_THREADS_PER_SCAN : threadsPerScan;
    }

    public int getThreadsPerScan() {
        return threadsPerScan;
    }

    public void setThreadsPerScan(int threadsPerScan) {
        setThreadsPerScanImpl(threadsPerScan);
        getConfig().setProperty(THREADS_PER_SCAN, this.threadsPerScan);
    }

    public int getRequestDelayInMs() {
        return requestDelayInMs;
    }

    public void setRequestDelayInMs(int requestDelayInMs) {
        this.requestDelayInMs = requestDelayInMs;
        getConfig().setProperty(REQUEST_DELAY_IN_MS, this.requestDelayInMs);
    }
}
