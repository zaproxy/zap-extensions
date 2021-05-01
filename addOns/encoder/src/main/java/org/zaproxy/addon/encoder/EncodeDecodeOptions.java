/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.encoder;

import org.zaproxy.zap.common.VersionedAbstractParam;

public class EncodeDecodeOptions extends VersionedAbstractParam {

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int PARAM_CURRENT_VERSION = 1;
    /** The base configuration key for all "encoder" configurations. */
    private static final String PARAM_BASE_KEY = "encoder";

    private static final String PARAM_BASE64_CHARSET = "encoder.base64charset";
    private static final String PARAM_BASE64_DO_BREAK_LINES = "encoder.base64dobreaklines";

    private static final String CORE_PARAM_BASE64_CHARSET = "encode.param.base64charset";
    private static final String CORE_PARAM_BASE64_DO_BREAK_LINES =
            "encode.param.base64dobreaklines";

    public static final String DEFAULT_CHARSET = "UTF-8";
    public static final boolean DEFAULT_DO_BREAK_LINES = true;

    private String base64Charset;
    private boolean base64DoBreakLines;

    public EncodeDecodeOptions() {
        base64Charset = DEFAULT_CHARSET;
        base64DoBreakLines = DEFAULT_DO_BREAK_LINES;
    }

    public String getBase64Charset() {
        return base64Charset;
    }

    public void setBase64Charset(String base64FromCharset) {
        this.base64Charset = base64FromCharset;
        getConfig().setProperty(PARAM_BASE64_CHARSET, base64FromCharset);
    }

    public boolean isBase64DoBreakLines() {
        return base64DoBreakLines;
    }

    public void setBase64DoBreakLines(boolean base64OuputBreak) {
        this.base64DoBreakLines = base64OuputBreak;
        getConfig().setProperty(PARAM_BASE64_DO_BREAK_LINES, base64OuputBreak);
    }

    @Override
    protected void parseImpl() {
        base64DoBreakLines = getBoolean(PARAM_BASE64_DO_BREAK_LINES, DEFAULT_DO_BREAK_LINES);
        base64Charset = getString(PARAM_BASE64_CHARSET, DEFAULT_CHARSET);
    }

    @Override
    protected String getConfigVersionKey() {
        return PARAM_BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return PARAM_CURRENT_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // When in ZAP "core"
        if (fileVersion == NO_CONFIG_VERSION) {
            boolean oldValue = getBoolean(CORE_PARAM_BASE64_DO_BREAK_LINES, DEFAULT_DO_BREAK_LINES);
            getConfig().clearProperty(CORE_PARAM_BASE64_DO_BREAK_LINES);

            getConfig().setProperty(PARAM_BASE64_DO_BREAK_LINES, Boolean.valueOf(oldValue));

            String oldCharset = getString(CORE_PARAM_BASE64_CHARSET, DEFAULT_CHARSET);
            getConfig().clearProperty(CORE_PARAM_BASE64_CHARSET);

            getConfig().setProperty(CORE_PARAM_BASE64_CHARSET, oldCharset);
        }
    }
}
