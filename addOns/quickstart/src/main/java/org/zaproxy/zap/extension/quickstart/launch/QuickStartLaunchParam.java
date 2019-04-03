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
package org.zaproxy.zap.extension.quickstart.launch;

import java.net.URL;

import org.apache.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;

public class QuickStartLaunchParam extends AbstractParam {

    private static final Logger LOGGER = Logger
            .getLogger(QuickStartLaunchParam.class);

    private static final String PARAM_BASE_KEY = "quickstart.launch";

    private static final String PARAM_START_PAGE = PARAM_BASE_KEY
            + ".startPage";

    private static final String PARAM_DEFAULT_BROWSER = PARAM_BASE_KEY
            + ".defaultBrowser";

    private static final String ZAP_START_PAGE = "ZAP";

    private static final String BLANK_START_PAGE = "BLANK";

    private static final String DEFAULT_BROWSER = "JxBrowser";   // The default default ;)

    private String startPage;
    private String defaultBrowser = DEFAULT_BROWSER;

    @Override
    protected void parse() {
        try {
            startPage = getConfig().getString(PARAM_START_PAGE, ZAP_START_PAGE);
        } catch (Exception e) {
            LOGGER.error("Failed to load the \"Start Page\" configuration", e);
        }
        try {
            defaultBrowser = getConfig().getString(PARAM_DEFAULT_BROWSER, DEFAULT_BROWSER);
        } catch (Exception e) {
            LOGGER.error(
                    "Failed to load the \"Default Browser\" configuration", e);
        }
    }

    public String getStartPage() {
        return startPage;
    }

    public boolean isZapStartPage() {
        return ZAP_START_PAGE.equals(startPage);
    }

    public boolean isBlankStartPage() {
        return BLANK_START_PAGE.equals(startPage);
    }

    public void setZapStartPage() {
        setStartPage(ZAP_START_PAGE);
    }

    public void setBlankStartPage() {
        setStartPage(BLANK_START_PAGE);
    }

    public void setStartPage(URL url) {
        if (url == null) {
            setZapStartPage();
        } else {
            setStartPage(url.toString());
        }
    }

    private void setStartPage(String str) {
        this.startPage = str;
        getConfig().setProperty(PARAM_START_PAGE, str);
    }

    public String getDefaultBrowser() {
        return defaultBrowser;
    }

    public void setDefaultBrowser(String defaultBrowser) {
        this.defaultBrowser = defaultBrowser;
        getConfig().setProperty(PARAM_DEFAULT_BROWSER, defaultBrowser);
    }

}
