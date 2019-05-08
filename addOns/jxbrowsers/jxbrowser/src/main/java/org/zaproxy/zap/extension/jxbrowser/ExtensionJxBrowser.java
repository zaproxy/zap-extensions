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
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.jxbrowser;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;

import com.teamdev.jxbrowser.chromium.ProductInfo;

public class ExtensionJxBrowser extends ExtensionAdaptor {

    public static final String NAME = "ExtensionJxBrowser";

    public static final String RESOURCES = "/org/zaproxy/zap/extension/jxbrowser/resources";

    private static final Logger LOGGER = Logger.getLogger(ExtensionJxBrowser.class);

    /**
     * A minimal extension, just needed to load the messages correctly;)
     */
    public ExtensionJxBrowser() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();
        LOGGER.info("Using version " + ProductInfo.getVersion() + " of JxBrowser.");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }
}
