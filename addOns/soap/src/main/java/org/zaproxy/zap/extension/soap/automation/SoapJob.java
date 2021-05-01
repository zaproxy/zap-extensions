/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap.automation;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.soap.ExtensionImportWSDL;

public class SoapJob extends AutomationJob {

    private static final String JOB_NAME = "soap";
    private static final String RESOURCES_DIR = "/org/zaproxy/zap/extension/soap/resources/";

    private static final String PARAM_WSDL_FILE = "wsdlFile";
    private static final String PARAM_WSDL_URL = "wsdlUrl";

    private ExtensionImportWSDL extSoap;

    private String wsdlFile;
    private String wsdlUrl;

    private ExtensionImportWSDL getExtSoap() {
        if (extSoap == null) {
            extSoap =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionImportWSDL.class);
        }
        return extSoap;
    }

    @Override
    public boolean applyCustomParameter(String name, String value) {
        switch (name) {
            case PARAM_WSDL_FILE:
                wsdlFile = value;
                return true;
            case PARAM_WSDL_URL:
                wsdlUrl = value;
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_WSDL_FILE, "");
        map.put(PARAM_WSDL_URL, "");
        return map;
    }

    @Override
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {

        if (wsdlFile != null && !wsdlFile.isEmpty()) {
            File file = new File(wsdlFile);
            if (!file.exists() || !file.canRead()) {
                progress.error(Constant.messages.getString("soap.automation.error.file", wsdlFile));
            } else {
                getExtSoap().syncImportWsdlFile(file);
            }
        }

        if (wsdlUrl != null && !wsdlUrl.isEmpty()) {
            try {
                new URI(wsdlUrl, true);
                getExtSoap().syncImportWsdlUrl(wsdlUrl);
            } catch (Exception e) {
                progress.error(Constant.messages.getString("soap.automation.error.url", wsdlUrl));
            }
        }
    }

    // For Unit Tests
    protected String getWsdlFile() {
        return wsdlFile;
    }

    // For Unit Tests
    protected String getWsdlUrl() {
        return wsdlUrl;
    }

    public String getTemplateDataMin() {
        return getResourceAsString(getName() + "-min.yaml");
    }

    public String getTemplateDataMax() {
        return getResourceAsString(getName() + "-max.yaml");
    }

    private String getResourceAsString(String name) {
        try (InputStream in = ExtensionImportWSDL.class.getResourceAsStream(RESOURCES_DIR + name)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.nofile", RESOURCES_DIR + name));
        }
        return "";
    }

    @Override
    public Order getOrder() {
        return Order.EXPLORE;
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Object getParamMethodObject() {
        return null;
    }

    @Override
    public String getParamMethodName() {
        return null;
    }
}
