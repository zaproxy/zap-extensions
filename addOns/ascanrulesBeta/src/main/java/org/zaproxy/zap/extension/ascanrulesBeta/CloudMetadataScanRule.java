/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpVersion;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.methods.ByteArrayRequestEntity;
import org.apache.commons.httpclient.methods.EntityEnclosingMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpMethodHelper;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.SSLConnector;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.ZapGetMethod;
import org.zaproxy.zap.users.User;

/**
 * Attempts to retrieve cloud metadata by forging the host header and requesting a specific URL. See
 * https://www.nginx.com/blog/trust-no-one-perils-of-trusting-user-input/ for more details
 */
public class CloudMetadataScanRule extends AbstractHostPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.cloudmetadata.";

    private static final int PLUGIN_ID = 90034;
    private static final String METADATA_PATH = "/latest/meta-data/";
    private static final List<String> METADATA_HOSTS =
            Arrays.asList(
                    "169.154.169.254", "aws.zaproxy.org", "100.100.100.200", "alibaba.zaproxy.org");

    private static final Logger LOG = LogManager.getLogger(CloudMetadataScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    private static boolean useHttpSender;

    static {
        try {
            Class.forName("org.zaproxy.addon.network.internal.client.BaseHttpSender");
            useHttpSender = SSLConnector.class.getAnnotation(Deprecated.class) != null;
        } catch (Exception e) {
            useHttpSender = false;
        }
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
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
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public void raiseAlert(HttpMessage newRequest, String host) {
        newAlert()
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setAttack(host)
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "otherinfo"))
                .setMessage(newRequest)
                .raise();
    }

    @Override
    public void scan() {
        HttpMessage newRequest = getNewMsg();
        for (String host : METADATA_HOSTS) {
            try {
                newRequest.getRequestHeader().getURI().setPath(METADATA_PATH);
                this.sendMessageWithCustomHostHeader(newRequest, host);
                if (isSuccess(newRequest) && newRequest.getResponseBody().length() > 0) {
                    this.raiseAlert(newRequest, host);
                    return;
                }
            } catch (Exception e) {
                LOG.warn("Error sending URL {}", newRequest.getRequestHeader().getURI(), e);
            }
        }
    }

    void sendMessageWithCustomHostHeader(HttpMessage message, String host) throws IOException {
        if (useHttpSender) {
            message.setUserObject(Collections.singletonMap("host", host));
            sendAndReceive(message, false);
            return;
        }

        HttpMethodParams params = new HttpMethodParams();
        params.setVirtualHost(host);
        HttpMethod method =
                createRequestMethod(message.getRequestHeader(), message.getRequestBody(), params);
        if (!(method instanceof EntityEnclosingMethod) || method instanceof ZapGetMethod) {
            method.setFollowRedirects(false);
        }
        User forceUser = getParent().getHttpSender().getUser(message);
        message.setTimeSentMillis(System.currentTimeMillis());
        if (forceUser != null) {
            getParent()
                    .getHttpSender()
                    .executeMethod(method, forceUser.getCorrespondingHttpState());
        } else {
            getParent().getHttpSender().executeMethod(method, null);
        }
        message.setTimeElapsedMillis(
                (int) (System.currentTimeMillis() - message.getTimeSentMillis()));

        HttpMethodHelper.updateHttpRequestHeaderSent(message.getRequestHeader(), method);

        HttpResponseHeader resHeader = HttpMethodHelper.getHttpResponseHeader(method);
        resHeader.setHeader(HttpHeader.TRANSFER_ENCODING, null);
        message.setResponseHeader(resHeader);
        message.getResponseBody().setCharset(resHeader.getCharset());
        message.getResponseBody().setLength(0);
        message.getResponseBody().append(method.getResponseBody());
        message.setResponseFromTargetHost(true);
        getParent().notifyNewMessage(this, message);
    }

    private static HttpMethod createRequestMethod(
            HttpRequestHeader header, HttpBody body, HttpMethodParams params) throws URIException {
        HttpMethod httpMethod = new ZapGetMethod();
        httpMethod.setURI(header.getURI());
        httpMethod.setParams(params);
        params.setVersion(HttpVersion.HTTP_1_1);

        String msg = header.getHeadersAsString();

        String[] split = Pattern.compile("\\r\\n", Pattern.MULTILINE).split(msg);
        String token = null;
        String name = null;
        String value = null;

        int pos = 0;
        for (int i = 0; i < split.length; i++) {
            token = split[i];
            if (token.equals("")) {
                continue;
            }

            if ((pos = token.indexOf(":")) < 0) {
                continue;
            }
            name = token.substring(0, pos).trim();
            value = token.substring(pos + 1).trim();
            httpMethod.addRequestHeader(name, value);
        }
        if (body != null && body.length() > 0 && (httpMethod instanceof EntityEnclosingMethod)) {
            EntityEnclosingMethod post = (EntityEnclosingMethod) httpMethod;
            post.setRequestEntity(new ByteArrayRequestEntity(body.getBytes()));
        }
        httpMethod.setFollowRedirects(false);
        return httpMethod;
    }
}
