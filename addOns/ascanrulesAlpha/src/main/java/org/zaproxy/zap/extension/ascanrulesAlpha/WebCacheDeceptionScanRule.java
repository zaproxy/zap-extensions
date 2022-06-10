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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.ComparableResponse;

/**
 * Active scan rule which attempts Web Cache Deception attack.
 *
 * @author Nikhil (@bettercalln1ck)
 */
public class WebCacheDeceptionScanRule extends AbstractAppPlugin {

    private static final String MESSAGE_PREFIX = "ascanalpha.webCacheDeception.";
    private static final Logger LOG = LogManager.getLogger(WebCacheDeceptionScanRule.class);

    protected static final String[] TEST_EXTENSIONS = {
        "css", "jpg", "js", "html", "gif", "png", "svg", "php", "txt", "pdf", "asp"
    };
    private static final float SIMILARITY_THRESHOLD = 0.80f;
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS);

    @Override
    public int getId() {
        return 40039;
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
        if (!isSuccess(getBaseMsg())) {
            return;
        }
        if (initialTest()) {
            HttpMessage authorisedMessage = getNewMsg();
            try {
                sendAndReceive(authorisedMessage);
                URI uri = authorisedMessage.getRequestHeader().getURI();
                ArrayList<String> extensions = new ArrayList<>();
                String path = uri.getPath();
                String basePath = getBasePath(path);
                // checks whether the page with appended path gets cached or not
                for (String ext : TEST_EXTENSIONS) {
                    String newPath = basePath + "/test." + ext;
                    uri.setPath(newPath);
                    authorisedMessage.getRequestHeader().setURI(uri);
                    sendAndReceive(authorisedMessage);
                    ComparableResponse authCompResp =
                            new ComparableResponse(authorisedMessage, null);
                    HttpMessage unauthorisedCachedResponse =
                            makeUnauthorisedRequest(
                                    uri, authorisedMessage.getRequestHeader().getMethod());
                    ComparableResponse unAuthCompResp =
                            new ComparableResponse(unauthorisedCachedResponse, null);
                    if (authCompResp.compareWith(unAuthCompResp) >= SIMILARITY_THRESHOLD) {
                        extensions.add(ext);
                    }
                }
                uri.setPath(path);
                authorisedMessage.getRequestHeader().setURI(uri);
                sendAndReceive(authorisedMessage);
                if (!extensions.isEmpty()) {
                    StringBuilder attack = new StringBuilder();
                    for (String ext : extensions) {
                        attack.append("/test.").append(ext).append(",");
                    }
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setMessage(authorisedMessage)
                            .setOtherInfo(
                                    Constant.messages.getString(
                                            "ascanalpha.webCacheDeception.otherinfo"))
                            .setAttack(attack.toString())
                            .raise();
                }
            } catch (IOException e) {
                LOG.warn(e.getMessage(), e);
            }
        }
    }

    private static String getBasePath(String path) throws URIException {
        if (path != null && !"/".equals(path)) {
            return path;
        }
        return "";
    }

    private HttpMessage makeUnauthorisedRequest(URI uri, String method) throws IOException {

        HttpMessage unauthorisedMessage = new HttpMessage(uri);
        unauthorisedMessage.getRequestHeader().setMethod(method);
        HttpSender sender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(), false, 1);
        sender.sendAndReceive(unauthorisedMessage);
        return unauthorisedMessage;
    }

    private boolean initialTest() {
        HttpMessage authorisedMessage = getNewMsg();
        try {
            sendAndReceive(authorisedMessage);
            URI uri = authorisedMessage.getRequestHeader().getURI();
            ComparableResponse authCompResp = new ComparableResponse(authorisedMessage, null);
            HttpMessage unauthorisedCachedResponse =
                    makeUnauthorisedRequest(uri, authorisedMessage.getRequestHeader().getMethod());
            ComparableResponse unAuthCompResp =
                    new ComparableResponse(unauthorisedCachedResponse, null);
            // check whether authorised and unauthorised message are similar
            if (authCompResp.compareWith(unAuthCompResp) >= SIMILARITY_THRESHOLD) {
                return false;
            }
            String path = uri.getPath();
            String newPath = getBasePath(path) + "/test";
            uri.setPath(newPath);
            authorisedMessage.getRequestHeader().setURI(uri);
            sendAndReceive(authorisedMessage);
            ComparableResponse pathAppendedCompResp =
                    new ComparableResponse(authorisedMessage, null);
            if (authCompResp.compareWith(pathAppendedCompResp) < SIMILARITY_THRESHOLD) {
                return false;
            }

        } catch (IOException e) {
            LOG.warn(e.getMessage(), e);
        }
        return true;
    }

    @Override
    public int getCategory() {
        return Category.MISC;
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
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
