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
import org.apache.commons.text.similarity.LevenshteinDistance;
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

/**
 * Active scan rule which attempts Web Cache Deception attack.
 *
 * @author Nikhil (@bettercalln1ck)
 */
public class WebCacheDeceptionScanRule extends AbstractAppPlugin {

    private static final int LEVENSHTEIN_THRESHOLD = 200;

    private static final String MESSAGE_PREFIX = "ascanalpha.webCacheDeception.";
    private static final Logger LOG = LogManager.getLogger(WebCacheDeceptionScanRule.class);

    protected static final String[] TEST_EXTENSIONS = {
        "css", "jpg", "js", "html", "gif", "png", "svg", "php", "txt", "pdf", "asp"
    };

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

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
        if (initialTest()) {
            HttpMessage authorisedMessage = getNewMsg();
            try {
                sendAndReceive(authorisedMessage);
                URI uri = authorisedMessage.getRequestHeader().getURI();
                ArrayList<String> extensions = new ArrayList<>();
                String path = uri.getPath();
                // checks whether the page with appended path gets cached or not
                for (String ext : TEST_EXTENSIONS) {
                    String newPath = path + "/test." + ext;
                    uri.setPath(newPath);
                    authorisedMessage.getRequestHeader().setURI(uri);
                    sendAndReceive(authorisedMessage);
                    String cachedResponse = authorisedMessage.getResponseBody().toString();
                    String unauthorisedCachedResponse =
                            makeUnauthorisedRequest(
                                    uri, authorisedMessage.getRequestHeader().getMethod());

                    if (checkSimilarity(unauthorisedCachedResponse, cachedResponse)) {
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

    private boolean checkSimilarity(String a, String b) {
        LevenshteinDistance distance = new LevenshteinDistance();
        int levenshteinDistance = distance.apply(a, b);
        // if response length is less than threshold
        if (b.length() <= LEVENSHTEIN_THRESHOLD) {
            return levenshteinDistance < (int) (b.length() * 0.90);
        } else {
            return levenshteinDistance < LEVENSHTEIN_THRESHOLD;
        }
    }

    private String makeUnauthorisedRequest(URI uri, String method) throws IOException {

        HttpMessage unauthorisedMessage = new HttpMessage(uri);
        unauthorisedMessage.getRequestHeader().setMethod(method);
        HttpSender sender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(), false, 1);
        sender.sendAndReceive(unauthorisedMessage);
        return unauthorisedMessage.getResponseBody().toString();
    }

    private boolean initialTest() {
        HttpMessage authorisedMessage = getNewMsg();
        try {
            sendAndReceive(authorisedMessage);
            URI uri = authorisedMessage.getRequestHeader().getURI();
            String authorisedResponse = authorisedMessage.getResponseBody().toString();
            String unauthorisedResponse =
                    makeUnauthorisedRequest(uri, authorisedMessage.getRequestHeader().getMethod());
            // check whether authorised and unauthorised message are similar
            if (checkSimilarity(unauthorisedResponse, authorisedResponse)) {
                return false;
            }
            String path = uri.getPath();
            String newPath = path + "/test";
            uri.setPath(newPath);
            authorisedMessage.getRequestHeader().setURI(uri);
            sendAndReceive(authorisedMessage);
            String pathAppendedResponse = authorisedMessage.getResponseBody().toString();
            // check whether adding path to uri gives same response
            if (!checkSimilarity(pathAppendedResponse, authorisedResponse)) {
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
