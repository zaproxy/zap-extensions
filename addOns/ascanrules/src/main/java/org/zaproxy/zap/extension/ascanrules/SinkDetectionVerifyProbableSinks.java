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
package org.zaproxy.zap.extension.ascanrules;

import static org.zaproxy.zap.extension.ascanrules.SinkDetectionCollectAndRefreshParamValues.SINK_DETECTION_STORAGE;

import java.util.List;
import java.util.Random;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ParamSinksUtils;

public class SinkDetectionVerifyProbableSinks extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.sinkdetectionverifyprobablesinks.";

    private static Logger log = Logger.getLogger(SinkDetectionVerifyProbableSinks.class);

    @Override
    public int getId() {
        return 40040;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "misc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String[] getDependency() {
        return new String[] {"SinkDetectionFindProbableSinks"};
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "misc");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "misc");
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        // TODO: should test only on POST/PUT ?
        SinkDetectionStorage storage = getStorage();
        List<HttpMessage> possibleSinks = storage.getPossibleSinksForValue(value);

        try {
            HttpMessage inputMsg = msg.cloneRequest();
            String injectedValue = getRandomString();
            this.setParameter(inputMsg, param, injectedValue);
            sendAndReceive(inputMsg, false);

            for (HttpMessage possibleSink : possibleSinks) {
                // Reflections on the same request are not considered "stored sinks"
                if (inputMsg.hashCode() != possibleSink.hashCode()) {
                    HttpMessage possibleSink1 = possibleSink.cloneRequest();
                    sendAndReceive(possibleSink1, false);
                    if (possibleSink1.getResponseBody().toString().contains(injectedValue)) {
                        // the sink source needs to be the original message otherwise path
                        // params will not be stored properly
                        ParamSinksUtils.setSinkForSource(msg, param, possibleSink1);
                    }
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    private SinkDetectionStorage getStorage() {
        SinkDetectionStorage storage;
        Object obj = getKb().get(SINK_DETECTION_STORAGE);
        if (obj instanceof SinkDetectionStorage) {
            storage = (SinkDetectionStorage) obj;
        } else {
            throw new IllegalStateException(
                    "The SINK_DETECTION_STORAGE Should have been initialized by the SinkDetectionCollectAndRefreshParamValues");
        }
        return storage;
    }

    private static String getRandomString() {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random rand = new Random();
        int length = 8;
        StringBuilder result = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            result.append(alphabet.charAt(rand.nextInt(alphabet.length())));
        }
        return result.toString();
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getCweId() {
        return 79;
    }

    @Override
    public int getWascId() {
        return 8;
    }
}
