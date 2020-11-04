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

import java.util.Random;
import java.util.Set;
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

    private static final String alphabet =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private static final int RAND_STR_LEN = 8;

    private static Logger log = Logger.getLogger(SinkDetectionVerifyProbableSinks.class);

    @Override
    public int getId() {
        return 40037;
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
        Set<HttpMessage> possibleSinks = storage.getPossibleSinksForValue(value);

        try {
            HttpMessage inputMsg = msg.cloneRequest();
            String injectedValue = getRandomString();
            this.setParameter(inputMsg, param, injectedValue);
            sendAndReceive(inputMsg, false);

            for (HttpMessage possibleSink : possibleSinks) {
                // Reflections on the same request are not considered "stored sinks"
                if (inputMsg.hashCode() != possibleSink.hashCode()) {
                    HttpMessage possibleSinkClone = possibleSink.cloneRequest();
                    sendAndReceive(possibleSinkClone, false);
                    if (possibleSinkClone.getResponseBody().toString().contains(injectedValue)) {
                        // the sink source needs to be the original message otherwise path
                        // params will not be stored properly
                        ParamSinksUtils.setSinkForSource(msg, param, possibleSinkClone);
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
        Random rand = new Random();
        StringBuilder result = new StringBuilder(RAND_STR_LEN);
        for (int i = 0; i < RAND_STR_LEN; i++) {
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
