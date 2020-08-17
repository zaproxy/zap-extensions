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

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.zaproxy.zap.extension.ascanrules.SinkDetectionCollectAndRefreshParamValues.SINK_DETECTION_STORAGE;

import fi.iki.elonen.NanoHTTPD;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Kb;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ParamSinksUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

public abstract class SinkDetectionUnitTest<T extends AbstractAppPlugin>
        extends ActiveScannerAppTest<T> {

    public static final String baseHtmlResponse = "<!DOCTYPE html><html><body>OK</body></html>";

    SinkDetectionStorage storage = null;

    @BeforeEach
    protected void initiateStorage() {
        storage = new SinkDetectionStorage();
        kb = new Kb();
        kb.add(SINK_DETECTION_STORAGE, storage);
        ParamSinksUtils.reset();
        ParamSinksUtils.setMessagesStorage(new MockMessageStorage());
    }

    class SinkLocationHandler extends NanoServerHandler {
        private String[] storedValue;

        public SinkLocationHandler(String name, String[] storedValue) {
            super(name);
            this.storedValue = storedValue;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            String response = baseHtmlResponse.replace("OK", storedValue[0]);
            return newFixedLengthResponse(response);
        }
    }

    class HandlerStoresQueryParamXxxx extends NanoServerHandler {
        private String[] storedValue;

        public HandlerStoresQueryParamXxxx(String name, String[] storedValue) {
            super(name);
            this.storedValue = storedValue;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            String name = getFirstParamValue(session, "xxxx");
            if (name != null) {
                storedValue[0] = name;
            }
            return newFixedLengthResponse(baseHtmlResponse);
        }
    }

    class HandlerStoresPathParam extends NanoServerHandler {
        private String[] storedValue;

        public HandlerStoresPathParam(String name, String[] storedValue) {
            super(name);
            this.storedValue = storedValue;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            String uri = session.getUri();
            Pattern p = Pattern.compile("/sinksDetectionSavePathParameterInput/([^/]+)/name");
            Matcher m = p.matcher(uri);
            if (m.find()) {
                String name = m.group(1);
                if (name != null) {
                    this.storedValue[0] = name;
                }
            }
            return newFixedLengthResponse(baseHtmlResponse);
        }
    }

    class HandlerStoresPostParamXxxx extends NanoServerHandler {
        private String[] storedValue;

        public HandlerStoresPostParamXxxx(String name, String[] storedValue) {
            super(name);
            this.storedValue = storedValue;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            if (session.getMethod() == NanoHTTPD.Method.POST) {
                Map<String, String> formParams = new HashMap<String, String>();
                try {
                    session.parseBody(formParams);
                } catch (IOException e1) {
                    e1.printStackTrace();
                } catch (NanoHTTPD.ResponseException e1) {
                    e1.printStackTrace();
                }
                String name = getFirstParamValue(session, "xxxx");
                if (name != null) {
                    this.storedValue[0] = name;
                }
            }
            return newFixedLengthResponse(baseHtmlResponse);
        }
    }

    class MockMessageStorage implements ParamSinksUtils.MessagesStorage {

        Map<Integer, HttpMessage> messages = new HashMap<>();

        @Override
        public int storeMessage(HttpMessage msg) {
            int id = (int) Math.random();
            messages.put(id, msg);
            return id;
        }

        @Override
        public HttpMessage getMessage(int id) {
            return messages.get(id);
        }
    }
}
