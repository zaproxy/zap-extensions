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
package org.zaproxy.addon.oast.boast;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;

public class BoastRegistrar {

    private static final Logger LOG = LogManager.getLogger(BoastRegistrar.class);

    BoastServer boastServer;
    HttpSender httpSender;

    public BoastRegistrar(BoastServer boastServer) {
        this.boastServer = boastServer;
        httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        HttpSender.MANUAL_REQUEST_INITIATOR);
    }

    public JSONObject register(String boastUri) throws Exception {
        URI uri = new URI(boastUri, true);
        HttpMessage msg = new HttpMessage(uri);
        String secret = "Secret " + generateSecret();
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, secret);
        httpSender.sendAndReceive(msg);
        // TODO: Add error checking here for illegal responses
        return JSONObject.fromObject(msg.getResponseBody().toString());
    }

    private String generateSecret() {
        Random random = ThreadLocalRandom.current();
        byte[] r = new byte[32];
        random.nextBytes(r);
        return Base64.encodeBase64String(r);
    }
}
