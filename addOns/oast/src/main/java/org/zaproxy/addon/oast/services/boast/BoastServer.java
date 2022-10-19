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
package org.zaproxy.addon.oast.services.boast;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.utils.Stats;

public class BoastServer {

    private static final Logger LOGGER = LogManager.getLogger(BoastServer.class);

    private final URI uri;
    private final String id;
    private final String canary;
    private final HttpMessage boastMsg;
    private final HttpSender httpSender;
    private final List<String> eventIds = new ArrayList<>();

    public BoastServer(String uriString) throws IOException {
        httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        // TODO: Replace on next ZAP release with HttpSender.OAST_INITIATOR
                        ExtensionOast.HTTP_SENDER_OAST_INITIATOR);

        uri = new URI(uriString, true);
        boastMsg = new HttpMessage(uri);
        boastMsg.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, generateBoastSecret());
        httpSender.sendAndReceive(boastMsg);
        JSONObject result = JSONObject.fromObject(boastMsg.getResponseBody().toString());
        id = result.getString("id");
        canary = result.getString("canary");
        Stats.incCounter("stats.oast.boast.payloadsGenerated");
    }

    /** @return new BOAST events found on polling */
    public List<BoastEvent> poll() {
        try {
            httpSender.sendAndReceive(boastMsg);
            JSONObject pollResponse = JSONObject.fromObject(boastMsg.getResponseBody().toString());
            JSONArray events = pollResponse.getJSONArray("events");
            List<BoastEvent> newBoastEvents = new ArrayList<>();
            for (int i = 0; i < events.size(); ++i) {
                JSONObject event = events.getJSONObject(i);
                if (!eventIds.contains(event.getString("id"))) {
                    newBoastEvents.add(new BoastEvent(event));
                    eventIds.add(event.getString("id"));
                }
            }
            Stats.incCounter("stats.oast.boast.interactions", newBoastEvents.size());
            return newBoastEvents;
        } catch (IOException e) {
            LOGGER.warn(
                    Constant.messages.getString(
                            "oast.boast.error.poll", uri, e.getLocalizedMessage()),
                    e);
            return Collections.emptyList();
        }
    }

    public URI getUri() {
        return uri;
    }

    public String getPayload() {
        try {
            return id + "." + uri.getHost();
        } catch (URIException e) {
            LOGGER.warn(
                    Constant.messages.getString(
                            "oast.boast.error.payload", e.getLocalizedMessage()));
            return "";
        }
    }

    public String getId() {
        return id;
    }

    public String getCanary() {
        return canary;
    }

    private String generateBoastSecret() {
        Random random = ThreadLocalRandom.current();
        byte[] r = new byte[32];
        random.nextBytes(r);
        return "Secret " + Base64.encodeBase64String(r);
    }
}
