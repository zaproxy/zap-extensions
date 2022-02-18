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

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;

class BoastServerUnitTests extends TestUtils {

    private String boastUrl;

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        startServer();
        boastUrl = "http://localhost:" + nano.getListeningPort() + "/events";
    }

    @AfterEach
    void teardown() throws Exception {
        stopServer();
    }

    @Test
    void shouldRegisterSuccessfullyOnInstantiation() throws Exception {
        // Given
        StaticBoastServerHandler handler = new StaticBoastServerHandler();
        nano.addHandler(handler);

        // When
        BoastServer boastServer = new BoastServer(boastUrl);

        // Then
        assertThat(boastServer.getId(), is(handler.id));
        assertThat(boastServer.getCanary(), is(handler.canary));
    }

    @Test
    void shouldIncrementStatPayloadsGeneratedCorrectly() throws Exception {
        // Given
        StaticBoastServerHandler handler = new StaticBoastServerHandler();
        nano.addHandler(handler);
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);
        // When
        new BoastServer(boastUrl);
        // Then
        assertThat(stats.getStat("stats.oast.boast.payloadsGenerated"), is(1L));
    }

    @Test
    void shouldReturnBoastEventsOnPolling() throws Exception {
        // Given
        StaticBoastServerHandler handler = new StaticBoastServerHandler();
        nano.addHandler(handler);
        BoastServer boastServer = new BoastServer(boastUrl);
        JSONArray expectedEventsJsonArray =
                JSONObject.fromObject(handler.firstPollResponse).getJSONArray("events");
        List<BoastEvent> expectedEvents = new ArrayList<>();
        for (int i = 0; i < expectedEventsJsonArray.size(); ++i) {
            expectedEvents.add(new BoastEvent(expectedEventsJsonArray.getJSONObject(i)));
        }

        // When
        List<BoastEvent> events = boastServer.poll();

        // Then
        assertThat(events, is(expectedEvents));
    }

    @Test
    void shouldIncrementStatInteractionsCorrectly() throws Exception {
        // Given
        StaticBoastServerHandler handler = new StaticBoastServerHandler();
        nano.addHandler(handler);
        BoastServer boastServer = new BoastServer(boastUrl);
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);
        // When
        List<BoastEvent> events = boastServer.poll();
        // Then
        assertThat(stats.getStat("stats.oast.boast.interactions"), is((long) events.size()));
    }

    @Test
    void shouldReturnNewBoastEventsOnPollingMultipleTimes() throws Exception {
        // Given
        StaticBoastServerHandler handler = new StaticBoastServerHandler();
        nano.addHandler(handler);
        BoastServer boastServer = new BoastServer(boastUrl);
        JSONArray expectedEventsJsonArray =
                JSONObject.fromObject(handler.secondPollResponse).getJSONArray("events");
        List<BoastEvent> expectedEvents = new ArrayList<>();
        for (int i = 0; i < expectedEventsJsonArray.size(); ++i) {
            expectedEvents.add(new BoastEvent(expectedEventsJsonArray.getJSONObject(i)));
        }

        // When
        List<BoastEvent> events = boastServer.poll();
        events.addAll(boastServer.poll());

        // Then
        assertThat(events, is(expectedEvents));
    }

    static class StaticBoastServerHandler extends NanoServerHandler {
        private int pollCount = 0;
        private final String id = "cxcjyaf5wahkidrp2zvhxe6ola";
        private final String canary = "x7ilthx62hx2kfyvsioydd43da";
        private final String registrationResponse =
                "{\"id\":\"cxcjyaf5wahkidrp2zvhxe6ola\",\"canary\":\"x7ilthx62hx2kfyvsioydd43da\",\"events\":[]}";
        private final String firstPollResponse =
                "{\"id\":\"cxcjyaf5wahkidrp2zvhxe6ola\",\"canary\":\"x7ilthx62hx2kfyvsioydd43da\",\"events\":[{\"id\":\"fbb6osymic6llzuiw7f7ylwix4\",\"time\":\"2020-09-16T16:31:05.183124969+01:00\",\"testID\":\"cxcjyaf5wahkidrp2zvhxe6ola\",\"receiver\":\"HTTP\",\"remoteAddress\":\"192.0.2.1:57770\",\"dump\":\"GET /cxcjyaf5wahkidrp2zvhxe6ola HTTP/1.1\\r\\nHost: localhost:8080\\r\\nUser-Agent: ZAP\\r\\n\\r\\n\"}]}";
        private final String secondPollResponse =
                "{\"id\":\"cxcjyaf5wahkidrp2zvhxe6ola\",\"canary\":\"x7ilthx62hx2kfyvsioydd43da\",\"events\":[{\"id\":\"fbb6osymic6llzuiw7f7ylwix4\",\"time\":\"2020-09-16T16:31:05.183124969+01:00\",\"testID\":\"cxcjyaf5wahkidrp2zvhxe6ola\",\"receiver\":\"HTTP\",\"remoteAddress\":\"192.0.2.1:57770\",\"dump\":\"GET /cxcjyaf5wahkidrp2zvhxe6ola HTTP/1.1\\r\\nHost: localhost:8080\\r\\nUser-Agent: ZAP\\r\\n\\r\\n\"},{\"id\":\"abc6jklic6llzapw7f7ylzap4\",\"time\":\"2020-09-16T16:35:05.183124969+01:00\",\"testID\":\"cxcjyaf5wahkidrp2zvhxe6ola\",\"receiver\":\"HTTPS\",\"remoteAddress\":\"192.0.2.5:57723\",\"dump\":\"GET /cxcjyaf5wahkidrp2zvhxe6ola HTTP/1.1\\r\\nHost: localhost:8080\\r\\n\"}]}";

        public StaticBoastServerHandler() {
            super("/events");
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            ++pollCount;
            if (pollCount == 1) {
                return newFixedLengthResponse(registrationResponse);
            } else if (pollCount == 2) {
                return newFixedLengthResponse(firstPollResponse);
            } else {
                return newFixedLengthResponse(secondPollResponse);
            }
        }
    }
}
