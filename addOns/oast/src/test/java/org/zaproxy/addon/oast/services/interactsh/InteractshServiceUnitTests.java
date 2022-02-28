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
package org.zaproxy.addon.oast.services.interactsh;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;

class InteractshServiceUnitTests extends TestUtils {

    private String serverUrl;

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        startServer();
        serverUrl = "http://localhost:" + nano.getListeningPort();
    }

    @AfterEach
    void teardown() throws Exception {
        stopServer();
    }

    @Test
    void shouldSendValidRegistrationRequest() throws Exception {
        // Given
        InteractshParam param = new InteractshParam(serverUrl, 60, "");
        InteractshService service = new InteractshService(param);
        StaticInteractshServerHandler handler = new StaticInteractshServerHandler("/register", "");
        nano.addHandler(handler);
        // When
        service.register();
        // Then
        JSONObject request = JSONObject.fromObject(handler.getRequestBody());
        assertThat(request.containsKey("public-key"), is(true));
        assertThat(request.containsKey("secret-key"), is(true));
        assertThat(request.containsKey("correlation-id"), is(true));
    }

    @Test
    void shouldIncrementStatPayloadsGeneratedCorrectly() throws Exception {
        // Given
        InteractshParam param = new InteractshParam(serverUrl, 60, "");
        InteractshService service = new InteractshService(param);
        StaticInteractshServerHandler handler = new StaticInteractshServerHandler("/register", "");
        nano.addHandler(handler);
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);
        // When
        service.getNewPayload();
        // Then
        assertThat(stats.getStat("stats.oast.interactsh.payloadsGenerated"), is(1L));
    }

    @Test
    void shouldSendValidDeregistrationRequest() throws Exception {
        // Given
        InteractshParam param = new InteractshParam(serverUrl, 60, "");
        InteractshService service = new InteractshService(param);
        StaticInteractshServerHandler handler =
                new StaticInteractshServerHandler("/deregister", "");
        nano.addHandler(handler);
        nano.addHandler(new StaticInteractshServerHandler("/register", ""));
        service.register();
        // When
        service.deregister();
        // Then
        JSONObject request = JSONObject.fromObject(handler.getRequestBody());
        assertThat(request.containsKey("correlation-id"), is(true));
    }

    @Test
    void shouldSendValidPollRequest() throws Exception {
        // Given
        InteractshParam param = new InteractshParam(serverUrl, 60, "");
        InteractshService service = new InteractshService(param);
        StaticInteractshServerHandler handler = new StaticInteractshServerHandler("/poll", "");
        nano.addHandler(handler);
        nano.addHandler(new StaticInteractshServerHandler("/register", ""));
        service.register();
        // When
        service.getInteractions();
        // Then
        Map<String, List<String>> queryParam = handler.getParameters();
        assertThat(queryParam.containsKey("id"), is(true));
        assertThat(queryParam.containsKey("secret"), is(true));
    }

    @Test
    void shouldDecryptPollingResponseCorrectly() throws Exception {
        // Given
        InteractshParam param = new InteractshParam(serverUrl, 60, "");
        InteractshService service = new InteractshService(param);
        List<InteractshEvent> interactions = setUpMockRegisterAndPollEndpoints(service);
        // When
        List<InteractshEvent> decryptedEvents = service.getInteractions();
        // Then
        assertThat(decryptedEvents.size(), is(1));
        assertThat(decryptedEvents.equals(interactions), is(true));
    }

    @Test
    void shouldIncrementStatInteractionsCorrectly() throws Exception {
        // Given
        InteractshParam param = new InteractshParam(serverUrl, 60, "");
        InteractshService service = new InteractshService(param);
        setUpMockRegisterAndPollEndpoints(service);
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);
        // When
        List<InteractshEvent> decryptedEvents = service.getInteractions();
        // Then
        assertThat(
                stats.getStat("stats.oast.interactsh.interactions"),
                is((long) decryptedEvents.size()));
    }

    private List<InteractshEvent> setUpMockRegisterAndPollEndpoints(InteractshService service)
            throws Exception {
        nano.addHandler(new StaticInteractshServerHandler("/register", ""));
        service.register(false);

        JSONObject eventJson = new JSONObject();
        eventJson.put("protocol", "http");
        eventJson.put("unique-id", "c4sr5v02eke4m3ndgl90crh5gooyyyyyy");
        eventJson.put("full-id", "c4sr5v02eke4m3ndgl90crh5gooyyyyyy");
        eventJson.put("raw-request", "GET " + serverUrl + "HTTP/1.1\r\n\r\n");
        eventJson.put(
                "raw-response",
                "HTTP/1.1 200 OK\r\n\r\n<html><head></head><body>yyyyyyoog5hrc09lgdn3m4eke20v5rs4c</body></html>");
        eventJson.put("remote-address", "192.0.2.0:12345");
        eventJson.put("timestamp", "2021-07-30T11:39:49.674610317Z");
        String event = eventJson.toString();

        // Generate AES key and encrypt event with it
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
        byte[] ivBytes = new byte[16];
        new SecureRandom().nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        Cipher eventEncryptor = Cipher.getInstance("AES/CFB/NoPadding");
        eventEncryptor.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedEvent = eventEncryptor.doFinal(event.getBytes());

        // Encrypt AES Key with service public key
        Cipher aesEncryptor = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        OAEPParameterSpec oaepParameterSpec =
                new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        aesEncryptor.init(Cipher.ENCRYPT_MODE, service.getRsaPublicKey(), oaepParameterSpec);
        byte[] aesKey = aesEncryptor.doFinal(key.getEncoded());

        // Prepend AES IV to encrypted event
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(ivBytes);
        outputStream.write(encryptedEvent);

        JSONObject pollResponseJson = new JSONObject();
        JSONArray data = new JSONArray();
        data.add(Base64.getEncoder().encodeToString(outputStream.toByteArray()));
        pollResponseJson.put("data", data);
        pollResponseJson.put("aes_key", Base64.getEncoder().encodeToString(aesKey));
        String pollResponse = pollResponseJson.toString();
        nano.addHandler(new StaticInteractshServerHandler("/poll", pollResponse));
        return Collections.singletonList(new InteractshEvent(eventJson));
    }

    private static class StaticInteractshServerHandler extends NanoServerHandler {
        private String request;
        private String response;
        private Map<String, List<String>> parameters;

        public StaticInteractshServerHandler(String path, String response) {
            super(path);
            this.response = response;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            request = getBody(session);
            parameters = session.getParameters();
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, NanoHTTPD.MIME_PLAINTEXT, response);
        }

        public String getRequestBody() {
            return request;
        }

        public Map<String, List<String>> getParameters() {
            return parameters;
        }
    }
}
