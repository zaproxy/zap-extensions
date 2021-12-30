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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.oast.OastService;
import org.zaproxy.zap.network.HttpRequestBody;

public class InteractshService extends OastService implements OptionsChangedListener {

    // The Interactsh client methods in this class are based on the official Interactsh CLI client:
    // https://github.com/projectdiscovery/interactsh/blob/f5b53a7b8be329ee6d4936ed753e3c46472e5726/pkg/client/client.go

    private static final Logger LOGGER = LogManager.getLogger(InteractshService.class);

    private final ScheduledExecutorService executorService =
            Executors.newSingleThreadScheduledExecutor(
                    new OastThreadFactory("ZAP-OAST-Interactsh-"));
    private final UUID secretKey;
    private final String correlationId;
    private final HttpSender httpSender;
    private final InteractshParam param;

    private URI serverUrl;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private HttpMessage pollMsg;
    private boolean isRegistered;
    private int currentPollingFrequency;
    private ScheduledFuture<?> pollingSchedule;

    public InteractshService() {
        this(new InteractshParam());
    }

    InteractshService(InteractshParam param) {
        httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        HttpSender.MANUAL_REQUEST_INITIATOR);
        secretKey = UUID.randomUUID();
        correlationId = RandomStringUtils.randomAlphanumeric(20).toLowerCase(Locale.ROOT);
        this.param = param;
    }

    @Override
    public String getName() {
        return "Interactsh";
    }

    @Override
    public void startService() {
        LOGGER.debug("Starting Interactsh Service.");
        if (pollingSchedule == null || pollingSchedule.isDone()) {
            schedulePoller(param.getPollingFrequency());
        }
    }

    @Override
    public void stopService() {
        executorService.shutdown();
        deregister();
    }

    @Override
    public void sessionChanged() {
        if (isRegistered) {
            stopPoller();
            deregister();
        }
    }

    public void optionsLoaded() {
        currentPollingFrequency = param.getPollingFrequency();
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        if (currentPollingFrequency != param.getPollingFrequency()) {
            stopPoller();
            startService();
            currentPollingFrequency = param.getPollingFrequency();
            LOGGER.debug(
                    "Updated Interactsh Polling frequency to {} seconds.", currentPollingFrequency);
        }
    }

    public void register() throws InteractshException {
        try {
            if (isRegistered) {
                return;
            }
            serverUrl = new URI(param.getServerUrl(), true);
            KeyPair keyPair = generateRsaKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            PemObject pemObject = new PemObject("PUBLIC KEY", publicKey.getEncoded());
            ByteArrayOutputStream pubKeyByteStream = new ByteArrayOutputStream();
            PemWriter pemWriter = new PemWriter(new OutputStreamWriter(pubKeyByteStream));
            pemWriter.writeObject(pemObject);
            pemWriter.close();
            String pubKeyEncoded =
                    new String(Base64.getEncoder().encode(pubKeyByteStream.toByteArray()));

            JSONObject reqBodyJson = new JSONObject();
            reqBodyJson.put("public-key", pubKeyEncoded);
            reqBodyJson.put("secret-key", secretKey.toString());
            reqBodyJson.put("correlation-id", correlationId);
            HttpRequestBody reqBody = new HttpRequestBody(reqBodyJson.toString());

            URI registrationUri = (URI) serverUrl.clone();
            registrationUri.setPath("/register");
            HttpRequestHeader reqHeader =
                    createRequestHeader(registrationUri, reqBody.getBytes().length);
            HttpMessage reqMsg = new HttpMessage(reqHeader, reqBody);
            httpSender.sendAndReceive(reqMsg);
            if (reqMsg.getResponseHeader().getStatusCode() != 200) {
                LOGGER.warn(
                        "Error during interactsh register, due to bad HTTP code {}. Content: {}",
                        reqMsg.getResponseHeader().getStatusCode(),
                        reqMsg.getResponseBody());

                throw new InteractshException(
                        Constant.messages.getString(
                                "oast.interactsh.error.register",
                                Constant.messages.getString("oast.interactsh.error.badHttpCode")));
            }

            LOGGER.debug(
                    "Registered correlationId {}. StatusCode: {}, Content {}",
                    correlationId,
                    reqMsg.getResponseHeader().getStatusCode(),
                    reqMsg.getResponseBody());
            isRegistered = true;
            schedulePoller(0);
        } catch (IOException | CloneNotSupportedException | NoSuchAlgorithmException e) {
            LOGGER.error("Error during interactsh register: {}", e.getMessage(), e);
            throw new InteractshException(
                    Constant.messages.getString(
                            "oast.interactsh.error.register", e.getLocalizedMessage()));
        }
    }

    private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();
        LOGGER.debug("OAST Interactsh: RSA key pair generated.");
        return keyPair;
    }

    // For unit tests
    PublicKey getRsaPublicKey() {
        return publicKey;
    }

    public void deregister() {
        try {
            if (!isRegistered) {
                return;
            }
            URI deregistrationUri = (URI) serverUrl.clone();
            deregistrationUri.setPath("/deregister");
            JSONObject reqBodyJson = new JSONObject();
            reqBodyJson.put("correlation-id", correlationId);
            reqBodyJson.put("secret-key", secretKey.toString());
            HttpRequestBody reqBody = new HttpRequestBody(reqBodyJson.toString());
            HttpRequestHeader reqHeader =
                    createRequestHeader(deregistrationUri, reqBody.getBytes().length);
            HttpMessage deregisterMsg = new HttpMessage(reqHeader, reqBody);
            httpSender.sendAndReceive(deregisterMsg);
            if (deregisterMsg.getResponseHeader().getStatusCode() != 200) {
                LOGGER.warn(
                        "Error during interactsh deregister, due to bad HTTP code {}. Content: {}",
                        deregisterMsg.getResponseHeader().getStatusCode(),
                        deregisterMsg.getResponseBody());
                return;
            }
            LOGGER.debug("Deregistered correlationId: {}", correlationId);
            isRegistered = false;
        } catch (Exception e) {
            LOGGER.error("Error during interactsh deregister: {}", e.getMessage(), e);
        }
    }

    private HttpRequestHeader createRequestHeader(URI uri, int contentLength)
            throws HttpMalformedHeaderException {
        HttpRequestHeader reqHeader =
                new HttpRequestHeader(HttpRequestHeader.POST, uri, HttpHeader.HTTP11);
        reqHeader.setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        reqHeader.setHeader(HttpHeader.CONTENT_LENGTH, String.valueOf(contentLength));
        if (!param.getAuthToken().isEmpty()) {
            reqHeader.setHeader(HttpHeader.AUTHORIZATION, param.getAuthToken());
        }
        return reqHeader;
    }

    @Override
    public String getNewPayload() throws URIException, InteractshException {
        if (!isRegistered) {
            register();
        }
        return correlationId
                + RandomStringUtils.randomAlphanumeric(13).toLowerCase(Locale.ROOT)
                + '.'
                + serverUrl.getHost();
    }

    @Override
    public void poll() {
        stopPoller();
        schedulePoller(0);
    }

    private void stopPoller() {
        if (pollingSchedule != null) {
            pollingSchedule.cancel(false);
        }
    }

    private void schedulePoller(int initialDelay) {
        if (!isRegistered) {
            return;
        }
        LOGGER.debug("Start Polling the Interactsh Server ...");
        pollingSchedule =
                executorService.scheduleAtFixedRate(
                        new InteractshPoller(this),
                        initialDelay,
                        param.getPollingFrequency(),
                        TimeUnit.SECONDS);
    }

    /** @return new interactions from the server. */
    public List<InteractshEvent> getInteractions() {
        try {
            if (!isRegistered) {
                LOGGER.warn(Constant.messages.getString("oast.interactsh.error.poll.unregistered"));
                return new ArrayList<>();
            }
            if (pollMsg == null) {
                URI pollUri = (URI) serverUrl.clone();
                pollUri.setPath("/poll");
                pollUri.setQuery("id=" + correlationId + "&secret=" + secretKey.toString());
                HttpRequestHeader reqHeader =
                        new HttpRequestHeader(HttpRequestHeader.GET, pollUri, HttpHeader.HTTP11);
                if (!param.getAuthToken().isEmpty()) {
                    reqHeader.setHeader(HttpHeader.AUTHORIZATION, param.getAuthToken());
                }
                pollMsg = new HttpMessage(reqHeader);
            }
            httpSender.sendAndReceive(pollMsg);
            if (pollMsg.getResponseHeader().getStatusCode() != 200) {
                LOGGER.warn(
                        "Error during interactsh poll, due to bad HTTP code {}. Content: {}",
                        pollMsg.getResponseHeader().getStatusCode(),
                        pollMsg.getResponseBody());
                return new ArrayList<>();
            }

            JSONObject response = JSONObject.fromObject(pollMsg.getResponseBody().toString());
            if (!response.containsKey("data") || !response.containsKey("aes_key")) {
                LOGGER.warn(
                        "Bad polling response received from interactsh server. Missing data or aes_key element. HTTP code {}. Content: {}",
                        pollMsg.getResponseHeader().getStatusCode(),
                        pollMsg.getResponseBody());
                return new ArrayList<>();
            }
            String aesKey = response.getString("aes_key");
            JSONArray interactions = response.getJSONArray("data");
            LOGGER.debug(
                    "Polled {} interactions for correlationId: {}",
                    interactions.size(),
                    correlationId);

            List<InteractshEvent> result = new ArrayList<>();
            for (int i = 0; i < interactions.size(); ++i) {
                String interaction = interactions.getString(i);
                result.add(
                        new InteractshEvent(
                                JSONObject.fromObject(
                                        new String(decryptMessage(aesKey, interaction)))));
            }
            if (LOGGER.isDebugEnabled()) {
                for (InteractshEvent event : result) {
                    LOGGER.debug(
                            "Returned interaction for correlationId: {}. Time: {}, Protocol:{}, UniqueId:{}, RemoteAddress:{}",
                            correlationId,
                            event.getTimestamp(),
                            event.getProtocol(),
                            event.getUniqueId(),
                            event.getRemoteAddress());
                }
            }
            return result;
        } catch (Exception e) {
            LOGGER.error("Error during interactsh poll: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }

    /** Decrypts an AES-256-RSA-OAEP encrypted message to string */
    private byte[] decryptMessage(String encodedEncryptedKey, String encodedEncryptedMsg) {
        try {
            byte[] decodedEncryptedKey = Base64.getDecoder().decode(encodedEncryptedKey);
            Cipher decryptionCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            OAEPParameterSpec oaepParameterSpec =
                    new OAEPParameterSpec(
                            "SHA-256",
                            "MGF1",
                            MGF1ParameterSpec.SHA256,
                            PSource.PSpecified.DEFAULT);
            decryptionCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
            byte[] decodedDecryptedKey = decryptionCipher.doFinal(decodedEncryptedKey);

            byte[] decodedEncryptedMsg = Base64.getDecoder().decode(encodedEncryptedMsg);
            decryptionCipher = Cipher.getInstance("AES/CFB/NoPadding");
            SecretKey aesKey = new SecretKeySpec(decodedDecryptedKey, "AES");
            IvParameterSpec iv =
                    new IvParameterSpec(
                            Arrays.copyOf(decodedEncryptedMsg, decryptionCipher.getBlockSize()));
            decryptionCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            return decryptionCipher.doFinal(
                    Arrays.copyOfRange(
                            decodedEncryptedMsg,
                            decryptionCipher.getBlockSize(),
                            decodedEncryptedMsg.length));
        } catch (Exception e) {
            LOGGER.warn(
                    "Could not decrypt Interactsh interactions: {}", e.getLocalizedMessage(), e);
            return new byte[0];
        }
    }

    public InteractshParam getParam() {
        return param;
    }

    @Override
    public boolean isRegistered() {
        return isRegistered;
    }
}
