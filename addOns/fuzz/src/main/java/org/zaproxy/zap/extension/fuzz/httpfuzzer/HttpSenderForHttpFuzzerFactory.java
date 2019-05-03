/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer;

import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.DefaultHttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;

import java.io.IOException;

public class HttpSenderForHttpFuzzerFactory{

    public static HttpSender create(HttpFuzzerOptions httpFuzzerOptions){
        HttpSender httpSender = new HttpSender(
                Model.getSingleton().getOptionsParam().getConnectionParam(),
                true,
                HttpSender.FUZZER_INITIATOR);

        if (httpFuzzerOptions.isFollowRedirects()) {
            httpSender.setFollowRedirect(httpFuzzerOptions.isFollowRedirects());
            httpSender.setMaxRedirects(httpFuzzerOptions.getMaximumRedirects());
            httpSender.setAllowCircularRedirects(httpFuzzerOptions.isAllowCircularRedirects());
        }

        httpSender.setRemoveUserDefinedAuthHeaders(true);

        // Retries are handled by the fuzzer tasks.
        httpSender.setMaxRetriesOnIOError(0);
        return httpSender;
    }

    public static void sendAndReceive(HttpSender httpSender, HttpFuzzerOptions httpFuzzerOptions, HttpMessage httpMessage) throws IOException {
        if(httpFuzzerOptions.isFollowRedirects()){
            HttpRequestConfig config = HttpRequestConfig
                    .builder()
                    .setRedirectionValidator(DefaultHttpRedirectionValidator.INSTANCE)
                    .setFollowRedirects(true)
                    .build();
            httpSender.sendAndReceive(httpMessage, config);
        }else{
            httpSender.sendAndReceive(httpMessage);
        }
    }
}
