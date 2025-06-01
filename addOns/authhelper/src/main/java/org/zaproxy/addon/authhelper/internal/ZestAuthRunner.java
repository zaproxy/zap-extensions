/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.zap.users.User;
import org.zaproxy.zest.core.v1.ZestActionFailException;
import org.zaproxy.zest.core.v1.ZestAssertFailException;
import org.zaproxy.zest.core.v1.ZestAssignFailException;
import org.zaproxy.zest.core.v1.ZestClient;
import org.zaproxy.zest.core.v1.ZestClientElementSendKeys;
import org.zaproxy.zest.core.v1.ZestClientFailException;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestInvalidCommonTestException;
import org.zaproxy.zest.core.v1.ZestResponse;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;
import org.zaproxy.zest.impl.ZestBasicRunner;

public class ZestAuthRunner extends ZestBasicRunner {

    private static final Logger LOGGER = LogManager.getLogger(ZestAuthRunner.class);

    private static final String TOTP_VAR_NAME = "TOTP";

    private WebDriver webDriver;

    private String totpVar;
    private User user;

    public ZestAuthRunner() {
        super();
    }

    public void setWebDriver(WebDriver webDriver) {
        this.webDriver = webDriver;
    }

    public void setup(User user, ZestScript script) {
        this.user = user;
        totpVar =
                script.getParameters().getTokenStart()
                        + TOTP_VAR_NAME
                        + script.getParameters().getTokenEnd();
    }

    @Override
    public String handleClient(ZestScript script, ZestClient client)
            throws ZestClientFailException {
        LOGGER.debug("handleClient {}", client.getClass().getCanonicalName());

        if (client instanceof ZestClientLaunch clientLaunch) {
            this.addWebDriver(clientLaunch.getWindowHandle(), webDriver);
            LOGGER.debug(
                    "handleClient client launch, registering {}", clientLaunch.getWindowHandle());
            this.webDriver.get(clientLaunch.getUrl());
            return clientLaunch.getWindowHandle();
        } else if (client instanceof ZestClientWindowClose) {
            // We don't want to close the window as the browser lifecycle is managed externally
            return null;
        }
        return super.handleClient(script, client);
    }

    @Override
    public ZestResponse runStatement(
            ZestScript script, ZestStatement stmt, ZestResponse lastResponse)
            throws ZestAssertFailException,
                    ZestActionFailException,
                    ZestInvalidCommonTestException,
                    IOException,
                    ZestAssignFailException,
                    ZestClientFailException {
        if (stmt instanceof ZestClientElementSendKeys sendKeys
                && totpVar.equals(sendKeys.getValue())) {
            String code = TotpSupport.getCode(user.getAuthenticationCredentials());
            setVariable(TOTP_VAR_NAME, code);
        }
        return super.runStatement(script, stmt, lastResponse);
    }
}
