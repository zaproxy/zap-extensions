/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.testutils;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.List;

import net.htmlparser.jericho.Source;

import org.junit.Before;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Class with utility/helper methods for passive scanner tests ({@link org.zaproxy.zap.extension.pscan.PluginPassiveScanner
 * PluginPassiveScanner}).
 * 
 * @param <T> the type of the passive scanner.
 */
public abstract class PassiveScannerTestUtils<T extends PassiveScanner> extends TestUtils {

    protected T rule;
    protected PassiveScanThread parent;
    protected List<Alert> alertsRaised;

    public PassiveScannerTestUtils() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        setUpZap();

        alertsRaised = new ArrayList<>();
        parent = new PassiveScanThread(null, null, new ExtensionAlert(), null) {
            @Override
            public void raiseAlert(int id, Alert alert) {
                defaultAssertions(alert);
                alertsRaised.add(alert);
            }
        };
        rule = createScanner();
        rule.setParent(parent);
    }

    protected void defaultAssertions(Alert alert) {
        if (rule instanceof PluginPassiveScanner) {
            PluginPassiveScanner pps = (PluginPassiveScanner) rule;
            assertThat(alert.getPluginId(), is(equalTo(pps.getPluginId())));
        }
        assertThat(alert.getAttack(), isEmptyOrNullString());
    }

    protected abstract T createScanner();
    
    protected Source createSource(HttpMessage msg) {
        return new Source(msg.getResponseBody().toString());
    }

}