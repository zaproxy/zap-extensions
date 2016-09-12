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
package org.zaproxy.zap.extension.pscanrules;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;

import net.htmlparser.jericho.Source;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.mockito.Mockito;

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.anyVararg;
import static org.mockito.Mockito.when;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.I18N;

@RunWith(MockitoJUnitRunner.class)
public abstract class PassiveScannerTest {

    protected PluginPassiveScanner rule;
    protected PassiveScanThread parent;
    protected List<Alert> alertsRaised;

    @BeforeClass
    public static void beforeClass() {
        Constant.messages = Mockito.mock(I18N.class);

        final ResourceBundle msg = getExtensionResourceBundle(new ExtensionPscanRules());
        when(Constant.messages.getString(anyString())).thenAnswer(new Answer<String>() {

            @Override
            public String answer(InvocationOnMock invocation) {
                return msg.getString((String) invocation.getArguments()[0]);
            }
        });

        when(Constant.messages.getString(anyString(), anyVararg())).thenAnswer(new Answer<String>() {

            @Override
            public String answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                return MessageFormat.format(msg.getString((String) args[0]), Arrays.copyOfRange(args, 1, args.length));
            }
        });
    }

    public PassiveScannerTest() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        alertsRaised = new ArrayList<>();
        parent = new PassiveScanThread(null, null, new ExtensionAlert()) {
            @Override
            public void raiseAlert(int arg0, Alert arg1) {
                alertsRaised.add(arg1);
            }
        };
        rule = createScanner();
        rule.setParent(parent);
    }

    protected abstract PluginPassiveScanner createScanner();
    
    protected Source createSource(HttpMessage msg) {
        return new Source(msg.getResponseHeader().toString() + msg.getResponseBody().toString());
    }

    protected static Matcher<Alert> hasNameLoadedWithKey(final String key) {
        return new BaseMatcher<Alert>() {

            @Override
            public boolean matches(Object actualValue) {
                return ((Alert) actualValue).getAlert().equals(Constant.messages.getString(key));
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("alert name ").appendValue(Constant.messages.getString(key));
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                description.appendText("was ").appendValue(((Alert) item).getAlert());
            }
        };
    }

    private static ResourceBundle getExtensionResourceBundle(Extension ext) {
        return ResourceBundle.getBundle(
                ext.getClass().getPackage().getName() + ".resources." + Constant.MESSAGES_PREFIX,
                Locale.ROOT,
                ext.getClass().getClassLoader(),
                ResourceBundle.Control.getControl(ResourceBundle.Control.FORMAT_PROPERTIES));
    }

}