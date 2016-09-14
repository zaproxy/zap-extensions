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
package org.zaproxy.zap.extension;

import static org.junit.Assert.assertTrue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.anyVararg;
import static org.mockito.Mockito.when;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Locale;
import java.util.ResourceBundle;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.zaproxy.zap.utils.I18N;

/**
 * Class with utility methods for scanners' tests ({@link org.parosproxy.paros.core.scanner.Plugin Plugin} and
 * {@link org.zaproxy.zap.extension.pscan.PluginPassiveScanner PluginPassiveScanner}).
 * 
 * @see #mockMessages(Extension)
 * @see #hasNameLoadedWithKey(String)
 */
@RunWith(MockitoJUnitRunner.class)
public abstract class ScannerTestUtils {

    /**
     * Mocks the class variable {@link Constant#messages} using the resource bundle (Messages.properties) created from the given
     * extension.
     * <p>
     * The extension's messages are asserted that exists before obtaining it.
     * <p>
     * Resource messages that do not belong to the extension (that is, do not start with {@link Extension#getI18nPrefix()}) have
     * an empty {@code String}.
     *
     * @param extension the target extension to mock the messages
     */
    protected static void mockMessages(final Extension extension) {
        I18N i18n = Mockito.mock(I18N.class);
        Constant.messages = i18n;

        given(i18n.getLocal()).willReturn(Locale.getDefault());

        final ResourceBundle msg = getExtensionResourceBundle(extension);
        when(i18n.getString(anyString())).thenAnswer(new Answer<String>() {

            @Override
            public String answer(InvocationOnMock invocation) {
                String key = (String) invocation.getArguments()[0];
                if (key.startsWith(extension.getI18nPrefix())) {
                    assertKeyExists(msg, key);
                    return msg.getString(key);
                }
                // Return an empty string for non extension's messages.
                return "";
            }
        });

        when(i18n.getString(anyString(), anyVararg())).thenAnswer(new Answer<String>() {

            @Override
            public String answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                String key = (String) args[0];
                if (key.startsWith(extension.getI18nPrefix())) {
                    assertKeyExists(msg, key);
                    return MessageFormat.format(msg.getString(key), Arrays.copyOfRange(args, 1, args.length));
                }
                // Return an empty string for non extension's messages.
                return "";
            }
        });
    }

    private static ResourceBundle getExtensionResourceBundle(Extension ext) {
        return ResourceBundle.getBundle(
                ext.getClass().getPackage().getName() + ".resources." + Constant.MESSAGES_PREFIX,
                Locale.ROOT,
                ext.getClass().getClassLoader(),
                ResourceBundle.Control.getControl(ResourceBundle.Control.FORMAT_PROPERTIES));
    }

    private static void assertKeyExists(ResourceBundle msg, String key) {
        assertTrue("No resource message for: " + key, msg.containsKey(key));
    }

    /**
     * Creates a matcher that matches when the examined {@code Alert} has a name that matches with one loaded with the given
     * key.
     *
     * @param key the key for the name
     * @return the name matcher
     */
    protected static Matcher<Alert> hasNameLoadedWithKey(final String key) {
        return new BaseMatcher<Alert>() {

            @Override
            public boolean matches(Object actualValue) {
                return ((Alert) actualValue).getName().equals(Constant.messages.getString(key));
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("alert name ").appendValue(Constant.messages.getString(key));
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                description.appendText("was ").appendValue(((Alert) item).getName());
            }
        };
    }

    /**
     * Creates a matcher that matches when the examined {@code Alert} has a name that contains the string loaded with the given
     * key.
     *
     * @param key the key for the name
     * @return the name matcher
     */
    protected static Matcher<Alert> containsNameLoadedWithKey(final String key) {
        return new BaseMatcher<Alert>() {

            @Override
            public boolean matches(Object actualValue) {
                return ((Alert) actualValue).getName().contains(Constant.messages.getString(key));
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("alert name contains ").appendValue(Constant.messages.getString(key));
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                description.appendText("was ").appendValue(((Alert) item).getName());
            }
        };
    }

}
