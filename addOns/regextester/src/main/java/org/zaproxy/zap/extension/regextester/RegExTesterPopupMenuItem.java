/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.regextester;

import java.util.function.Consumer;
import java.util.function.Function;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.view.popup.PopupMenuHttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
public class RegExTesterPopupMenuItem extends PopupMenuHttpMessageContainer {
    private static final long serialVersionUID = 1L;

    private static final String POPUP_MENU_LABEL =
            Constant.messages.getString("regextester.popup.option");
    private static final String POPUP_MENU_ALL =
            Constant.messages.getString("regextester.popup.option.all");
    private static final String POPUP_MENU_BODY =
            Constant.messages.getString("regextester.popup.option.body");
    private static final String POPUP_MENU_HEADER =
            Constant.messages.getString("regextester.popup.option.header");
    private static final String POPUP_MENU_REQUEST =
            Constant.messages.getString("regextester.popup.option.request");
    private static final String POPUP_MENU_RESPONSE =
            Constant.messages.getString("regextester.popup.option.response");

    private ExtensionRegExTester extension;

    public RegExTesterPopupMenuItem(ExtensionRegExTester extension) {
        super(POPUP_MENU_LABEL);
        this.extension = extension;
        setButtonStateOverriddenByChildren(false);
        add(createRequestMenu());
        add(createResponseMenu());
    }

    private PopupMenuHttpMessageContainer createRequestMenu() {
        PopupMenuHttpMessageContainer request =
                new PopupMenuHttpMessageContainer(POPUP_MENU_REQUEST);

        request.add(
                new SubMenuItem(
                        POPUP_MENU_HEADER,
                        m -> !m.getRequestHeader().isEmpty(),
                        m -> showDialog(m.getRequestHeader().toString())));

        request.add(
                new SubMenuItem(
                        POPUP_MENU_BODY,
                        m -> m.getRequestBody().length() != 0,
                        m -> showDialog(m.getRequestBody().toString())));

        request.addSeparator();

        request.add(
                new SubMenuItem(
                        POPUP_MENU_ALL,
                        m -> !m.getRequestHeader().isEmpty() && m.getRequestBody().length() != 0,
                        m ->
                                showDialog(
                                        m.getRequestHeader().toString()
                                                + m.getRequestBody().toString())));

        return request;
    }

    private PopupMenuHttpMessageContainer createResponseMenu() {
        PopupMenuHttpMessageContainer request =
                new PopupMenuHttpMessageContainer(POPUP_MENU_RESPONSE);

        request.add(
                new SubMenuItem(
                        POPUP_MENU_HEADER,
                        m -> !m.getResponseHeader().isEmpty(),
                        m -> showDialog(m.getResponseHeader().toString())));

        request.add(
                new SubMenuItem(
                        POPUP_MENU_BODY,
                        m -> m.getResponseBody().length() != 0,
                        m -> showDialog(m.getResponseBody().toString())));

        request.addSeparator();

        request.add(
                new SubMenuItem(
                        POPUP_MENU_ALL,
                        m -> !m.getResponseHeader().isEmpty() && m.getResponseBody().length() != 0,
                        m ->
                                showDialog(
                                        m.getResponseHeader().toString()
                                                + m.getResponseBody().toString())));

        return request;
    }

    private void showDialog(String value) {
        extension.showDialog("", value);
    }

    @Override
    public boolean precedeWithSeparator() {
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    private static class SubMenuItem extends PopupMenuItemHttpMessageContainer {

        private static final long serialVersionUID = 1L;

        private Function<HttpMessage, Boolean> isEnabled;
        private Consumer<HttpMessage> performAction;

        public SubMenuItem(
                String label,
                Function<HttpMessage, Boolean> isEnabled,
                Consumer<HttpMessage> performAction) {
            super(label);
            this.isEnabled = isEnabled;
            this.performAction = performAction;
        }

        @Override
        public boolean isButtonEnabledForSelectedHttpMessage(HttpMessage httpMessage) {
            return isEnabled.apply(httpMessage);
        }

        @Override
        public void performAction(HttpMessage httpMessage) {
            performAction.accept(httpMessage);
        }

        @Override
        public boolean isSafe() {
            return true;
        }
    }
}
