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
package org.zaproxy.zap.extension.fuzz;

import javax.swing.SwingUtilities;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.zaproxy.zap.extension.fuzz.impl.FuzzerDialog;
import org.zaproxy.zap.extension.httppanel.HttpPanel;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.view.messagecontainer.MessageContainer;
import org.zaproxy.zap.view.messagecontainer.SelectableContentMessageContainer;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuComponent;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuItemMessageContainer;

public class FuzzMessageWithLocationPopupMenuItem extends ExtensionPopupMenuItemMessageContainer {

    private static final long serialVersionUID = -8193155428377564351L;

    private ExtensionFuzz extension;

    private ShowFuzzerDialogAction<?, ?> action;

    public FuzzMessageWithLocationPopupMenuItem(ExtensionFuzz extension) {
        super(Constant.messages.getString("fuzz.popup.menu.fuzz.message"));
        setIcon(FuzzerUIUtils.FUZZER_ICON);

        this.extension = extension;

        addActionListener(
                e -> {
                    action.perform();
                    action = null;
                });
    }

    @Override
    public boolean isEnableForMessageContainer(MessageContainer<?> invoker) {
        if (!extension.hasFuzzerHandlers()) {
            return false;
        }

        if (invoker instanceof SelectableContentMessageContainer) {
            return isEnableForMessageContainerHelper(
                    (SelectableContentMessageContainer<?>) invoker);
        }
        return false;
    }

    @Override
    public int getMenuIndex() {
        return 3;
    }

    private <M extends Message, F extends Fuzzer<M>> boolean isEnableForMessageContainerHelper(
            SelectableContentMessageContainer<M> invoker) {
        if (SwingUtilities.getAncestorOfClass(FuzzerDialog.class, invoker.getComponent()) != null
                || SwingUtilities.getAncestorOfClass(HttpPanel.class, invoker.getComponent())
                        == null) {
            return false;
        }

        FuzzerHandler<M, F> fuzzHandler = extension.getFuzzHandler(invoker);
        if (fuzzHandler == null || !fuzzHandler.canFuzz(invoker)) {
            return false;
        }

        if (invoker.isEmpty()) {
            this.setEnabled(false);
            return true;
        }

        if (Control.getSingleton().getMode().equals(Mode.protect)) {
            // In protected mode, so disable if not in scope
            if (!fuzzHandler.getMessage(invoker).isInScope()) {
                this.setEnabled(false);
                return true;
            }
        }

        action = new ShowFuzzerDialogAction<>(invoker, fuzzHandler);

        this.setEnabled(true);
        return true;
    }

    @Override
    public void dismissed(ExtensionPopupMenuComponent selectedMenuComponent) {
        if (selectedMenuComponent != this) {
            action = null;
        }
    }

    private class ShowFuzzerDialogAction<M extends Message, F extends Fuzzer<M>> {

        private final SelectableContentMessageContainer<M> invoker;
        private final FuzzerHandler<M, F> fuzzHandler;

        private ShowFuzzerDialogAction(
                SelectableContentMessageContainer<M> invoker, FuzzerHandler<M, F> fuzzHandler) {
            this.invoker = invoker;
            this.fuzzHandler = fuzzHandler;
        }

        public void perform() {
            extension.showFuzzerDialog(fuzzHandler, invoker);
        }
    }
}
