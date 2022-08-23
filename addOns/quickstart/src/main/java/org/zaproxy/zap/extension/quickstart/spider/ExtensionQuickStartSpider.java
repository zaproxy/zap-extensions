/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart.spider;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.swing.JCheckBox;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.spider.ExtensionSpider2;
import org.zaproxy.addon.spider.SpiderScan;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.QuickStartParam;
import org.zaproxy.zap.extension.quickstart.TraditionalSpider;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.Target;

public class ExtensionQuickStartSpider extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            Collections.unmodifiableList(
                    Arrays.asList(ExtensionQuickStart.class, ExtensionSpider2.class));

    private TraditionalSpiderImpl traditionalSpider;

    @Override
    public String getUIName() {
        return Constant.messages.getString("quickstart.spider.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.spider.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        if (ExtensionSpider.class.getAnnotation(Deprecated.class) == null) {
            return;
        }

        traditionalSpider = new TraditionalSpiderImpl();
        getExtension(ExtensionQuickStart.class).setTraditionalSpider(traditionalSpider);
    }

    private static <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (ExtensionSpider.class.getAnnotation(Deprecated.class) == null) {
            return;
        }

        getExtension(ExtensionQuickStart.class).setTraditionalSpider(null);
    }

    private static class TraditionalSpiderImpl implements TraditionalSpider {

        private JCheckBox spiderCheckBox;

        @Override
        public String getLabel() {
            return Constant.messages.getString("quickstart.label.tradspider");
        }

        @Override
        public JCheckBox getComponent() {
            if (spiderCheckBox == null) {
                QuickStartParam param =
                        getExtension(ExtensionQuickStart.class).getQuickStartParam();
                spiderCheckBox = new JCheckBox();
                spiderCheckBox.setSelected(param.isTradSpiderEnabled());
                spiderCheckBox.addActionListener(
                        e -> param.setTradSpiderEnabled(spiderCheckBox.isSelected()));
            }
            return spiderCheckBox;
        }

        @Override
        public boolean isSelected() {
            return getComponent().isSelected();
        }

        @Override
        public void setEnabled(boolean enabled) {
            getComponent().setEnabled(enabled);
        }

        @Override
        public Scan startScan(String displayName, Target target) {
            ExtensionSpider2 extension = getExtension(ExtensionSpider2.class);

            int scanId = extension.startScan(displayName, target, null, null);
            return new ScanImpl(extension.getScan(scanId));
        }
    }

    private static class ScanImpl implements TraditionalSpider.Scan {

        private SpiderScan scan;

        public ScanImpl(SpiderScan scan) {
            this.scan = scan;
        }

        @Override
        public boolean isStopped() {
            return scan.isStopped();
        }

        @Override
        public void stopScan() {
            scan.stopScan();
        }

        @Override
        public int getProgress() {
            return scan.getProgress();
        }
    }
}
