/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
package org.zaproxy.zap.extension.codedx;

import java.net.URL;
import java.util.List;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.report.ReportLastScan.ReportType;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * The Code Dx ZAP extension used to include request and response data in alert reports. 
 * 
 */
public class CodeDxExtension extends ExtensionAdaptor {

    // The name is public so that other extensions can access it
    public static final String NAME = "CodeDxExtension";

    private ZapMenuItem menu = null;

    public List<Alert> alerts;

    public CodeDxExtension() {
        super(NAME);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addReportMenuItem(getMenu());
        }

    }

    public ZapMenuItem getMenu() {
        if (menu == null) {
            menu = new ZapMenuItem("codedx.topmenu.report.title");

            menu.addActionListener(new java.awt.event.ActionListener() {

                @Override
                public void actionPerformed(java.awt.event.ActionEvent ae) {
                    ReportLastScanHttp saver = new ReportLastScanHttp();
                    saver.generateReport(getView(), getModel(), ReportType.XML);
                }
            });
        }
        return menu;
    }

    @Override
    public String getAuthor() {
        return Constant.messages.getString("codedx.author");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("codedx.desc");
    }

    @Override
    public URL getURL() {
        return null;
    }
}