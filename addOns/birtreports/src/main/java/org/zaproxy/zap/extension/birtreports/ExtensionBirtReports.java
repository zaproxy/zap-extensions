/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.birtreports;

import org.apache.log4j.Logger;
import org.eclipse.birt.core.exception.BirtException;
import org.eclipse.birt.core.framework.Platform;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.view.ZapMenuItem;

/** The extension responsible to setup the BIRT reports. */
public class ExtensionBirtReports extends ExtensionAdaptor {

    private static final Logger LOGGER = Logger.getLogger(ExtensionBirtReports.class);

    private ZapMenuItem menuGeneratePdfReport;
    private ZapMenuItem menuGenerateScriptedPdfReport;
    private ZapMenuItem menuUpdateLogo;

    private boolean platformInitialised;

    @Override
    public void initModel(Model model) {
        super.initModel(model);

        try {
            Platform.startup();
            platformInitialised = true;
        } catch (BirtException e) {
            LOGGER.warn("Failed to initialise Platform for BIRT:", e);
        }
    }

    @Override
    public void unload() {
        super.unload();

        if (platformInitialised) {
            Platform.shutdown();
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (platformInitialised && hasView()) {
            extensionHook.getHookMenu().addReportMenuItem(getMenuGenerateDefaultPdfReport());
            extensionHook.getHookMenu().addReportMenuItem(getMenuGenerateScriptedPdfReport());
            extensionHook.getHookMenu().addReportMenuItem(getMenuUpdateLogo());
        }
    }

    private ZapMenuItem getMenuGenerateDefaultPdfReport() {
        if (menuGeneratePdfReport == null) {
            menuGeneratePdfReport = new ZapMenuItem("birtreports.menu.pdf.default");
            menuGeneratePdfReport.addActionListener(
                    e -> {
                        ReportLastScan reportgen = new ReportLastScan();
                        reportgen.generateXmlforBirtPdf(getView(), getModel());
                        reportgen.executeBirtPdfReport(
                                getView(), Constant.messages.getString("birtreports.report.title"));
                    });
        }
        return menuGeneratePdfReport;
    }

    private ZapMenuItem getMenuGenerateScriptedPdfReport() {
        if (menuGenerateScriptedPdfReport == null) {
            menuGenerateScriptedPdfReport = new ZapMenuItem("birtreports.menu.pdf.scripted");
            menuGenerateScriptedPdfReport.addActionListener(
                    e -> {
                        ReportLastScan reportgen = new ReportLastScan();
                        reportgen.executeBirtScriptReport(
                                getView(), Constant.messages.getString("birtreports.report.title"));
                    });
        }
        return menuGenerateScriptedPdfReport;
    }

    private ZapMenuItem getMenuUpdateLogo() {
        if (menuUpdateLogo == null) {
            menuUpdateLogo = new ZapMenuItem("birtreports.menu.update.logo");
            menuUpdateLogo.addActionListener(e -> new ReportLastScan().uploadLogo(getView()));
        }
        return menuUpdateLogo;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("birtreports.desc");
    }
}
