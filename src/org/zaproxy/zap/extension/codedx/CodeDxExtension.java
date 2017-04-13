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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.report.ReportLastScan.ReportType;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.codedx.security.SSLConnectionSocketFactoryFactory;
import org.zaproxy.zap.view.ZapMenuItem;

/*
 * The Code Dx ZAP extension used to include request and response data in alert reports. 
 * 
 */
public class CodeDxExtension extends ExtensionAdaptor {

    private static final Logger LOGGER = Logger.getLogger(CodeDxExtension.class);

    private static final int TIMEOUT = 5000;
    
    // The name is public so that other extensions can access it
    public static final String NAME = "CodeDxExtension";

    private ZapMenuItem menuUpload = null;
    private ZapMenuItem menuExport = null;

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
            extensionHook.getHookMenu().addReportMenuItem(getUploadMenu());
            extensionHook.getHookMenu().addReportMenuItem(getExportMenu());
        }

    }

    public ZapMenuItem getUploadMenu() {
        if (menuUpload == null) {
            menuUpload = new ZapMenuItem("codedx.topmenu.upload.title");
            menuUpload.addActionListener(new UploadActionListener(this));
        }
        return menuUpload;
    }
    
    public ZapMenuItem getExportMenu() {
        if (menuExport == null) {
            menuExport = new ZapMenuItem("codedx.topmenu.report.title");

            menuExport.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent ae) {
                    ReportLastScanHttp saver = new ReportLastScanHttp();
                    saver.generateReport(getView(), getModel(), ReportType.XML);
                }
            });
        }
        return menuExport;
    }
    
    public CloseableHttpClient getHttpClient(){
        try {
            return getHttpClient(CodeDxProperties.getInstance().getServerUrl());    
        } catch (MalformedURLException e){
            View.getSingleton().showWarningDialog(Constant.messages.getString("codedx.error.client.invalid"));
        }
        catch (IOException | GeneralSecurityException e) {
            View.getSingleton().showWarningDialog(Constant.messages.getString("codedx.error.client.failed"));
            LOGGER.error("Error creating HTTP client: ", e);
        }
        return null;
    }
    
    public CloseableHttpClient getHttpClient(String url) throws IOException, GeneralSecurityException{  
        RequestConfig config = RequestConfig.custom().setConnectTimeout(TIMEOUT).setSocketTimeout(TIMEOUT)
                .setConnectionRequestTimeout(TIMEOUT).build();
        return HttpClientBuilder.create()
                .setSSLSocketFactory(SSLConnectionSocketFactoryFactory.getFactory(new URL(url).getHost(), this))
                .setDefaultRequestConfig(config).build();
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