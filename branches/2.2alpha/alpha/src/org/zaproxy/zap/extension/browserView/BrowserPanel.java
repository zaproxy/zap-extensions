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
package org.zaproxy.zap.extension.browserView;

import java.awt.BorderLayout;
import java.net.MalformedURLException;
import java.net.URL;

import javafx.application.Platform;
import javafx.embed.swing.JFXPanel;
import javafx.scene.Scene;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;

import javax.swing.JPanel;
  
public class BrowserPanel extends JPanel {
 
	private static final long serialVersionUID = 1L;
	private final JFXPanel jfxPanel = new JFXPanel();
    private WebEngine engine;
    private boolean enabled;
 
    public BrowserPanel(boolean enabled) {
        super();
        this.enabled = enabled;
        initComponents();
    }
    
    private void initComponents() {
        createScene();
        this.add(jfxPanel, BorderLayout.CENTER);
    }
 
    private void createScene() {
        Platform.runLater(new Runnable() {
            @Override 
            public void run() {
                WebView view = new WebView();
                view.setDisable(! enabled);
                engine = view.getEngine();
                jfxPanel.setScene(new Scene(view));
            }
        });
    }
 
    public void loadURL(final String url) {
        Platform.runLater(new Runnable() {
            @Override 
            public void run() {
                String tmp = toURL(url);
                if (tmp == null) {
                    tmp = toURL("http://" + url);
                }
                engine.load(tmp);
            }
        });
    }
    
    public void loadContent(final String content) {
        Platform.runLater(new Runnable() {
            @Override 
            public void run() {
                engine.loadContent(content);
            }
        });
    }

    private static String toURL(String str) {
        try {
            return new URL(str).toExternalForm();
        } catch (MalformedURLException exception) {
            return null;
        }
    }
}
