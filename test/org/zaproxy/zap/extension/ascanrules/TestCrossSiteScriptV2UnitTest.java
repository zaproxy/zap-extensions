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
package org.zaproxy.zap.extension.ascanrules;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.network.HttpMessage;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

public class TestCrossSiteScriptV2UnitTest extends ActiveScannerTest {

    @Override
    protected TestCrossSiteScriptV2 createScanner() {
        return new TestCrossSiteScriptV2();
    }

    @Test
    public void reportsSimpleXss() throws NullPointerException, IOException {
        String test = "reportsSimpleXss";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    response = getHtml("InputInParagraph.html",
                    		new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage("/" + test + "/?name=test");
        
        this.rule.init(msg, this.parent);

        ((AbstractAppParamPlugin)this.rule).scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), 
                equalTo("</p><script>alert(1);</script><p>"));
    }
    
    @Test
    public void noXssStripNasties() throws NullPointerException, IOException {
        String test = "noXssStripNasties";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    // Strip out suitable nasties
                    name = name.replaceAll("<", "")
                                .replaceAll(">", "")
                                .replaceAll("&", "")
                                .replaceAll("#", "");
                    response = getHtml("InputInParagraph.html",
                    		new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage("/" + test + "/?name=test");
        
        this.rule.init(msg, this.parent);

        ((AbstractAppParamPlugin)this.rule).scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }
    
    @Test
    public void reportsXssInAttribute() throws NullPointerException, IOException {
        String test = "reportsXssInAttribute";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String color = session.getParms().get("color");
                String response;
                if (color != null) {
                    // Strip out < and >
                    color = color.replaceAll("<", "").replaceAll(">", "");
                    response = getHtml("InputInAttribute.html",
                    		new String[][] {{"color", color}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage("/" + test + "/?color=red");
        
        this.rule.init(msg, this.parent);

        ((AbstractAppParamPlugin)this.rule).scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), 
                equalTo("\" onMouseOver=\"alert(1);"));
    }
}
