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
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

public class TestCrossSiteScriptV2UnitTest extends ActiveScannerTest<TestCrossSiteScriptV2> {

    @Override
    protected TestCrossSiteScriptV2 createScanner() {
        return new TestCrossSiteScriptV2();
    }

    @Test
    public void shouldReportXssInParagraph() throws NullPointerException, IOException {
        String test = "/shouldReportXssInParagraph/";
        
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
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("</p><script>alert(1);</script><p>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("</p><script>alert(1);</script><p>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
    
    @Test
    public void shouldNotReportXssInFilteredParagraph() throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInFilteredParagraph/";
        
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
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }
    
    @Test
    public void shouldReportXssInComment() throws NullPointerException, IOException {
        String test = "/shouldReportXssInComment/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    response = getHtml("InputInComment.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("--><script>alert(1);</script><!--"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("--><script>alert(1);</script><!--"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
    
    @Test
    public void shouldReportXssInCommentWithFilteredScripts() throws NullPointerException, IOException {
        String test = "/shouldReportXssInCommentWithFilteredScripts/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    // Strip out 'script' ignoring the case
                    name = name.replaceAll("(?i)script", "");
                    response = getHtml("InputInComment.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), 
                equalTo("--><b onMouseOver=alert(1);>test</b><!--"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("--><b onMouseOver=alert(1);>test</b><!--"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
    
    @Test
    public void shouldNotReportXssInFilteredComment() throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInFilteredComment/";
        
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
                    response = getHtml("InputInComment.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }
    
    @Test
    public void shouldReportXssInBody() throws NullPointerException, IOException {
        String test = "/shouldReportXssInBody/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    response = getHtml("InputInBody.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(),  equalTo("<script>alert(1);</script>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("<script>alert(1);</script>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
    
    @Test
    public void shouldReportXssInSpanContent() throws NullPointerException, IOException {
        String test = "/shouldReportXssInSpanContent/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    response = getHtml("InputInSpan.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                System.out.println(response);
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(),  equalTo("</span><script>alert(1);</script><span>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("</span><script>alert(1);</script><span>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
    
    @Test
    public void shouldReportXssOutsideOfTags() throws NullPointerException, IOException {
        String test = "/shouldReportXssOutsideOfTags/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    response = getHtml("InputIsBody.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(),  equalTo("<script>alert(1);</script>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("<script>alert(1);</script>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
    
    @Test
    public void shouldReportXssOutsideOfHtmlTags() throws NullPointerException, IOException {
        String test = "/shouldReportXssOutsideOfHtmlTags/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    response = getHtml("InputOutsideHtmlTag.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(),  equalTo("<script>alert(1);</script>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("<script>alert(1);</script>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
    
    @Test
    public void shouldReportXssInBodyWithFilteredScript() throws NullPointerException, IOException {
        String test = "/shouldReportXssInBodyWithFilteredScript/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    // Strip out 'script' ignoring the case
                    name = name.replaceAll("(?i)script", "");
                    response = getHtml("InputInBody.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), 
                equalTo("<b onMouseOver=alert(1);>test</b>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("<b onMouseOver=alert(1);>test</b>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
    
    @Test
    public void shouldNotReportXssInFilteredBody() throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInFilteredBody/";
        
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
                    response = getHtml("InputInBody.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldReportXssInAttribute() throws NullPointerException, IOException {
        String test = "/shouldReportXssInAttribute/";
        
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
        
        HttpMessage msg = this.getHttpMessage(test + "?color=red");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), 
                equalTo("\" onMouseOver=\"alert(1);"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("color"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("\" onMouseOver=\"alert(1);"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldNotReportXssInFilteredAttribute() throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInFilteredAttribute/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String color = session.getParms().get("color");
                String response;
                if (color != null) {
                    // Strip out suitable nasties
                    color = color.replaceAll("<", "")
                                .replaceAll(">", "")
                                .replaceAll("&", "")
                                .replaceAll("#", "")
                                .replaceAll("\"", "");;
                    response = getHtml("InputInAttribute.html",
                            new String[][] {{"color", color}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?color=red");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldReportXssInAttributeScriptTag() throws NullPointerException, IOException {
        String test = "/shouldReportXssInAttributeScriptTag/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String color = session.getParms().get("color");
                String response;
                if (color != null) {
                    // Strip out < and >
                    color = color.replaceAll("<", "").replaceAll(">", "");
                    response = getHtml("InputInAttributeScriptTag.html",
                            new String[][] {{"color", color}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?color=red");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(";alert(1)"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("color"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo(";alert(1)"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldReportXssInFrameSrcTag() throws NullPointerException, IOException {
        String test = "/shouldReportXssInFrameSrcTag/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    // Strip out < and >
                    name = name.replaceAll("<", "").replaceAll(">", "");
                    response = getHtml("InputInFrameSrcTag.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=file.html");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("javascript:alert(1);"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("javascript:alert(1);"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldReportXssInScriptIdTag() throws NullPointerException, IOException {
        String test = "/shouldReportXssInScriptIdTag/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String name = session.getParms().get("name");
                String response;
                if (name != null) {
                    // Strip out < and >
                    name = name.replaceAll("<", "").replaceAll(">", "");
                    response = getHtml("InputInScriptIdTag.html",
                            new String[][] {{"name", name}});
                } else {
                    response = getHtml("NoInput.html");
                }
                return new Response(response);
            }
        });
        
        HttpMessage msg = this.getHttpMessage(test + "?name=file.html");
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(" src=http://badsite.com"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo(" src=http://badsite.com"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
    
    @Test
    public void shouldReportXssInReflectedUrl() throws NullPointerException, IOException {
        String test = "/shouldReportXssInReflectedUrl";

        NanoServerHandler handler = new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String url = session.getUri();
                if (session.getQueryParameterString() != null) {
                    try {
                        url += "?" + 
                                URLDecoder.decode(session.getQueryParameterString(), "UTF-8");
                    } catch (UnsupportedEncodingException e) {
                        // At least this might be noticed
                        e.printStackTrace();
                    } 
                }
                
                String response = getHtml("ReflectedUrl.html",
                            new String[][] {{"url", url}});
                return new Response(response);
            }
        };

        this.nano.addHandler(handler);
        this.nano.setHandler404(handler);

        HttpMessage msg = this.getHttpMessage(test);
        
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), 
                equalTo("</p><script>alert(1);</script><p>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("query"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("</p><script>alert(1);</script><p>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
}
