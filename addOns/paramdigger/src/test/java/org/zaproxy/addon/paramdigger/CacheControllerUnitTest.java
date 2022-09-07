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
package org.zaproxy.addon.paramdigger;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

class CacheControllerUnitTest extends TestUtils {
    private CacheController cacheController;
    private HttpSender httpSender =
            new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, 17);
    private ParamDiggerConfig config;

    @BeforeEach
    void init() throws Exception {
        setUpZap();
        startServer();
        config = new ParamDiggerConfig();
    }

    @Test
    void shouldFindCacheWithParameterCacheBuster() throws Exception {
        // Given
        String path = "/testparam";
        Map<String, String> params = new HashMap<>();
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    int count = 0;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        Map<String, List<String>> ps = session.getParameters();
                        String header = "x-cache";
                        String value = "";
                        for (Map.Entry<String, List<String>> entry : ps.entrySet()) {
                            if (!params.containsKey(entry.getKey())) {
                                params.put(entry.getKey(), entry.getValue().get(0));
                                value = "miss";
                            } else if (params.get(entry.getKey()).equals(entry.getValue().get(0))) {
                                value = "hit";
                            } else {
                                value = "miss";
                            }
                        }
                        if (value.isEmpty() && count == 0) {
                            value = "miss";
                            count++;
                        } else if (value.isEmpty() && count > 0) {
                            value = "hit";
                        }
                        Response response =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeName.html",
                                                new String[][] {{"q", ""}, {"p", ""}}));
                        response.addHeader(header, value);
                        return response;
                    }
                });
        String url = this.getHttpMessage(path).getRequestHeader().getURI().toString();
        config.setUrl(url);

        // When
        cacheController = new CacheController(this.httpSender, config);

        // Then
        assertThat(cacheController.isCached(Method.GET), equalTo(true));
        assertThat(cacheController.getCache().getIndicator(), equalTo("x-cache"));
        assertThat(cacheController.getCache().isCacheBusterFound(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterIsParameter(), equalTo(true));
    }

    @Test
    void shouldNotFindCacheWithAnyCacheBuster() throws Exception {
        // Given
        String path = "/testnocache";
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String header = "x-cache";
                        String value = "miss";
                        Response response =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeName.html",
                                                new String[][] {{"q", ""}, {"p", ""}}));
                        response.addHeader(header, value);
                        return response;
                    }
                });
        String url = this.getHttpMessage(path).getRequestHeader().getURI().toString();
        config.setUrl(url);
        config.setCacheBusterName("p");

        // When
        cacheController = new CacheController(this.httpSender, config);

        // Then
        assertThat(cacheController.isCached(Method.GET), equalTo(false));
        assertThat(cacheController.getCache().getIndicator(), equalTo("x-cache"));
        assertThat(cacheController.getCache().isCacheBusterFound(), equalTo(false));
        assertThat(cacheController.getCache().isCacheBusterIsParameter(), equalTo(false));
        assertThat(cacheController.getCache().isCacheBusterIsHeader(), equalTo(false));
        assertThat(cacheController.getCache().isCacheBusterIsCookie(), equalTo(false));
    }

    @Test
    void shouldFindCacheWithHeaderCacheBuster() throws Exception {
        // Given
        String path = "/testheader";
        Map<String, String> headers = new HashMap<>();
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        Map<String, String> hs = session.getHeaders();
                        String header = "x-cache";
                        String value = "miss";

                        for (Map.Entry<String, String> entry : hs.entrySet()) {
                            if (!headers.containsKey(entry.getKey())) {
                                headers.put(entry.getKey(), entry.getValue());
                                value = "miss";
                            } else if (headers.get(entry.getKey()).equals(entry.getValue())) {
                                value = "hit";
                            } else {
                                value = "miss";
                            }
                        }
                        Response response =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeName.html",
                                                new String[][] {{"q", ""}, {"p", ""}}));
                        response.addHeader(header, value);
                        response.addHeader("p", "1");
                        return response;
                    }
                });
        String url = this.getHttpMessage(path).getRequestHeader().getURI().toString();
        config.setUrl(url);
        config.setCacheBusterName("p");

        // When
        cacheController = new CacheController(this.httpSender, config);

        // Then
        assertThat(cacheController.isCached(Method.GET), equalTo(true));
        assertThat(cacheController.getCache().getIndicator(), equalTo("x-cache"));
        assertThat(cacheController.getCache().isCacheBusterFound(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterIsHeader(), equalTo(true));
    }

    @Test
    void shouldFindCacheWithCookieCacheBuster() throws Exception {
        // Given
        String path = "/testcookie";
        Map<String, String> cookies = new HashMap<>();
        List<String> cList = new ArrayList<>();
        cList.add("p");
        cList.add("q");

        this.nano.addHandler(
                new NanoServerHandler(path) {
                    int count = 0;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        Iterator<String> c = session.getCookies().iterator();
                        List<String> cs = new ArrayList<>();
                        c.forEachRemaining(cs::add);

                        String header = "x-cache";
                        String value = "miss";

                        for (String entry : cs) {
                            if (!cookies.containsKey(entry)
                                    && (entry.equalsIgnoreCase("p")
                                            || entry.equalsIgnoreCase("q"))) {
                                cookies.put(entry, session.getCookies().read(entry));
                                value = "miss";
                            } else if (cookies.get(entry) != null
                                    && cookies.get(entry)
                                            .equals(session.getCookies().read(entry))) {
                                value = "hit";
                            } else {
                                value = "miss";
                            }
                        }

                        if (count == 0) {
                            value = "miss";
                            count++;
                        } else if (cs.isEmpty() && count > 0) {
                            value = "hit";
                        }
                        Response response =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeName.html",
                                                new String[][] {{"q", ""}, {"p", ""}}));
                        response.addHeader(header, value);
                        return response;
                    }
                });
        String url = this.getHttpMessage(path).getRequestHeader().getURI().toString();
        config.setUrl(url);
        config.setCacheBusterName("p");
        config.setCacheBustingCookies(cList);

        // When
        cacheController = new CacheController(this.httpSender, config);

        // Then
        assertThat(cacheController.isCached(Method.GET), equalTo(true));
        assertThat(cacheController.getCache().getIndicator(), equalTo("x-cache"));
        assertThat(cacheController.getCache().isCacheBusterFound(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterIsCookie(), equalTo(true));
    }

    @Test
    void shouldFindCacheWithParameterCacheBusterWhenNoIndicatorPresent()
            throws HttpMalformedHeaderException {
        // Given
        String path = "/testnoindicparam";
        Map<String, String> params = new HashMap<>();
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        Map<String, List<String>> ps = session.getParameters();
                        for (Map.Entry<String, List<String>> entry : ps.entrySet()) {
                            if (!params.containsKey(entry.getKey())) {
                                params.put(entry.getKey(), entry.getValue().get(0));
                                try {
                                    Thread.sleep(140);
                                } catch (InterruptedException e) {
                                    e.printStackTrace();
                                }
                            } else if (params.get(entry.getKey()) != null
                                    && entry.getValue().get(0) != null
                                    && !params.get(entry.getKey())
                                            .equals(entry.getValue().get(0))) {
                                params.put(entry.getKey(), entry.getValue().get(0));
                                try {
                                    Thread.sleep(180);
                                } catch (InterruptedException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                        Response resp =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeName.html",
                                                new String[][] {{"q", ""}, {"p", ""}}));
                        return resp;
                    }
                });

        String url = getHttpMessage(path).getRequestHeader().getURI().toString();
        config.setUrl(url);

        // When
        cacheController = new CacheController(this.httpSender, config);

        // Then
        assertThat(cacheController.isCached(Method.GET), equalTo(true));
        assertThat(cacheController.getCache().hasTimeIndicator(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterFound(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterIsParameter(), equalTo(true));
    }

    @Test
    void shouldFindCacheWithHeaderCacheBusterWhenNoIndicatorPresent()
            throws HttpMalformedHeaderException {
        // Given
        String path = "/testnoindicheader";
        Map<String, String> headers = new HashMap<>();
        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        Map<String, String> hs = session.getHeaders();
                        for (Map.Entry<String, String> entry : hs.entrySet()) {
                            if (!headers.containsKey(entry.getKey())) {
                                headers.put(entry.getKey(), entry.getValue());
                                try {
                                    Thread.sleep(160);
                                } catch (InterruptedException e) {
                                    e.printStackTrace();
                                }
                            } else if (headers.get(entry.getKey()) != null
                                    && entry.getValue() != null
                                    && !headers.get(entry.getKey()).equals(entry.getValue())) {
                                headers.put(entry.getKey(), entry.getValue());
                                try {
                                    Thread.sleep(180);
                                } catch (InterruptedException e) {
                                    e.printStackTrace();
                                }
                            }
                        }

                        Response resp =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeName.html",
                                                new String[][] {{"q", ""}, {"p", ""}}));
                        return resp;
                    }
                });

        String url = getHttpMessage(path).getRequestHeader().getURI().toString();
        config.setUrl(url);

        // When
        cacheController = new CacheController(this.httpSender, config);

        // Then
        assertThat(cacheController.isCached(Method.GET), equalTo(true));
        assertThat(cacheController.getCache().hasTimeIndicator(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterFound(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterIsHeader(), equalTo(true));
    }

    @Test
    void shouldFindCacheWithCookieCacheBusterWhenNoIndicatorPresent()
            throws HttpMalformedHeaderException {
        // Given
        String path = "/testnoindiccookie";
        Map<String, String> cookies = new HashMap<>();
        List<String> cList = new ArrayList<>();
        cList.add("p");
        cList.add("q");

        this.nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        Iterator<String> c = session.getCookies().iterator();
                        List<String> cs = new ArrayList<>();
                        c.forEachRemaining(cs::add);

                        for (String entry : cs) {
                            if (!cookies.containsKey(entry)
                                    && (entry.equalsIgnoreCase("p")
                                            || entry.equalsIgnoreCase("q"))) {
                                cookies.put(entry, session.getCookies().read(entry));
                                try {
                                    Thread.sleep(160);
                                } catch (InterruptedException e) {
                                    e.printStackTrace();
                                }
                            } else if (cookies.get(entry) != null
                                    && !cookies.get(entry)
                                            .equals(session.getCookies().read(entry))) {
                                cookies.put(entry, session.getCookies().read(entry));
                                try {
                                    Thread.sleep(180);
                                } catch (InterruptedException e) {
                                    e.printStackTrace();
                                }
                            }
                        }

                        Response response =
                                newFixedLengthResponse(
                                        getHtml(
                                                "AttributeName.html",
                                                new String[][] {{"q", ""}, {"p", ""}}));
                        return response;
                    }
                });
        String url = this.getHttpMessage(path).getRequestHeader().getURI().toString();
        config.setUrl(url);
        config.setCacheBusterName("p");
        config.setCacheBustingCookies(cList);
        // When
        cacheController = new CacheController(this.httpSender, config);

        // Then
        assertThat(cacheController.isCached(Method.GET), equalTo(true));
        assertThat(cacheController.getCache().hasTimeIndicator(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterFound(), equalTo(true));
        assertThat(cacheController.getCache().isCacheBusterIsCookie(), equalTo(true));
    }
}
