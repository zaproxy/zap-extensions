/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package com.sittinglittleduck.DirBuster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sittinglittleduck.DirBuster.SimpleHttpClient.HttpMethod;
import java.net.URI;
import java.net.URL;
import java.util.concurrent.LinkedBlockingQueue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/** Unit tests for {@link Worker}. */
@MockitoSettings(strictness = Strictness.LENIENT)
@ExtendWith(MockitoExtension.class)
class WorkerUnitTest {

    private static final String TARGET_URL = "http://example.com/admin";

    @Mock Manager manager;
    @Mock SimpleHttpClient httpClient;
    @Mock HttpResponse httpResponse;

    private LinkedBlockingQueue<WorkUnit> workQueue;
    private Worker worker;
    private boolean savedParseHTML;

    @BeforeEach
    void setUp() {
        workQueue = new LinkedBlockingQueue<>();
        manager.workQueue = workQueue;
        when(manager.getHttpClient()).thenReturn(httpClient);
        worker = new Worker(1, manager);
        savedParseHTML = Config.parseHTML;
        Config.parseHTML = false;
    }

    @AfterEach
    void tearDown() {
        Config.parseHTML = savedParseHTML;
    }

    // -- Thread state --

    @Test
    void shouldNotBeWorkingInitially() {
        assertThat(worker.isWorking(), is(false));
    }

    @Test
    void shouldExitRunImmediatelyWhenStopped() throws Exception {
        when(manager.hasWorkLeft()).thenReturn(true);
        worker.stopThread();

        Thread t = new Thread(worker);
        t.start();
        t.join(1000);

        assertThat(t.isAlive(), is(false));
    }

    // -- verifyIfCodeIsValid (exercised via run in simple mode) --

    @Test
    void shouldNotReportFoundWhenResponseCodeIs404() throws Exception {
        WorkUnit workUnit = buildGetWorkUnit(false, null, HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.NOT_FOUND);

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager, never())
                .foundFile(any(URL.class), anyInt(), anyString(), any(BaseCase.class));
        verify(manager, never())
                .foundDir(any(URL.class), anyInt(), anyString(), any(BaseCase.class));
    }

    @Test
    void shouldNotReportFoundWhenResponseCodeIsZero() throws Exception {
        WorkUnit workUnit = buildGetWorkUnit(false, null, HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(0);

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager, never())
                .foundFile(any(URL.class), anyInt(), anyString(), any(BaseCase.class));
        verify(manager, never())
                .foundDir(any(URL.class), anyInt(), anyString(), any(BaseCase.class));
    }

    @Test
    void shouldNotReportFoundWhenResponseCodeIsBadGateway() throws Exception {
        WorkUnit workUnit = buildGetWorkUnit(false, null, HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.BAD_GATEWAY);

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager, never())
                .foundFile(any(URL.class), anyInt(), anyString(), any(BaseCase.class));
        verify(manager, never())
                .foundDir(any(URL.class), anyInt(), anyString(), any(BaseCase.class));
    }

    @Test
    void shouldReportFileFoundWhenResponseCodeIsValid() throws Exception {
        WorkUnit workUnit = buildGetWorkUnit(false, null, HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.OK);

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager).foundFile(any(URL.class), anyInt(), anyString(), any(BaseCase.class));
    }

    @Test
    void shouldReportDirFoundWhenResponseCodeIsValid() throws Exception {
        WorkUnit workUnit = buildGetWorkUnit(true, null, HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.OK);

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager).foundDir(any(URL.class), anyInt(), anyString(), any(BaseCase.class));
    }

    // -- verifyResponseForValidRequests: content analysis mode --

    @Test
    void shouldNotReportFoundWhenResponseContainsFileNotFound() throws Exception {
        WorkUnit workUnit =
                buildGetWorkUnit(false, "base case content", HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.OK);
        when(httpResponse.getResponseBody())
                .thenReturn("<html>File Not Found on this server</html>");

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager, never())
                .foundFile(
                        any(URL.class),
                        anyInt(),
                        anyString(),
                        anyString(),
                        anyString(),
                        any(BaseCase.class));
    }

    @Test
    void shouldNotReportFoundWhenResponseMatchesBaseCase() throws Exception {
        String baseCase = "normal page content";
        WorkUnit workUnit = buildGetWorkUnit(false, baseCase, HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.OK);
        when(httpResponse.getResponseBody()).thenReturn(baseCase);

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager, never())
                .foundFile(
                        any(URL.class),
                        anyInt(),
                        anyString(),
                        anyString(),
                        anyString(),
                        any(BaseCase.class));
    }

    @Test
    void shouldReportFoundWhenResponseDiffersFromBaseCase() throws Exception {
        WorkUnit workUnit =
                buildGetWorkUnit(false, "base case content", HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.OK);
        when(httpResponse.getResponseBody()).thenReturn("completely different page content");

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager)
                .foundFile(
                        any(URL.class),
                        anyInt(),
                        anyString(),
                        anyString(),
                        anyString(),
                        any(BaseCase.class));
    }

    // -- Regex mode --

    @Test
    void shouldNotReportFoundWhenRegexMatchesResponse() throws Exception {
        WorkUnit workUnit =
                buildGetWorkUnit(false, "base case", HttpStatus.NOT_FOUND, true, "file not found");
        setupHttpResponseWithCode(HttpStatus.OK);
        when(httpResponse.getResponseBody()).thenReturn("Error: file not found on this server");

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager, never())
                .foundFile(
                        any(URL.class),
                        anyInt(),
                        anyString(),
                        anyString(),
                        anyString(),
                        any(BaseCase.class));
    }

    @Test
    void shouldReportFoundWhenRegexDoesNotMatchResponse() throws Exception {
        WorkUnit workUnit =
                buildGetWorkUnit(false, "base case", HttpStatus.NOT_FOUND, true, "file not found");
        setupHttpResponseWithCode(HttpStatus.OK);
        when(httpResponse.getResponseBody()).thenReturn("Welcome to the admin panel");

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager)
                .foundFile(
                        any(URL.class),
                        anyInt(),
                        anyString(),
                        anyString(),
                        anyString(),
                        any(BaseCase.class));
    }

    // -- HEAD method --

    @Test
    void shouldSendGetRequestAfterSuccessfulHead() throws Exception {
        URL targetUrl = new URI(TARGET_URL).toURL();
        BaseCase baseCaseObj =
                new BaseCase(
                        targetUrl, HttpStatus.NOT_FOUND, false, targetUrl, null, null, false, null);
        WorkUnit workUnit = new WorkUnit(targetUrl, false, HttpMethod.HEAD, baseCaseObj, "item");

        when(manager.isLimitRequests()).thenReturn(false);
        when(httpClient.send(any(HttpMethod.class), anyString())).thenReturn(httpResponse);
        when(httpResponse.getStatusCode()).thenReturn(HttpStatus.OK);
        when(httpResponse.getResponseHeader()).thenReturn("");
        when(httpResponse.getResponseBody()).thenReturn("");

        runWorkerWithOneWorkUnit(workUnit);

        verify(httpClient, times(2)).send(any(HttpMethod.class), anyString());
        verify(manager).foundFile(any(URL.class), anyInt(), anyString(), any(BaseCase.class));
    }

    // -- parseHtml --

    @Test
    void shouldParseHtmlWhenContentTypeIsText() throws Exception {
        Config.parseHTML = true;
        WorkUnit workUnit = buildGetWorkUnit(false, null, HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.NOT_FOUND);
        when(httpResponse.getContentType()).thenReturn("text/html");

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager, atLeastOnce()).addHTMLToParseQueue(any(HTMLparseWorkUnit.class));
    }

    @Test
    void shouldNotParseHtmlWhenContentTypeIsNull() throws Exception {
        Config.parseHTML = true;
        WorkUnit workUnit = buildGetWorkUnit(false, null, HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.NOT_FOUND);
        when(httpResponse.getContentType()).thenReturn(null);

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager, never()).addHTMLToParseQueue(any());
    }

    @Test
    void shouldNotParseHtmlWhenContentTypeIsNotText() throws Exception {
        Config.parseHTML = true;
        WorkUnit workUnit = buildGetWorkUnit(false, null, HttpStatus.NOT_FOUND, false, null);
        setupHttpResponseWithCode(HttpStatus.NOT_FOUND);
        when(httpResponse.getContentType()).thenReturn("application/json");

        runWorkerWithOneWorkUnit(workUnit);

        verify(manager, never()).addHTMLToParseQueue(any());
    }

    // -- Helpers --

    private WorkUnit buildGetWorkUnit(
            boolean isDir, String baseCase, int failCode, boolean useRegex, String regex)
            throws Exception {
        URL url = new URI(TARGET_URL).toURL();
        BaseCase baseCaseObj =
                new BaseCase(url, failCode, isDir, url, baseCase, null, useRegex, regex);
        return new WorkUnit(url, isDir, HttpMethod.GET, baseCaseObj, "item");
    }

    private void setupHttpResponseWithCode(int statusCode) throws Exception {
        when(manager.isLimitRequests()).thenReturn(false);
        when(httpClient.send(any(HttpMethod.class), anyString())).thenReturn(httpResponse);
        when(httpResponse.getStatusCode()).thenReturn(statusCode);
        when(httpResponse.getResponseHeader()).thenReturn("");
        when(httpResponse.getResponseBody()).thenReturn("");
    }

    private void runWorkerWithOneWorkUnit(WorkUnit workUnit) throws InterruptedException {
        workQueue.put(workUnit);
        when(manager.hasWorkLeft()).thenReturn(true, false);
        Thread t = new Thread(worker);
        t.start();
        t.join(2000);
        assertThat("Worker thread should have terminated", t.isAlive(), is(false));
    }
}
