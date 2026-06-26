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
package org.zaproxy.addon.client.spider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.lang.reflect.Field;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.DirectedMultigraph;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriver.Options;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.extension.option.OptionsParamView;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.DriverConfiguration;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.ScanListenner2;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link SpiderScanController}. */
@MockitoSettings(strictness = Strictness.LENIENT)
class SpiderScanControllerUnitTest extends TestUtils {

    private static final String START_URL = "https://www.example.com/";

    private ExtensionClientIntegration extension;
    private ClientMap clientMap;
    private ValueProvider valueProvider;
    private ClientSpiderOptions defaultOptions;
    private SpiderScanController controller;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionClientIntegration());

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        OptionsParam optionsParam =
                mock(OptionsParam.class, withSettings().strictness(Strictness.LENIENT));
        OptionsParamView viewParam =
                mock(OptionsParamView.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getOptionsParam()).willReturn(optionsParam);
        given(optionsParam.getViewParam()).willReturn(viewParam);
        given(viewParam.getMode()).willReturn(Control.Mode.standard.name());

        ExtensionSelenium extSelenium =
                mock(ExtensionSelenium.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionHistory history = mock(ExtensionHistory.class);
        when(extensionLoader.getExtension(ExtensionSelenium.class)).thenReturn(extSelenium);
        when(extensionLoader.getExtension(ExtensionHistory.class)).thenReturn(history);

        ExtensionNetwork network =
                mock(ExtensionNetwork.class, withSettings().strictness(Strictness.LENIENT));
        when(extensionLoader.getExtension(ExtensionNetwork.class)).thenReturn(network);
        Server server = mock(Server.class, withSettings().strictness(Strictness.LENIENT));
        given(server.start(anyInt())).willReturn(8080);
        given(network.createHttpServer(any(HttpServerConfig.class))).willReturn(server);

        WebDriver wd = mock(WebDriver.class, withSettings().strictness(Strictness.LENIENT));
        Options wdOptions = mock(Options.class, withSettings().strictness(Strictness.LENIENT));
        when(wd.manage()).thenReturn(wdOptions);
        when(wdOptions.timeouts())
                .thenReturn(
                        mock(
                                withSettings()
                                        .defaultAnswer(CALLS_REAL_METHODS)
                                        .strictness(Strictness.LENIENT)));
        when(extSelenium.getWebDriver(any(String.class), any(DriverConfiguration.class)))
                .thenReturn(wd);

        extension = mock(ExtensionClientIntegration.class);
        Session session = mock(Session.class);
        when(extension.getModel()).thenReturn(model);
        when(model.getSession()).thenReturn(session);
        lenient().when(extension.getAuthenticationHandlers()).thenReturn(java.util.List.of());

        defaultOptions = new ClientSpiderOptions();
        defaultOptions.load(new ZapXmlConfiguration());
        defaultOptions.setThreadCount(1);
        defaultOptions.setShutdownTimeInSecs(10);
        when(extension.getClientSpiderParam()).thenReturn(defaultOptions);

        clientMap = mock(ClientMap.class);
        when(clientMap.getGraph()).thenReturn(new DirectedMultigraph<>(DefaultEdge.class));
        valueProvider = mock(ValueProvider.class);

        controller = new SpiderScanController(extension, clientMap, valueProvider);
    }

    @AfterEach
    void tearDown() {
        controller.stopAllScans();
        controller.removeAllScans();
    }

    @Test
    void shouldAssignIncrementalScanIds() throws URIException {
        // When
        int firstId = startMinimalScan();
        int secondId = startMinimalScan();

        // Then
        assertThat(firstId, is(0));
        assertThat(secondId, is(1));
    }

    @Test
    void shouldReturnSpiderForScanId() throws URIException {
        // Given
        int id = startMinimalScan();

        // When / Then
        assertThat(controller.getScan(id), is(notNullValue()));
        assertThat(controller.getScan(id).getScanId(), is(id));
    }

    @Test
    void shouldUpdateScanIdViaSetScanId() throws URIException {
        // Given
        int id = startMinimalScan();
        ClientSpider spider = controller.getScan(id);

        // When
        spider.setScanId(99);

        // Then
        assertThat(spider.getScanId(), is(99));
    }

    @Test
    void shouldConvertContextSpecificObjectsToScanOptions() throws Exception {
        // Given
        Context context = mock(Context.class);
        User user = mock(User.class);
        ClientSpiderOptions customOptions = new ClientSpiderOptions();
        customOptions.load(new ZapXmlConfiguration());
        customOptions.setThreadCount(3);

        // When
        int id =
                controller.startScan(
                        "scan",
                        null,
                        user,
                        new Object[] {
                            new URI(START_URL, true), customOptions, context, Boolean.TRUE
                        });
        ClientSpider spider = controller.getScan(id);
        ScanOptions scanOptions = getScanOptions(spider);

        // Then
        assertThat(spider.getTargetUrl(), is(START_URL));
        assertThat(scanOptions.getContext(), is(context));
        assertThat(scanOptions.getUser(), is(user));
        assertThat(scanOptions.isSubtreeOnly(), is(true));
        assertThat(getValueProvider(spider), is(valueProvider));
    }

    @Test
    void shouldUseDefaultClientOptionsWhenNotProvided() throws URIException {
        // When
        int id = controller.startScan("scan", null, START_URL, null, ScanOptions.builder().build());
        controller.getScan(id).stopScan();

        // Then
        assertThat(controller.getScan(id), is(notNullValue()));
    }

    @Test
    void shouldNotEmitScanNotificationsWhenExternalControl() throws URIException {
        // Given
        ScanListenner2 listener = mock(ScanListenner2.class);

        // When
        int id =
                controller.startScan(
                        "scan",
                        null,
                        START_URL,
                        defaultOptions,
                        ScanOptions.builder().setExternalControl(true).build());
        ClientSpider spider = controller.getScan(id);
        spider.setListener(listener);
        spider.stopScan();

        // Then
        assertThat(spider.isExternalControl(), is(true));
        verify(listener, never()).scanProgress(anyInt(), any(), anyInt(), anyInt());
        verify(listener, never()).scanFinshed(anyInt(), any());
    }

    @Test
    void shouldEmitScanFinishedWhenNotExternalControl() throws URIException {
        // Given
        ScanListenner2 listener = mock(ScanListenner2.class);

        // When
        int id =
                controller.startScan(
                        "scan", null, START_URL, defaultOptions, ScanOptions.builder().build());
        ClientSpider spider = controller.getScan(id);
        spider.setListener(listener);
        spider.stopScan();

        // Then
        assertThat(spider.isExternalControl(), is(false));
        verify(listener, timeout(5000)).scanFinshed(anyInt(), any());
    }

    @Test
    void shouldUseUserFromScanOptions() throws URIException {
        // Given
        User scanUser = mock(User.class);

        // When
        int id =
                controller.startScan(
                        "scan",
                        null,
                        START_URL,
                        defaultOptions,
                        ScanOptions.builder().setUser(scanUser).build());
        ScanOptions scanOptions = getScanOptions(controller.getScan(id));

        // Then
        assertThat(scanOptions.getUser(), is(scanUser));
    }

    @Test
    void shouldSetUserFromParamWhenNotInScanOptions() throws URIException {
        // Given
        User user = mock(User.class);

        // When
        int id =
                controller.startScan(
                        "scan", null, user, new Object[] {uri(START_URL), Boolean.FALSE});
        ScanOptions scanOptions = getScanOptions(controller.getScan(id));

        // Then
        assertThat(scanOptions.getUser(), is(user));
        assertThat(scanOptions.isSubtreeOnly(), is(false));
    }

    private int startMinimalScan() throws URIException {
        int id =
                controller.startScan(
                        "scan", null, START_URL, defaultOptions, ScanOptions.builder().build());
        controller.getScan(id).stopScan();
        return id;
    }

    private static URI uri(String url) throws URIException {
        return new URI(url, true);
    }

    private static ScanOptions getScanOptions(ClientSpider spider) {
        return getField(spider, "scanOptions", ScanOptions.class);
    }

    private static ValueProvider getValueProvider(ClientSpider spider) {
        return getField(spider, "valueProvider", ValueProvider.class);
    }

    private static <T> T getField(ClientSpider spider, String name, Class<T> type) {
        try {
            Field field = ClientSpider.class.getDeclaredField(name);
            field.setAccessible(true);
            return type.cast(field.get(spider));
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
}
