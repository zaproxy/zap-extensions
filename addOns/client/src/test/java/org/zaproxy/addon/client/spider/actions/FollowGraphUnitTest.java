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
package org.zaproxy.addon.client.spider.actions;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.withSettings;

import java.util.Map;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.DirectedMultigraph;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ElementLocator;
import org.zaproxy.addon.client.internal.graph.ClientGraphVertex;
import org.zaproxy.addon.client.spider.ActionWaitStrategy;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;

/** Unit test for {@link FollowGraph}. */
class FollowGraphUnitTest extends TestUtils {

    private static final String URL_A = "http://example.com/a";
    private static final String URL_B = "http://example.com/b";
    private static final String URL_C = "http://example.com/c";

    private WebDriver wd;
    private Graph<ClientGraphVertex, DefaultEdge> graph;
    private ValueProvider valueProvider;
    private ActionWaitStrategy waitStrategy;
    private InMemoryStats stats;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionClientIntegration());
    }

    @BeforeEach
    void setUp() {
        wd = mock();
        graph = new DirectedMultigraph<>(DefaultEdge.class);
        valueProvider = mock();
        waitStrategy = mock(withSettings().strictness(Strictness.LENIENT));
        given(waitStrategy.waitAfterPageLoad(any())).willReturn(true);
        given(waitStrategy.waitAfterAction()).willReturn(true);
        stats = new InMemoryStats();
        Stats.addListener(stats);
    }

    @AfterEach
    void tearDown() {
        Stats.removeListener(stats);
    }

    @Test
    void shouldDoNothingWhenAlreadyAtTarget() {
        // Given
        given(wd.getCurrentUrl()).willReturn(URL_A);
        FollowGraph action = new FollowGraph(graph, URL_A, valueProvider);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertCommonState(wd, result);
        verify(waitStrategy, never()).waitAfterPageLoad(any());
        verify(wd, never()).get(any());
        assertThat(stats.getStat("stats.client.spider.action.follow"), is(1L));
    }

    @Test
    void shouldDoNothingWhenAlreadyAtTargetWithEmptyFragment() {
        // Given
        given(wd.getCurrentUrl()).willReturn(URL_A);
        FollowGraph action = new FollowGraph(graph, URL_A + "#", valueProvider);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertCommonState(wd, result);
        verify(waitStrategy, never()).waitAfterPageLoad(any());
        verify(wd, never()).get(any());
        assertThat(stats.getStat("stats.client.spider.action.follow"), is(1L));
    }

    @Test
    void shouldFollowGraphPathWhenDirectPathExists() {
        // Given
        ClientSideComponent linkComponent = createLinkComponent(URL_A, URL_B);
        addGraphEdge(URL_A, linkComponent, URL_B);

        given(wd.getCurrentUrl()).willReturn(URL_A);
        WebElement element = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(element);

        FollowGraph action = new FollowGraph(graph, URL_B, valueProvider);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertCommonState(wd, result);
        verify(element).click();
        verify(wd, never()).get(any());
        verify(waitStrategy).waitAfterPageLoad(URL_B);
        assertThat(stats.getStat("stats.client.spider.action.follow"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.follow.path"), is(1L));
    }

    @Test
    void shouldFallBackToOpenUrlWhenNoPathExists() {
        // Given
        ClientGraphVertex.Url vertexA = new ClientGraphVertex.Url(URL_A);
        ClientGraphVertex.Url vertexB = new ClientGraphVertex.Url(URL_B);
        graph.addVertex(vertexA);
        graph.addVertex(vertexB);

        given(wd.getCurrentUrl()).willReturn(URL_A);

        FollowGraph action = new FollowGraph(graph, URL_B, valueProvider);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertCommonState(wd, result);
        verify(wd).get(URL_B);
        verify(waitStrategy).waitAfterPageLoad(URL_B);
        assertThat(stats.getStat("stats.client.spider.action.follow"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.follow.fallback"), is(1L));
    }

    @Test
    void shouldFollowMultiHopPath() {
        // Given
        ClientSideComponent link1 = createLinkComponent(URL_A, URL_B);
        ClientSideComponent link2 = createLinkComponent(URL_B, URL_C);
        addGraphEdge(URL_A, link1, URL_B);
        addGraphEdge(URL_B, link2, URL_C);

        given(wd.getCurrentUrl()).willReturn(URL_A);
        WebElement element = visibleElement();
        given(wd.findElement(any())).willReturn(element);

        FollowGraph action = new FollowGraph(graph, URL_C, valueProvider);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertCommonState(wd, result);
        verify(element, times(2)).click();
        verify(wd, never()).get(any());
        verify(waitStrategy).waitAfterAction();
        verify(waitStrategy).waitAfterPageLoad(URL_C);
        assertThat(stats.getStat("stats.client.spider.action.follow"), is(1L));
        assertThat(stats.getStat("stats.client.spider.action.follow.path"), is(1L));
    }

    @Test
    void shouldFollowMultiHopPathWaitingAfterFirstHop() {
        // Given
        ClientSideComponent link1 = createLinkComponent(URL_A, URL_B);
        ClientSideComponent link2 = createLinkComponent(URL_B, URL_C);
        addGraphEdge(URL_A, link1, URL_B);
        addGraphEdge(URL_B, link2, URL_C);
        String urlD = "http://example.com/d";
        ClientSideComponent link3 = createLinkComponent(URL_C, urlD);
        addGraphEdge(URL_C, link3, urlD);

        given(wd.getCurrentUrl()).willReturn(URL_A);
        WebElement element = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(element);

        FollowGraph action = new FollowGraph(graph, urlD, valueProvider);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertCommonState(wd, result);
        verify(waitStrategy, times(2)).waitAfterAction();
        verify(waitStrategy).waitAfterPageLoad(urlD);
    }

    @Test
    void shouldHandleClickExceptionGracefullyAndFallBack() {
        // Given
        ClientSideComponent linkComponent = createLinkComponent(URL_A, URL_B);
        addGraphEdge(URL_A, linkComponent, URL_B);

        given(wd.getCurrentUrl()).willReturn(URL_A);
        WebElement element = visibleElement();
        given(wd.findElement(any(By.class))).willReturn(element);

        willThrow(RuntimeException.class).given(element).click();

        FollowGraph action = new FollowGraph(graph, URL_B, valueProvider);

        // When / Then
        boolean result = assertDoesNotThrow(() -> action.run(waitStrategy, wd));
        assertCommonState(wd, result);
        assertThat(stats.getStat("stats.client.spider.action.follow"), is(1L));
    }

    @Test
    void shouldFallBackWhenSourceVertexNotInGraph() {
        // Given
        given(wd.getCurrentUrl()).willReturn(URL_A);

        FollowGraph action = new FollowGraph(graph, URL_B, valueProvider);

        // When
        boolean result = action.run(waitStrategy, wd);

        // Then
        assertCommonState(wd, result);
        verify(wd).get(URL_B);
        assertThat(stats.getStat("stats.client.spider.action.follow.fallback"), is(1L));
    }

    private void assertCommonState(WebDriver wd, boolean result) {
        assertThat(result, is(equalTo(true)));
        verifyNoInteractions(valueProvider);
        verify(wd, never()).findElements(any());
    }

    private static ClientSideComponent createLinkComponent(String parentUrl, String href) {
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        null,
                        parentUrl,
                        href,
                        null,
                        ClientSideComponent.Type.LINK,
                        null,
                        -1);
        component.setElementLocator(new ElementLocator("xpath", "//a[@href='" + href + "']"));
        return component;
    }

    private void addGraphEdge(String sourceUrl, ClientSideComponent component, String targetUrl) {
        ClientGraphVertex.Url source = new ClientGraphVertex.Url(sourceUrl);
        ClientGraphVertex.Component comp = new ClientGraphVertex.Component(component);
        ClientGraphVertex.Url target = new ClientGraphVertex.Url(targetUrl);
        graph.addVertex(source);
        graph.addVertex(comp);
        graph.addVertex(target);
        graph.addEdge(source, comp);
        graph.addEdge(comp, target);
    }

    private static WebElement visibleElement() {
        WebElement element = mock(WebElement.class);
        given(element.isDisplayed()).willReturn(true);
        return element;
    }
}
