/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.addon.spider.parser;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link SpiderHtmlParser}. */
class SpiderHtmlParserUnitTest extends SpiderParserTestUtils<SpiderHtmlParser> {

    private static final Path BASE_DIR_HTML_FILES =
            getResourcePath(SpiderHtmlParserUnitTest.class, "html");

    @Override
    protected SpiderHtmlParser createParser() {
        given(spiderOptions.isParseComments()).willReturn(true);
        return new SpiderHtmlParser();
    }

    @Test
    void shouldFailToEvaluateAnUndefinedContext() {
        // Given
        ParseContext ctx = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> parser.canParseResource(ctx, false));
    }

    @Test
    void shouldParseHtmlResponse() {
        // Given
        messageWith("NoURLsSpiderHtmlParser.html");
        boolean parsed = false;
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(true)));
    }

    @Test
    void shouldNotParseHtmlResponseIfAlreadyParsed() {
        // Given
        messageWith("NoURLsSpiderHtmlParser.html");
        boolean parsed = true;
        // When
        boolean canParse = parser.canParseResource(ctx, parsed);
        // Then
        assertThat(canParse, is(equalTo(false)));
    }

    @Test
    void shouldFailToParseAnUndefinedContext() {
        // Given
        ParseContext ctx = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> parser.parseResource(ctx));
    }

    @Test
    void shouldNeverConsiderCompletelyParsed() {
        // Given
        messageWith("NoURLsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
    }

    @Test
    void shouldFindUrlsInAElements() {
        // Given
        messageWith("AElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(7)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://a.example.com/base/scheme",
                        "http://a.example.com:8000/b",
                        "https://a.example.com/c?a=b",
                        "http://example.com/sample/a/relative",
                        "http://example.com/sample/",
                        "http://example.com/a/absolute",
                        "ftp://a.example.com/"));
    }

    @Test
    void shouldFindUrlsInAnchorPingElements() {
        // Given
        messageWith("AElementsWithPingSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(23)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        // a URLs followed by ping URLs
                        "http://a.example.com/base/scheme",
                        "http://ping.example.com/base/scheme",
                        "http://a.example.com:8000/b",
                        "http://ping.example.com:8000/b",
                        "https://a.example.com/c?a=b",
                        "https://ping.example.com/c?a=b",
                        "http://example.com/sample/a/relative",
                        "http://example.com/sample/a/relative/ping",
                        "http://example.com/a/absolute",
                        "http://example.com/a/absolute/ping",
                        "ftp://a.example.com/",
                        "https://ping.example.com/ping",
                        // Ping first, is parsed href before ping
                        "http://b.example.com/",
                        "https://ping.first.com/",
                        // Ignored anchors but picked pings
                        "http://ping.example.com/mailping",
                        "http://ping.example.com/jsping",
                        "http://ping.example.com/ping",
                        // Multiple ping URLs
                        "http://a.example.com/",
                        "http://ping.example.com/",
                        "http://pong.example.com/",
                        // Multiple ping URLs with tab in the middle
                        "http://a.example.com/",
                        "http://ping.example.com/",
                        "http://pong.example.com/")); // Trailing slash is added on host
    }

    @Test
    void shouldFindUrlsInAppletElements() {
        // Given
        messageWith("AppletElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(8)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example.com/applet/src/file.class",
                        "https://example.com/applet/src/file.class",
                        "https://example.com/absolute/codebase/",
                        "http://example.com/sample/relative/applet/codebase/",
                        "http://example.com/absolute/applet/codebase/",
                        "http://example.com/test/html/body/applet/archive",
                        "https://example.com/absolute/archive",
                        "http://example.com/archive.zip"));
    }

    @Test
    void shouldFindUrlsInImportElements() {
        // Given
        messageWith("ImportElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(5)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example.com/import/namespace/implementation",
                        "https://import.example.com:9000/namespace/implementation",
                        "http://import.example.com/namespace/implementation",
                        "http://example.com/sample/import/namespace/implementation",
                        "ftp://import.example.com/namespace/implementation"));
    }

    @Test
    void shouldFindUrlsInAreaPingElements() {
        // Given
        messageWith("AreaElementsWithPingSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(23)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        // area URLs followed by ping URLs
                        "http://a.example.com/base/scheme",
                        "http://ping.example.com/base/scheme",
                        "http://a.example.com:8000/b",
                        "http://ping.example.com:8000/b",
                        "https://a.example.com/c?a=b",
                        "https://ping.example.com/c?a=b",
                        "http://example.com/sample/a/relative",
                        "http://example.com/sample/a/relative/ping",
                        "http://example.com/a/absolute",
                        "http://example.com/a/absolute/ping",
                        "ftp://a.example.com/",
                        "https://ping.example.com/ping",
                        // Ping first, is parsed href before ping
                        "http://b.example.com/",
                        "https://ping.first.com/",
                        // Ignored anchors but picked pings
                        "http://ping.example.com/mailping",
                        "http://ping.example.com/jsping",
                        "http://ping.example.com/ping",
                        // Multiple ping URLs
                        "http://a.example.com/",
                        "http://ping.example.com/",
                        "http://pong.example.com/",
                        // Multiple ping URLs with tab in the middle
                        "http://a.example.com/",
                        "http://ping.example.com/",
                        "http://pong.example.com/")); // Trailing slash is added on host
    }

    @Test
    void shouldUseMessageUriIfNoBaseElement() {
        // Given
        messageWith("NoBaseWithAElementSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(1)));
        assertThat(listener.getUrlsFound(), contains("http://example.com/relative/no/base"));
    }

    @Test
    void shouldUseAbsolutePathBaseElement() {
        // Given
        messageWith("BaseWithAbsolutePathHrefAElementSpiderHtmlParser.html", "/a/b");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(2)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example.com/base/absolute/path/relative/a/element",
                        "http://example.com/absolute/a/element"));
    }

    @Test
    void shouldUseRelativePathBaseElement() {
        // Given
        messageWith("BaseWithRelativePathHrefAElementSpiderHtmlParser.html", "/a/b");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(2)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example.com/a/base/relative/path/relative/a/element",
                        "http://example.com/absolute/a/element"));
    }

    @Test
    void shouldIgnoreBaseAndUseMessageUriIfBaseElementDoesNotHaveHref() {
        // Given
        messageWith("BaseWithoutHrefAElementSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(1)));
        assertThat(listener.getUrlsFound(), contains("http://example.com/relative/no/base"));
    }

    @Test
    void shouldIgnoreBaseAndUseMessageUriIfBaseElementHaveEmptyHref() {
        // Given
        messageWith("BaseWithEmptyHrefAElementSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(1)));
        assertThat(listener.getUrlsFound(), contains("http://example.com/relative/no/base"));
    }

    @Test
    void shouldFindUrlsInAreaElements() throws Exception {
        // Given
        messageWith("AreaElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(7)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://area.example.com/base/scheme",
                        "http://area.example.com:8000/b",
                        "https://area.example.com/c?a=b",
                        "http://example.com/sample/area/relative",
                        "http://example.com/sample/",
                        "http://example.com/area/absolute",
                        "ftp://area.example.com/"));
    }

    @Test
    void shouldFindUrlsInAudioElements() throws Exception {
        // Given
        messageWith("AudioElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(3)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example.com/sample/relative/src",
                        "http://example.com/absolute/src",
                        "https://audio.example.com/external/audio/src"));
    }

    @Test
    void shouldFindUrlsInEmbedElements() {
        // Given
        messageWith("EmbedElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(7)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://embed.example.com/base/scheme",
                        "http://embed.example.com:8000/b",
                        "https://embed.example.com/c?a=b",
                        "http://example.com/sample/embed/relative",
                        "http://example.com/sample/",
                        "http://example.com/embed/absolute",
                        "ftp://embed.example.com/"));
    }

    @Test
    void shouldFindUrlsInFrameElements() {
        // Given
        messageWith("FrameElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(7)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://frame.example.com/base/scheme",
                        "http://frame.example.com:8000/b",
                        "https://frame.example.com/c?a=b",
                        "http://example.com/sample/frame/relative",
                        "http://example.com/sample/",
                        "http://example.com/frame/absolute",
                        "ftp://frame.example.com/"));
    }

    @Test
    void shouldFindUrlsInIFrameElements() {
        // Given
        messageWith("IFrameElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(7)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://iframe.example.com/base/scheme",
                        "http://iframe.example.com:8000/b",
                        "https://iframe.example.com/c?a=b",
                        "http://example.com/sample/iframe/relative",
                        "http://example.com/sample/",
                        "http://example.com/iframe/absolute",
                        "ftp://iframe.example.com/"));
    }

    @Test
    void shouldFindUrlsInIsIndexElements() {
        // Given
        messageWith("IsIndexElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(3)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example.com/sample/relative/action",
                        "http://example.com/absolute/action",
                        "https://isindex.example.com/action/target.html"));
    }

    @Test
    void shouldFindUrlsInLinkElements() {
        // Given
        messageWith("LinkElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(7)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://link.example.com/base/scheme",
                        "http://link.example.com:8000/b",
                        "https://link.example.com/c?a=b",
                        "http://example.com/sample/link/relative",
                        "http://example.com/sample/",
                        "http://example.com/link/absolute",
                        "ftp://link.example.com/"));
    }

    @Test
    void shouldFindUrlsInInputElements() {
        // Given
        messageWith("InputElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(3)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example.com/sample/relative/src",
                        "http://example.com/absolute/src",
                        "https://input.example.com/external/inputsrc"));
    }

    @Test
    void shouldFindUrlsInObjectElements() {
        // Given
        messageWith("ObjectElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(11)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://object.example.com/base/data",
                        "http://object.example.com:8000/data",
                        "https://object.example.com/data?a=b",
                        "http://example.com/sample/data/relative",
                        "http://example.com/sample/",
                        "http://example.com/data/absolute",
                        "ftp://object.example.com/data",
                        "http://object.example.com/codebase/scheme",
                        "https://object.example.com/codebase?a=b",
                        "http://example.com/sample/codebase/relative",
                        "http://example.com/codebase/absolute"));
    }

    @Test
    void shouldFindUrlsInScriptElements() {
        // Given
        messageWith("ScriptElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(7)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://script.example.com/base/scheme",
                        "http://script.example.com:8000/b",
                        "https://script.example.com/c?a=b",
                        "http://example.com/sample/script/relative",
                        "http://example.com/sample/",
                        "http://example.com/script/absolute",
                        "ftp://script.example.com/"));
    }

    @Test
    void shouldFindUrlsInTableElements() {
        // Given
        messageWith("TableElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(11)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://table.background.example.com/base/scheme",
                        "http://table.background.example.com:8000/b",
                        "https://table.background.example.com/c?a=b",
                        "http://example.com/sample/background/relative",
                        "http://example.com/sample/",
                        "http://example.com/background/absolute",
                        "ftp://background.example.com/",
                        "http://example.com/background/td_absolute1",
                        "http://example.com/background/td_absolute2",
                        "http://example.com/sample/background/td_relative1",
                        "http://td.background.example.com/"));
    }

    @Test
    void shouldFindUrlsInVideoElements() {
        // Given
        messageWith("VideoElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(14)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://video.example.com/base/scheme",
                        "http://video.example.com:8000/b",
                        "https://video.example.com/c?a=b",
                        "http://example.com/sample/video/relative",
                        "http://example.com/sample/",
                        "http://example.com/video/absolute",
                        "ftp://video.example.com/",
                        "http://poster.example.com/",
                        "http://example.com/sample/poster/relative",
                        "http://example.com/media/cc0-videos/flower.webm",
                        "http://example.com/media/cc0-videos/flower.mp4",
                        "ftp://src.precedence.example.com/",
                        "http://example.com/media/cc0-videos/stillFound.webm",
                        "http://example.com/media/cc0-videos/stillFound.mp4"));
    }

    @Test
    void shouldFindUrlsInImgElements() {
        // Given
        messageWith("ImgElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(24)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://img.example.com/base/scheme",
                        "http://img.example.com:8000/b",
                        "https://img.example.com/c?a=b",
                        "http://example.com/sample/img/relative",
                        "http://example.com/sample/",
                        "http://example.com/img/absolute",
                        "ftp://img.example.com/",
                        "http://example.com/sample/relative/longdesc",
                        "https://img.example.com/full/longdesc",
                        "http://example.com/img/lowsrc",
                        "https://video.example.com/dynsrc/video",
                        "http://example.com/test/html/body/img/srcset1x.found",
                        "http://example.com/test/html/body/img/srcset2x.found",
                        "http://example.com/test/html/body/img/normal_srcset.found",
                        "http://example.com/test/html/body/img/normal_srcset1.found",
                        "http://example.com/test/html/body/img/normal_srcset2.found",
                        "http://example.com/test/html/body/img/normal_srcset3.found",
                        "http://example.com/test/html/body/img/compact_srcset1.found",
                        "http://example.com/test/html/body/img/compact_srcset2.found",
                        "http://example.com/test/html/body/img/compact_srcset3.found",
                        "http://example.com/test/html/body/img/mixed_compact_srcset1.found",
                        "http://example.com/test/html/body/img/mixed_compact_srcset2.found",
                        "http://example.com/sample/pixel_width1.png",
                        "http://example.com/sample/pixel_width2.png"));
    }

    @Test
    void shouldFindUrlsInMetaElements() {
        // Given
        messageWith("MetaElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(22)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://meta.example.com:8443/refresh/base/scheme",
                        "https://meta.example.com/refresh",
                        "http://example.com/sample/meta/refresh/relative",
                        "http://example.com/meta/refresh/absolute",
                        "http://meta.example.com/refresh/url/quoted/single",
                        "http://meta.example.com/refresh/url/quoted/double",
                        "ftp://meta.example.com/refresh",
                        "http://meta.example.com:8080/location/base/scheme",
                        "https://meta.example.com/location",
                        "http://example.com/sample/meta/location/relative",
                        "http://example.com/meta/location/absolute",
                        "ftp://meta.example.com/location",
                        "http://example.com/meta/csp",
                        "http://meta.example.com:4444/meta/base/csp/scheme",
                        "https://meta.example.com/meta/csp",
                        "http://example.com/sample/meta/csp/refresh/relative",
                        "ftp://meta.example.com/meta/csp/",
                        "http://example.com/meta/msapplication",
                        "http://meta.example.com:1337/meta/msapplication",
                        "https://meta.example.com/meta/msapplication",
                        "http://example.com/sample/meta/msapplication/refresh/relative",
                        "ftp://meta.example.com/meta/msapplication/refresh"));
    }

    @Test
    void shouldFindUrlsInString() {
        // Given
        messageWith("StringSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(3)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://example2.com/test/p/string/fullUrl",
                        "http://example.com/sample/with/base/tag",
                        "http://meta.example.com:8443/inline/string/scheme"));
    }

    @Test
    void shouldFindUrlsInCommentsWithElements() {
        // AKA shouldNotFindPlainUrlsInCommentsWithElements
        // Given
        messageWith("CommentWithElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(9)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://a.example.com/",
                        "http://area.example.com/",
                        "http://frame.example.com/",
                        "http://iframe.example.com/",
                        "http://img.example.com/",
                        "http://link.example.com/",
                        "http://meta.example.com/refresh/",
                        "http://meta.example.com/location/",
                        "http://script.example.com/"));
    }

    @Test
    void shouldNotFindUrlsInCommentsWithElementsIfNotEnabledToParseComments() {
        // Given
        given(spiderOptions.isParseComments()).willReturn(false);
        messageWith("CommentWithElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(0)));
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    @Test
    void shouldFindUrlsInCommentsWithoutElements() {
        // Given
        messageWith("CommentWithoutElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(10)));
        assertThat(
                listener.getUrlsFound(),
                contains(
                        "http://plaincomment.example.com/",
                        "http://plaincomment.example.com/z.php?x=y",
                        "http://plaincomment.example.com/c.pl?x=y",
                        "https://plaincomment.example.com/d.asp?x=y",
                        "https://plaincomment.example.com/e/e1/e2.html?x=y",
                        "https://plaincomment.example.com/surrounded/with/parenthesis",
                        "https://plaincomment.example.com/surrounded/with/brackets",
                        "https://plaincomment.example.com/surrounded/with/curly/brackets",
                        "http://plaincomment.example.com/variant1",
                        "http://plaincomment.example.com/variant2"));
    }

    @Test
    void shouldNotFindUrlsInCommentsWithoutElementsIfNotEnabledToParseComments() {
        // Given
        given(spiderOptions.isParseComments()).willReturn(false);
        messageWith("CommentWithoutElementsSpiderHtmlParser.html");
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(0)));
        assertThat(listener.getUrlsFound(), is(empty()));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "DocTypeWithFullUrl.html",
                "DocTypeWithRelativeUrl.html",
                "ManifestWithFullUrl.html",
                "ManifestWithRelativeUrl.html",
                "BackgroundWithFullUrl.html",
                "BackgroundWithRelativeUrl.html"
            })
    void shouldFindUrlInFile(String file) {
        // Given
        given(spiderOptions.isParseComments()).willReturn(false);
        messageWith(file);
        // When
        boolean completelyParsed = parser.parseResource(ctx);
        // Then
        assertThat(completelyParsed, is(equalTo(false)));
        assertThat(listener.getNumberOfUrlsFound(), is(equalTo(1)));
        assertThat(listener.getUrlsFound(), contains("http://example.com/found"));
    }

    private void messageWith(String filename) {
        messageWith(filename, "/");
    }

    private void messageWith(String filename, String requestUri) {
        try {
            String fileContents = readFile(BASE_DIR_HTML_FILES.resolve(filename));
            msg.setRequestHeader("GET " + requestUri + " HTTP/1.1\r\nHost: example.com\r\n");
            msg.setResponseHeader(
                    "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/html; charset=UTF-8\r\n"
                            + "Content-Length: "
                            + fileContents.length());
            msg.setResponseBody(fileContents);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
