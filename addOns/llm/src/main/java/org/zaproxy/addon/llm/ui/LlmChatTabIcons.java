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
package org.zaproxy.addon.llm.ui;

import java.util.Base64;
import javax.swing.Icon;
import javax.swing.ImageIcon;

final class LlmChatTabIcons {

    private static final String PLUS_PNG_B64 =
            """
            iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFn
            ZVJlYWR5ccllPAAAAatJREFUeNqkU71KA0EQ/vaiib+lWCiordidpSg+QHwDBSt7n8DGhwhYCPoEgqCC
            INomARuLVIqgYKFG5f6z68xOzrvzYuXA3P7MzLffN7unjDH4jw3xx91bQXuxU4woNDjUX7VgsFOIH3/B
            nHgC0J65AzwFjDpZgoG7vb7lMsPDq6MiuK+B+kjGwFpCUjwK1DIQ3/dl0ssVh5TTM0UJP8aBgBKGleSG
            IWyP0oKYRm3KPSgYJ0Q0EpEgCASA2WmWZQY3kazBmjP9UhBFEbTWAgA0f9W2yHeG+vrd+tqGy5r5xNTT
            9erSqpvfdxwHN7fXOQZ0QhzH1oWArLsfXXieJ/KTGEZLcbVaTVn9ALTOLk9L+mYX5lxd0Xh6eGyVgspK
            6APwI8n3x9hmNpORJOuBo5ah8GcTc7dAHmkhNpYQlpHr47Hq2NspA1yEwHkoO/MVYLMmWJNarjEUQBzQ
            w7rPvardFC8tZuOEwwB4p9PHqXgCdm738sUDJPB8mnwKj7qCTtJ527+XyAs6tOf2Bb6SP0OeGxRTVMp2
            h9nweWMoKS20l3+QT/vwqfZbgAEAUCrnlLQ+w4QAAAAASUVORK5CYII=
            """;

    private static final String CLOSE_GREY_PNG_B64 =
            """
            iVBORw0KGgoAAAANSUhEUgAAAAkAAAAJCAQAAABKmM6bAAAAAXNSR0IArs4c6QAAAAJiS0dEAP+Hj8y/
            AAAACXBIWXMAAAsTAAALEwEAmpwYAAAAB3RJTUUH3QcVEwMaf7xpfAAAAJxJREFUCNdlxbEKgkAAgOH/
            PAcpSBNabmjJxRcIXFrc23oAH6Dn6RXaG5sCh4YocGmLILjJFDEwIr2GaOpbPvgjIQj8hV8VxW8LTLxU
            Jp7MvoOEYbUfJeroJGql2ZS1hLLw+idnrtbaZNczSBgHZhqprY7UredWVWFBF4cq1U2W6lB1MUhc0+SD
            +66+mEfu1YfXU+BgI2hpEdgI3h/IMj2IOCESPwAAAABJRU5ErkJggg==
            """;

    private static final String CLOSE_RED_PNG_B64 =
            """
            iVBORw0KGgoAAAANSUhEUgAAAAkAAAAJCAYAAADgkQYQAAAAAXNSR0IArs4c6QAAAAZiS0dEAP8A/wD/
            oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB90HFRMEI2/4d7MAAACwSURBVBjThdChTgNR
            EIXh72LA8QBkSXiEBgcCe5MKPJLFVDapq6wskpWQkCxmn2VeAodENpAwCLZkBQlj/vkzx8wpmem/OYCh
            lDqUEkMp9S+XmXria7XKnuhZTz0zf0JP1Edi17Y55TPnv6HM1LHuiPf5PDvigeX+5gVb6j3xNpvllFtq
            ZtJjQ7w2TW6IluXU99+fXnK7IBqucXLFzYK44A5nBcc4Guv4wOe4H47cfQMsqmT683nkgAAAAABJRU5E
            rkJggg==
            """;

    static final Icon PLUS_ICON = decodePngBase64(PLUS_PNG_B64);
    static final Icon CLOSE_GREY_ICON = decodePngBase64(CLOSE_GREY_PNG_B64);
    static final Icon CLOSE_RED_ICON = decodePngBase64(CLOSE_RED_PNG_B64);

    private LlmChatTabIcons() {}

    private static Icon decodePngBase64(String base64) {
        String compact = base64.replaceAll("\\s+", "");
        return new ImageIcon(Base64.getDecoder().decode(compact));
    }
}
