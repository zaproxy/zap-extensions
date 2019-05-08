/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.accessControl.widgets;

import javax.swing.ImageIcon;

public final class SiteNodeIcons {
    public static final ImageIcon ROOT_ICON =
            new ImageIcon(SiteNodeIcons.class.getResource("/resource/icon/16/094.png"));
    public static final ImageIcon LEAF_ICON =
            new ImageIcon(SiteNodeIcons.class.getResource("/resource/icon/fugue/document.png"));
    public static final ImageIcon FOLDER_OPEN_ICON =
            new ImageIcon(
                    SiteNodeIcons.class.getResource(
                            "/resource/icon/fugue/folder-horizontal-open.png"));
    public static final ImageIcon FOLDER_CLOSED_ICON =
            new ImageIcon(
                    SiteNodeIcons.class.getResource("/resource/icon/fugue/folder-horizontal.png"));
    public static final ImageIcon LEAF_ICON_CHECK =
            new ImageIcon(
                    SiteNodeIcons.class.getResource("/resource/icon/fugue/document-check.png"));
    public static final ImageIcon FOLDER_OPEN_ICON_CHECK =
            new ImageIcon(
                    SiteNodeIcons.class.getResource(
                            "/resource/icon/fugue/folder-horizontal-open-check.png"));
    public static final ImageIcon FOLDER_CLOSED_ICON_CHECK =
            new ImageIcon(
                    SiteNodeIcons.class.getResource(
                            "/resource/icon/fugue/folder-horizontal-check.png"));
    public static final ImageIcon LEAF_ICON_CROSS =
            new ImageIcon(
                    SiteNodeIcons.class.getResource("/resource/icon/fugue/document-cross.png"));
    public static final ImageIcon FOLDER_OPEN_ICON_CROSS =
            new ImageIcon(
                    SiteNodeIcons.class.getResource(
                            "/resource/icon/fugue/folder-horizontal-open-cross.png"));
    public static final ImageIcon FOLDER_CLOSED_ICON_CROSS =
            new ImageIcon(
                    SiteNodeIcons.class.getResource(
                            "/resource/icon/fugue/folder-horizontal-cross.png"));

    private SiteNodeIcons() {
        // Utility class
    }
}
