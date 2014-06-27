package org.zaproxy.zap.extension.accessControl.widgets;

import javax.swing.ImageIcon;
import javax.swing.tree.DefaultTreeCellRenderer;

public class SiteNodeIcons {
	public static final ImageIcon ROOT_ICON = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/16/094.png"));
	public static final ImageIcon LEAF_ICON = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/fugue/document.png"));
	public static final ImageIcon FOLDER_OPEN_ICON = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/fugue/folder-horizontal-open.png"));
	public static final ImageIcon FOLDER_CLOSED_ICON = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/fugue/folder-horizontal.png"));
	public static final ImageIcon LEAF_ICON_CHECK = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/fugue/document-check.png"));
	public static final ImageIcon FOLDER_OPEN_ICON_CHECK = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/fugue/folder-horizontal-open-check.png"));
	public static final ImageIcon FOLDER_CLOSED_ICON_CHECK = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/fugue/folder-horizontal-check.png"));
	public static final ImageIcon LEAF_ICON_CROSS = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/fugue/document-cross.png"));
	public static final ImageIcon FOLDER_OPEN_ICON_CROSS = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/fugue/folder-horizontal-open-cross.png"));
	public static final ImageIcon FOLDER_CLOSED_ICON_CROSS = new ImageIcon(DefaultTreeCellRenderer.class
			.getResource("/resource/icon/fugue/folder-horizontal-cross.png"));
}
