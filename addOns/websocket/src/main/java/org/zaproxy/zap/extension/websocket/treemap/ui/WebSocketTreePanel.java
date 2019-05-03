package org.zaproxy.zap.extension.websocket.treemap.ui;

import org.apache.log4j.Logger;

import javax.swing.*;
import java.awt.*;

public class WebSocketTreePanel extends JPanel{
	
	private static final long serialVersionUID = 1111011007687312311L;
	
	private static Logger LOGGER = Logger.getLogger(WebSocketTreePanel.class);
	
	public WebSocketTreePanel(JTree webSocketTree, String scrollPaneName){
		super(new BorderLayout());
		
		JScrollPane scrollPane = new JScrollPane();
		if (scrollPaneName != null) {
			scrollPane.setName(scrollPaneName);
		}
		
		JPanel panel = new ScrollableTreesPanel(webSocketTree);
		scrollPane.setViewportView(panel);
		
		add(scrollPane);
		
	}
	
	private static class ScrollableTreesPanel extends JPanel implements Scrollable {
		
		private static final long serialVersionUID = 2709986817434976954L;
		
		private final JTree websocketTree;
		
		public ScrollableTreesPanel(JTree websocketTree) {
			super(new BorderLayout());
			this.websocketTree = websocketTree;
			add(websocketTree, BorderLayout.CENTER);
		}
		
		@Override
		public Dimension getPreferredScrollableViewportSize() {
			Dimension dCT = websocketTree.getPreferredScrollableViewportSize();
			dCT.setSize( dCT.getWidth(), dCT.getHeight());
			return dCT;
		}
		
		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
			return websocketTree.getScrollableUnitIncrement(visibleRect, orientation, direction);
		}
		
		@Override
		public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
			// Same behaviour for both trees.
			return websocketTree.getScrollableBlockIncrement(visibleRect, orientation, direction);
		}
		
		@Override
		public boolean getScrollableTracksViewportWidth() {
			int width = websocketTree.getPreferredSize().width;
			return SwingUtilities.getUnwrappedParent(this).getWidth() > width;
		}
		
		@Override
		public boolean getScrollableTracksViewportHeight() {
			return SwingUtilities.getUnwrappedParent(this)
					.getHeight() > (websocketTree.getPreferredSize().height);
		}
	}
}

