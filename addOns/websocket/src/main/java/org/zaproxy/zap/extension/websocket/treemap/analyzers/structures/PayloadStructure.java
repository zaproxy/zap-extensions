package org.zaproxy.zap.extension.websocket.treemap.analyzers.structures;

import org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.utilities.ClassValuePair;

import java.util.HashMap;
import java.util.List;

public interface PayloadStructure {
	
	String toString();
	
	HashMap<String, ClassValuePair> getMap();
}
