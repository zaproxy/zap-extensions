package org.zaproxy.zap.extension.multiFuzz;

public abstract class FuzzLocation implements Comparable<FuzzLocation>{
	public abstract boolean overLap(FuzzLocation f);
}
