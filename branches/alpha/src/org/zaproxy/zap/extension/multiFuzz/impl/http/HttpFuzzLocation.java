package org.zaproxy.zap.extension.multiFuzz.impl.http;

import org.zaproxy.zap.extension.multiFuzz.FuzzLocation;

public class HttpFuzzLocation extends FuzzLocation{
	public final int start;
	public final int end;
	public final boolean header;
	
	public HttpFuzzLocation(int s, int e, boolean h){
		start = s;
		end = e;
		header = h;
	}
	
	@Override
	public boolean overLap(FuzzLocation f) {
		if(f.getClass().equals(HttpFuzzLocation.class)){
			boolean s = start < ((HttpFuzzLocation) f).start;
			boolean e = end < ((HttpFuzzLocation) f).end;
			return (s == e);
		}
		return false;
	}

	@Override
	public int compareTo(FuzzLocation o) {
		return start - ((HttpFuzzLocation) o).start;
	}

}
