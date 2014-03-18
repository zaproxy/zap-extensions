package org.zaproxy.zap.extension.multiFuzz;

import java.util.ArrayList;

import org.owasp.jbrofuzz.core.Fuzzer;

public class FuzzGap {
	private String orig;
	private MFuzzableMessage fuzzMessage;
	private FuzzLocation fuzzLoc;
	private ArrayList<Fuzzer> fuzzers;
	private ArrayList<FileFuzzer> fileFuzzers;
	private ArrayList<Integer> indices;

	public FuzzGap(FuzzLocation fl, MFuzzableMessage fm){
		this.fuzzLoc = fl;
		this.fuzzMessage = fm;
		this.orig = fuzzMessage.representName(fuzzLoc);
		this.fuzzers = new ArrayList<Fuzzer>();
		this.fileFuzzers = new ArrayList<FileFuzzer>();
		this.indices = new ArrayList<Integer>();
	}
	public FuzzLocation getFuzzLoc() {
		return fuzzLoc;
	}
	public void setFuzzLoc(FuzzLocation fuzzLoc) {
		this.fuzzLoc = fuzzLoc;
		this.orig = fuzzMessage.representName(fuzzLoc);
	}
	public String getOrig(){
		return this.orig;
	}
	public ArrayList<Integer> getIndices() {
		return indices;
	}
	public ArrayList<FileFuzzer> getFileFuzzers(){
		return this.fileFuzzers;
	}
	public ArrayList<Fuzzer> getFuzzers(){
		return this.fuzzers;
	}
	public void resetFuzzers(){
		fileFuzzers.clear();
		fuzzers.clear();
	}
	public void addFuzzer(FileFuzzer f){
		fileFuzzers.add(f);
	}
	public void addFuzzer(Fuzzer f){
		fuzzers.add(f);
	}
	public String getSubstitution(int nr){
		int n = nr;
		for(Fuzzer f : getFuzzers()){
			if(f.getMaximumValue() < n){
				n -= f.getMaximumValue();
			}
			else{
				f.resetCurrentValue();
				while(f.getCurrentValue() < n){
					f.next();
				}
				return ""+f.next();
			}
		}
		for(FileFuzzer f : getFileFuzzers()){
			if(f.getLength() < n){
				n -= f.getLength();
			}
			else{
				return f.getList().get(n);
			}
		}
		return null;
	}
}
