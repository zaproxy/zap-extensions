package org.zaproxy.zap.extension.websocket.treemap.analyzers.structures;

import com.google.gson.JsonParseException;
import com.google.gson.internal.LazilyParsedNumber;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.utilities.ClassValuePair;

import java.util.*;

public class LazyJsonStructure extends HashMap<String, ClassValuePair>  implements PayloadStructure{
	final static private long serialVersionUID = 1203010;
	final static public String NUMBER = "%n";
	final static public String STRING = "%s";
	final static public String BOOLEAN = "%b";
	
	public LazyJsonStructure(){
		super();
	}
	
	public LazyJsonStructure getTheAbstractMap(){
		return getTheAbstractMap(this);
	}
	
	public LazyJsonStructure getTheAbstractMap(LazyJsonStructure lazyJsonStructure){
		
		LazyJsonStructure newStructure = new LazyJsonStructure();
		
		Iterator<Entry<String, ClassValuePair>> iterator = lazyJsonStructure.entrySet().iterator();
		Entry<String, ClassValuePair> entry;
		ClassValuePair valuePair;
		
		while (iterator.hasNext()){
			entry = iterator.next();
			valuePair = entry.getValue();
			if(valuePair != null){
				if(valuePair.getaClass() == null){
					newStructure.put(entry.getKey(),null);
				}else if(valuePair.getaClass().equals(LazyJsonStructure.class)){
					newStructure.putObject(entry.getKey(),getTheAbstractMap((LazyJsonStructure) valuePair.getValue()));
				}else if (valuePair.getaClass() == ArrayList.class){
					List<ClassValuePair> classArrayList = valuePair.getValueList();
					ArrayList<Object> newList = new ArrayList<>();
					for( ClassValuePair item : classArrayList){
						if(item.equals(LazyJsonStructure.class)){
							newList.add(getTheAbstractMap((LazyJsonStructure) item.getValue()));
						}else {
							newList.add(nameToExpression(item.getaClass()));
						}
					}
					newStructure.putObject(entry.getKey(), newList);
				}else{
					newStructure.putObject(entry.getKey() , nameToExpression(valuePair.getaClass()));
				}
			}else {
				throw new JsonParseException("it's a meaningful message Key: " + entry.getKey());
			}
		}
		return newStructure;
	}
	
	public String nameToExpression(Class<?> className){
		if(className.equals(String.class)){
			return STRING;
		}else if(className.equals(LazilyParsedNumber.class)){
			return NUMBER;
		}else if(className.equals(Boolean.class)){
			return BOOLEAN;
		}
		return null;
	}
	
	public Object putObject(String s, Object o) {
		return super.put(s,new ClassValuePair(o));
	}
	
	@Override
	public ClassValuePair put(String s, ClassValuePair classValuePair) {
		return super.put(s, classValuePair);
	}
	
	@Override
	public HashMap<String, ClassValuePair> getMap() {
		return this;
	}
}

