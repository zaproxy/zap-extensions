package org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.utilities;

import java.util.ArrayList;
import java.util.List;

public class ClassValuePair{
	private Class<?> aClass = null;
	private Object value;
	private ArrayList<ClassValuePair> valuesList;
	
	public ClassValuePair(Object value){
		if(value != null) {
			this.aClass = value.getClass();
		}
		this.value =  value;
	}
	
	public ClassValuePair(List<Object> objectsList){
		this.aClass = objectsList.getClass();
		addList(objectsList);
	}
	
	public Class<?> getaClass() {
		return aClass;
	}
	
	public Object getValue() {
		return value;
	}
	
	public ArrayList<ClassValuePair> getValueList() {
		return valuesList;
	}
	
	public void addList(List<Object> objectList){
		if(valuesList == null){
			valuesList = new ArrayList<>();
		}
		for(Object object : objectList){
			valuesList.add(new ClassValuePair(object));
		}
	}
	
	
	public List<ClassValuePair> getList(){
		return valuesList;
	}
	
	public void addToList(Object object){
		valuesList.add(new ClassValuePair(object));
	}
	
	public void setValue(Object value) {
		this.value = value;
	}
	
}
