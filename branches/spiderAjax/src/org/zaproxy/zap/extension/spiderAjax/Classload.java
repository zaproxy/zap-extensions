package org.zaproxy.zap.extension.spiderAjax;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;

import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import com.sun.org.apache.xalan.internal.xsltc.runtime.Hashtable;

public class Classload extends ClassLoader{

	private String jarFile = "/Users/guifre/Dropbox/workspace/zap-exts/src/org/zaproxy/zap/extension/spiderAjax/lib/crawljax-2.1-SNAPSHOT.jar"; //Path to the jar file  
	    private Hashtable classes = new Hashtable(); //used to cache already defined classes  
	  
	    public Classload() {  
	        super(Classload.class.getClassLoader()); //calls the parent class loader's constructor  
	    }  
	  
	    public Class loadClass(String className) throws ClassNotFoundException {  
	        return findClass(className);  
	    }  
	  
	    public Class findClass(String className) {  
	        byte classByte[];  
	        Class result = null;  
	  
	        result = (Class) classes.get(className); //checks in cached classes  
	        if (result != null) {  
	            return result;  
	        }  
	  
	        try {  
	            return findSystemClass(className);  
	        } catch (Exception e) {  
	        }  
	  
	        try {  
	            JarFile jar = new JarFile(jarFile);  
	            JarEntry entry = jar.getJarEntry(className + ".class");  
	            InputStream is = jar.getInputStream(entry);  
	            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();  
	            int nextValue = is.read();  
	            while (-1 != nextValue) {  
	                byteStream.write(nextValue);  
	                nextValue = is.read();  
	            }  
	  
	            classByte = byteStream.toByteArray();  
	            result = defineClass(className, classByte, 0, classByte.length, null);  
	            classes.put(className, result);  
	            return result;  
	        } catch (Exception e) {  
	            return null;  
	        }  
	    }  
	  
	}  