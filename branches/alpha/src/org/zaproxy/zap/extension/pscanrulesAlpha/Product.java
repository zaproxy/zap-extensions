/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.pscanrulesAlpha;

/**
 * A product. 
 * @author 70pointer@gmail.com
 *
 */
public class Product {

	/**
	 * the known product types
	 */
	public enum ProductType {
		   PRODUCTTYPE_WEBSERVER
		   ,PRODUCTTYPE_APACHE_MODULE
		 }
	
	ProductType productType ;
	String productName;
	String productVersion;
	
	/**
	 * construct a Product
	 * @param productType
	 * @param productName
	 * @param productVersion
	 */
	public Product (ProductType type, String name, String version) {
		this.productType = type;
		this.productName = name;
		this.productVersion = version;
	}
	
	public ProductType getProductType() {
		return productType;
	}
	public void setProductType(ProductType productType) {
		this.productType = productType;
	}
	public String getProductName() {
		return productName;
	}
	public void setProductName(String productName) {
		this.productName = productName;
	}
	public String getProductVersion() {
		return productVersion;
	}
	public void setProductVersion(String version) {
		this.productVersion = version;
	}
	
	/**
	 * is this object equal to another?
	 * @param anotherProduct
	 * @return
	 */
	public boolean equals (Object anotherObject) {
		if ( anotherObject == null) return false;
		if ( ! ( anotherObject instanceof Product)) return false;
		
		Product anotherProduct = (Product) anotherObject;
		return ( productType == anotherProduct.getProductType() &&
				 productName.equals (anotherProduct.getProductName()) &&
				 productVersion.equals (anotherProduct.getProductVersion())  );
	}
	/**
	 * hashCode. Necessary for Set.containsKey() operation to work correctly
	 */
	public int hashCode () {
		return 314159265;
	}
	
}
