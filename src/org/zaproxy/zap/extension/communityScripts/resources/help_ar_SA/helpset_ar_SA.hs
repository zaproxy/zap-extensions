<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE helpset PUBLIC "-//Sun Microsystems Inc.//DTD JavaHelp HelpSet Version 2.0//EN" "http://java.sun.com/products/javahelp/helpset_2_0.dtd">
<helpset version="2.0" xml:lang="ar-SA">
  <title>المجتمع مخطوطات | انطلق امتداد</title>

  <maps>
     <homeID>top</homeID>
     <mapref location="map.jhm"/>
  </maps>

  <view>
    <name>TOC</name>
    <label>محتوى</label>
    <type>org.zaproxy.zap.extension.help.ZapTocView</type>
    <data>toc.xml</data>
  </view>

  <view>
    <name>Index</name>
    <label>الفهرس</label>
    <type>javax.help.IndexView</type>
    <data>index.xml</data>
  </view>

  <view>
    <name>Search</name>
    <label>بحث</label>
    <type>javax.help.SearchView</type>
    <data engine="com.sun.java.help.search.DefaultSearchEngine">
      JavaHelpSearch
    </data>
  </view>

  <view>
    <name>Favorites</name>
    <label>المفضلة</label>
    <type>javax.help.FavoritesView</type>
  </view>
</helpset>