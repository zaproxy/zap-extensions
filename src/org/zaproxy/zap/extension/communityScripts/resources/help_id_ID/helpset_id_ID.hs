<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE helpset PUBLIC "-//Sun Microsystems Inc.//DTD JavaHelp HelpSet Version 2.0//EN" "http://java.sun.com/products/javahelp/helpset_2_0.dtd">
<helpset version="2.0" xml:lang="id-ID">
  <title>Masyarakat Script | ZAP Ekstensi</title>

  <maps>
     <homeID>top</homeID>
     <mapref location="map.jhm"/>
  </maps>

  <view>
    <name>TOC</name>
    <label>Isi</label>
    <type>org.zaproxy.zap.extension.help.ZapTocView</type>
    <data>toc.xml</data>
  </view>

  <view>
    <name>Index</name>
    <label>Indeks</label>
    <type>javax.help.IndexView</type>
    <data>index.xml</data>
  </view>

  <view>
    <name>Search</name>
    <label>Pencarian</label>
    <type>javax.help.SearchView</type>
    <data engine="com.sun.java.help.search.DefaultSearchEngine">
      JavaHelpSearch
    </data>
  </view>

  <view>
    <name>Favorites</name>
    <label>Favorit</label>
    <type>javax.help.FavoritesView</type>
  </view>
</helpset>