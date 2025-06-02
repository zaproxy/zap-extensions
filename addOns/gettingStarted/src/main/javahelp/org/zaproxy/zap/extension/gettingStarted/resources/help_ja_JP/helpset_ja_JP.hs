<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE helpset PUBLIC "-//Sun Microsystems Inc.//DTD JavaHelp HelpSet Version 2.0//EN" "http://java.sun.com/products/javahelp/helpset_2_0.dtd">
<helpset version="2.0" xml:lang="ja-JP">
  <title>入門ガイド</title>

  <maps>
     <homeID>top</homeID>
     <mapref location="map.jhm"/>
  </maps>

  <view>
    <name>TOC</name>
    <label>コンテンツ</label>
    <type>org.zaproxy.zap.extension.help.ZapTocView</type>
    <data>toc.xml</data>
  </view>

  <view>
    <name>Index</name>
    <label>インデックス</label>
    <type>javax.help.IndexView</type>
    <data>index.xml</data>
  </view>

  <view>
    <name>Search</name>
    <label>検索</label>
    <type>javax.help.SearchView</type>
    <data engine="com.sun.java.help.search.DefaultSearchEngine">
      JavaHelpSearch
    </data>
  </view>

  <view>
    <name>Favorites</name>
    <label>お気に入り</label>
    <type>javax.help.FavoritesView</type>
  </view>
</helpset>