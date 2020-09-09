<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
  version="1.0"
  >
  <xsl:output method="html"/> 
 
  <xsl:template match="/OWASPZAPReport">

<html>
<head>
<!-- ZAP: rebrand -->
<title>ZAP Scanning Report</title>

</head>

<body text="#000000">
<!-- ZAP: rebrand -->
<p><h1>ZAP Scanning Report</h1></p>

<!-- Report name and desc -->
  <p><h3>Report name: </h3>
   <xsl:value-of select="reportname"/> </p>
  
  <p><h3>Report description: </h3> 
  <xsl:value-of select="reportdesc"/> </p>
  
  
<!-- for each site -->
<xsl:for-each select="site">
  
  <br></br>
  <HR SIZE="1"></HR>

  <p>
    <h2>Site: <xsl:value-of select="@name"/> </h2>
  </p> 

  <p>
  <xsl:apply-templates select="text()"/>
  </p>
  <p><strong>Summary of Alerts</strong></p>
  <table width="45%" border="0">
    <tr bgcolor="#666666"> 
      <td width="45%" height="24"><strong><font color="#FFFFFF" size="2" face="Arial, Helvetica, sans-serif">Risk 
        Level</font></strong></td>
      <td width="55%" align="center"><strong><font color="#FFFFFF" size="2" face="Arial, Helvetica, sans-serif">Number 
        of Alerts</font></strong></td>
    </tr>
    <tr> 
      <td bgcolor="#e8e8e8"><font size="2" face="Arial, Helvetica, sans-serif"><a href="#high">High</a></font></td>
      <td bgcolor="red" align="center"><font color="#FFFFFF" size="2" face="Arial, Helvetica, sans-serif">
      <xsl:value-of select="count(descendant::alertitem[riskcode='3'])"/>
      </font></td>
    </tr>
    <tr> 
      <td bgcolor="#e8e8e8"><font size="2" face="Arial, Helvetica, sans-serif"><a href="#medium">Medium</a></font></td>
      <td bgcolor="orange" align="center"><font color="#FFFFFF" size="2" face="Arial, Helvetica, sans-serif">
      <xsl:value-of select="count(descendant::alertitem[riskcode='2'])"/>
      </font></td>
    </tr>
      <tr> 
      <td bgcolor="#e8e8e8"><font size="2" face="Arial, Helvetica, sans-serif"><a href="#low">Low</a></font></td>
      <td bgcolor="yellow" align="center"><font size="2" face="Arial, Helvetica, sans-serif">
      <xsl:value-of select="count(descendant::alertitem[riskcode='1'])"/>
      </font></td>
    </tr>
      <tr> 
      <td bgcolor="#e8e8e8"><font size="2" face="Arial, Helvetica, sans-serif"><a href="#info">Informational</a></font></td>
      <td bgcolor="green" align="center"><font color="#FFFFFF" size="2" face="Arial, Helvetica, sans-serif">
      <xsl:value-of select="count(descendant::alertitem[riskcode='0'])"/>
      </font></td>
    </tr>
  </table>
  <p></p>
  <p></p>

  <p><strong>Alert Detail</strong></p>

  <xsl:apply-templates select="descendant::alertitem">
    <xsl:sort order="descending" data-type="number" select="riskcode"/>
    <xsl:sort order="descending" data-type="number" select="confidence"/>
  </xsl:apply-templates>

  <!-- if there is port scan result -->
  <xsl:if test="portscan/port">
  <p><strong>Port Scan</strong></p>

  	<xsl:apply-templates select="descendant::portscan">
  	<table width="500px" align="left" cellpadding="2" cellspacing="0" style="font-family: Verdana; font-size: 10px;">
  		<tr>
  			<td bgcolor="#808080">
  			  <font color="#FFFFFF">
  			    <b>Port Number</b>
  			  </font>
  			</td>
  			<td bgcolor="#808080">
  			  <font color="#FFFFFF">
  			    <b>Proto</b>
  			  </font>
  			</td>
  			<td bgcolor="#808080">
  			  <font color="#FFFFFF">
  			    <b>State</b>
  			  </font>
  			</td>
  		</tr>
  		
  		<xsl:for-each select="portscan/port">
  		<tr>
  			<td style="border: 1px solid #808080">
  				<xsl:value-of select="@number"/>
  			</td>
  			<td style="border: 1px solid #808080">
  				<xsl:value-of select="@proto"/>
  			</td>
  			<td style="border: 1px solid #808080">
  				<xsl:value-of select="@state"/>
  			</td>
  		</tr>
  		</xsl:for-each>
  	</table>
  	</xsl:apply-templates>
    <br></br>

  </xsl:if>


<!-- for each site -->
</xsl:for-each>


</body>
</html>
</xsl:template>


  <!-- Top Level Heading -->
  <xsl:template match="alertitem">
<p></p>
<table width="100%" border="0">
<xsl:apply-templates select="text()|alert|desc|uri|param|attack|evidence|otherinfo|solution|reference|cweid|wascid|requestheader|responseheader|requestbody|responsebody|p|br|wbr|ul|li"/>
</table>
  </xsl:template>

  <xsl:template match="alert[following-sibling::riskcode='3']">
  <tr bgcolor="red" height="24">	
    <td width="20%" valign="top"><strong><font color="#FFFFFF" size="3" face="Arial, Helvetica, sans-serif">
    <a name="high"/>
    <xsl:value-of select="following-sibling::riskdesc"/>
    </font></strong></td>
    <td width="80%"><strong><font color="#FFFFFF" size="3" face="Arial, Helvetica, sans-serif">
      <xsl:apply-templates select="text()"/>
</font></strong></td>
  </tr>
  </xsl:template>

  <xsl:template match="alert[following-sibling::riskcode='2']">
  <!-- ZAP: Changed the medium colour to orange -->
  <tr bgcolor="orange" height="24">	
    <td width="20%" valign="top"><strong><font color="#FFFFFF" size="3" face="Arial, Helvetica, sans-serif">
    <a name="medium"/>
    <xsl:value-of select="following-sibling::riskdesc"/>
	</font></strong></td>
    <td width="80%"><strong><font color="#FFFFFF" size="3" face="Arial, Helvetica, sans-serif">
      <xsl:apply-templates select="text()"/>
</font></strong></td>
  </tr>

  </xsl:template>
  <xsl:template match="alert[following-sibling::riskcode='1']">
  <!-- ZAP: Changed the low colour to yellow -->
  <tr bgcolor="yellow" height="24">
    <a name="low"/>
    <td width="20%" valign="top"><strong><font color="#000000" size="3" face="Arial, Helvetica, sans-serif">
    <xsl:value-of select="following-sibling::riskdesc"/>
	</font></strong></td>
    <td width="80%"><strong><font color="#000000" size="3" face="Arial, Helvetica, sans-serif">
      <xsl:apply-templates select="text()"/>
</font></strong></td>
  </tr>
  </xsl:template>
  
  <xsl:template match="alert[following-sibling::riskcode='0']">
  <tr bgcolor="green" height="24">	
    <td width="20%" valign="top"><strong><font color="#FFFFFF" size="3" face="Arial, Helvetica, sans-serif">
    <a name="info"/>
    <xsl:value-of select="following-sibling::riskdesc"/>
	</font></strong></td>
    <td width="80%"><strong><font color="#FFFFFF" size="3" face="Arial, Helvetica, sans-serif">
      <xsl:apply-templates select="text()"/>
</font></strong></td>
  </tr>
  </xsl:template>


<!-- 
  <xsl:template match="riskdesc">
  <tr valign="top"> 
    <td width="20%"><font size="2" face="Arial, Helvetica, sans-serif">Risk</font></td>
    <td width="20%"><font size="2" face="Arial, Helvetica, sans-serif">
    <p>
    <xsl:apply-templates select="text()|*"/>
    </p>
    </font></td>
  </tr>
  </xsl:template>
 -->

  <xsl:template match="desc">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><font size="2" face="Arial, Helvetica, sans-serif"><p>Description</p></font></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
    <xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="uri">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><strong><font size="2" face="Arial, Helvetica, sans-serif">URL</font></strong></td>
    <td width="80%"><strong>
    <font size="2" face="Arial, Helvetica, sans-serif">
    <xsl:apply-templates select="text()|*"/>
    </font></strong></td>
  </tr>
  </xsl:template>

  <xsl:template match="param">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><blockquote><font size="2" face="Arial, Helvetica, sans-serif">Parameter</font></blockquote></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>

<xsl:template match="attack">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><blockquote><font size="2" face="Arial, Helvetica, sans-serif">Attack</font></blockquote></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>

<xsl:template match="evidence">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><blockquote><font size="2" face="Arial, Helvetica, sans-serif">Evidence</font></blockquote></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="otherinfo">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><font size="2" face="Arial, Helvetica, sans-serif">Other Information</font></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="solution">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><font size="2" face="Arial, Helvetica, sans-serif"><p>Solution</p></font></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
	</font></td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="reference">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><font size="2" face="Arial, Helvetica, sans-serif"><p>Reference</p></font></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>
  
  <xsl:template match="cweid">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><font size="2" face="Arial, Helvetica, sans-serif"><p>CWE Id</p></font></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>
  
  <xsl:template match="wascid">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><font size="2" face="Arial, Helvetica, sans-serif"><p>WASC Id</p></font></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>
  
  <xsl:template match="requestheader">
   <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><blockquote><font size="2" face="Arial, Helvetica, sans-serif"><p>Request Header</p></font></blockquote></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
   </xsl:if>
  </xsl:template>
  
  <xsl:template match="responseheader">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><blockquote><font size="2" face="Arial, Helvetica, sans-serif"><p>Response Header</p></font></blockquote></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>
  
  <xsl:template match="requestbody">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><blockquote><font size="2" face="Arial, Helvetica, sans-serif"><p>Request Body</p></font></blockquote></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>
  
  <xsl:template match="responsebody">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8" valign="top"> 
    <td width="20%"><blockquote><font size="2" face="Arial, Helvetica, sans-serif"><p>Response Body</p></font></blockquote></td>
    <td width="80%">
    <font size="2" face="Arial, Helvetica, sans-serif">
	<xsl:apply-templates select="text()|*"/>
    </font></td>
  </tr>
  </xsl:if>
  </xsl:template>
    
  <xsl:template match="p">
  <p align="justify">
  <xsl:apply-templates select="text()|*"/>
  </p>
  </xsl:template> 

  <xsl:template match="br">
  <br/>
  <xsl:apply-templates/>
  </xsl:template> 

  <xsl:template match="ul">
  <ul>
  <xsl:apply-templates select="text()|*"/>
  </ul>
  </xsl:template> 

  <xsl:template match="li">
  <li>
  <xsl:apply-templates select="text()|*"/>
  </li>
  </xsl:template> 
  
  <xsl:template match="wbr">
  <wbr/>
  <xsl:apply-templates/>
  </xsl:template> 

</xsl:stylesheet>