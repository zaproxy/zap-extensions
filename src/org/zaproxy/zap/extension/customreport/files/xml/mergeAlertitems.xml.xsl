<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" version="1.0"  encoding="utf-8" indent="yes" />
<xsl:key name="k1" match="alertitem" use="concat(ancestor::site/@name, '|', alert)" />

<xsl:template match="/OWASPZAPReport">
  <OWASPZAPReport><xsl:copy-of select="@*" />
  <reportname>
  	<xsl:value-of select="reportname"/>
  </reportname>
  <reportdesc>
  	<xsl:value-of select="reportdesc"/>
  </reportdesc>
  <xsl:for-each select="site">
    <site><xsl:copy-of select="@*" />
      <alerts>
        <xsl:for-each select="alerts/alertitem[generate-id() = generate-id(key('k1', concat(ancestor::site/@name, '|', alert))[1])]">  
          <alertitem>
              <alert>
                <xsl:value-of select="alert"/>
              </alert>
              <riskcode>
                <xsl:value-of select="riskcode"/>
              </riskcode>
              <riskdesc>
                <xsl:value-of select="riskdesc"/>
              </riskdesc>
              <xsl:copy-of select="desc"/>
              <xsl:copy-of select="solution"/>
              <otherinfo>
                <xsl:value-of select="otherinfo"/>
              </otherinfo>
              <reference>
              	<xsl:value-of select="reference"/>
              </reference>
              <cweid>
              	<xsl:value-of select="cweid"/>
              </cweid>
              <wascid>
              	<xsl:value-of select="wascid"/>
              </wascid>
              <br/>


              <xsl:for-each select="key('k1', concat(ancestor::site/@name, '|', alert))">
                <uri>
                  <xsl:value-of select="uri"/>
                </uri>
                <param>
                  <xsl:value-of select="param"/>
                </param>  
                <attack>
                  <xsl:value-of select="attack"/>
                </attack>          
                <evidence>
                  <xsl:value-of select="evidence"/>
                </evidence>
                <xsl:copy-of select="requestheader"/>
                <xsl:copy-of select="responseheader"/>
                <requestbody>
                  <xsl:value-of select="requestbody"/>
                </requestbody>
                <responsebody>
                  <xsl:value-of select="responsebody"/>
                </responsebody>     

              </xsl:for-each>
            </alertitem>
        </xsl:for-each>
      </alerts>
      <portscan>
        <xsl:for-each select="port">
          <port><xsl:copy-of select="@*" /></port>
        </xsl:for-each>
      </portscan>
     </site>
   </xsl:for-each >
 


  </OWASPZAPReport>
</xsl:template>



</xsl:stylesheet>