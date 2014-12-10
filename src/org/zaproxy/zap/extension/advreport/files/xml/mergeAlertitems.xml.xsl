<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" version="1.0"  encoding="utf-8" indent="yes" />


<xsl:template match="/OWASPZAPReport">
  <OWASPZAPReport><xsl:copy-of select="@*" />
  <xsl:for-each select="site">
    <site><xsl:copy-of select="@*" />
      <alerts>
        <xsl:key name="alertByAlert" match="alertitem" use="concat(alert)" />
        <xsl:for-each select="alerts/alertitem[generate-id() = generate-id(key('alertByAlert',alert))]">
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
              <desc>
                <xsl:value-of select="desc"/>
              </desc>
              <solution>
                <xsl:value-of select="solution"/>
              </solution>
              <br/>


              <xsl:for-each select="key('alertByAlert', alert)">
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
                <br/>
                </evidence>

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