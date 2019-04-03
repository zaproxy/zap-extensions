<?xml version="1.0" encoding="UTF-8"?>
<!--
	Created By:	Goran Sarenkapa - JordanGS
	On:			March 10, 2016
	Uasge:		OWASP ZAP ExportReport Plugin
-->
<xsl:stylesheet 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  version="1.0"
  xmlns="http://www.w3.org/1999/xhtml" 
  exclude-result-prefixes="xsl">
  >
	<xsl:output method="xml" encoding="UTF-8" indent="yes" doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN" doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"/>
	<xsl:template match="/Report">
		<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
			<head>
				<title>OWASP ZAP Vulnerability Report</title>
				<style type="text/css">
					html *
					{
					   font-size: 98%;
					   color: #000;
					   font-family: Arial !important;
					}
					.darkstyle{
						vertical-align: text-top; 
						background:#666;
					}

					.lightstyle{
						vertical-align: text-top; 
						background:#b3b3b3;
					}

					.darkstyle div{
						color: #FFF;
						font-weight: bold;
					}

					.lightstyle div{
						color: #000;
						font-weight: bold;
					}

					.high
					{
						vertical-align: text-top; 
						background:#FF6666;					
					}
					.medium
					{
						vertical-align: text-top; 
						background:#FFB266;					
					}
					.low
					{
						vertical-align: text-top; 
						background:#FFFF99;					
					}
					.info
					{
						vertical-align: text-top; 
						background:#66B2FF;					
					}
					.high, .medium, .low, .info div{
						color: #000;
						font-weight: bold;
					}

					table {
						table-layout: fixed;
					}

					pre {
						white-space: pre-wrap;       /* CSS 3 */
						white-space: -moz-pre-wrap;  /* Mozilla, since 1999 */
						white-space: -pre-wrap;      /* Opera 4-6 */
						white-space: -o-pre-wrap;    /* Opera 7 */
						word-wrap: break-word;       /* Internet Explorer 5.5+ */
					}

					th, td {
						padding: 15px;
						word-break: break-word;
					}
				</style>
			</head>

			<body>
				<div>
					<a name="top"/>
				</div>
				<table style="width: 100%">
					<tr>
						<td colspan="4" class="darkstyle">
							<div style="font-size: 300%;">OWASP ZAP Vulnerability Report</div>
						</td>
					</tr>
					<tr>
						<td class="darkstyle">
							<div>Report Name:</div>
						</td>
						<td colspan="3" class="lightstyle">
							<div>
								<xsl:value-of select="Title"/>
							</div>
						</td>
					</tr>
					<tr>
						<td class="darkstyle">
							<div>Prepared For:</div>
						</td>
						<td class="lightstyle" style="width: 25%;">
							<div>
								<xsl:value-of select="For"/>
							</div>
						</td>
						<td class="darkstyle">
							<div>Prepared By:</div>
						</td>
						<td class="lightstyle">
							<div>
								<xsl:value-of select="By"/>
							</div>
						</td>
					</tr>
					<tr>
						<td class="darkstyle">
							<div>Scan Date:</div>
						</td>
						<td class="lightstyle">
							<div>
								<xsl:value-of select="ScanDate"/>
							</div>
						</td>
						<td class="darkstyle">
							<div>Scan Ver:</div>
						</td>
						<td class="lightstyle" style="width: 25%;">
							<div>
								<xsl:value-of select="ScanVersion"/>
							</div>
						</td>
					</tr>
					<tr>
						<td class="darkstyle">
							<div>Report Date:</div>
						</td>
						<td class="lightstyle">
							<div>
								<xsl:value-of select="ReportDate"/>
							</div>
						</td>
						<td class="darkstyle">
							<div>Report Ver:</div>
						</td>
						<td class="lightstyle">
							<div>
								<xsl:value-of select="ReportVersion"/>
							</div>
						</td>
					</tr>
					<tr>
						<td class="darkstyle">
							<div>Description:</div>
						</td>
						<td colspan="3" class="lightstyle">
							<div>
								<xsl:value-of select="Desc"/>
							</div>
						</td>
					</tr>
				</table>
				<div>
					<br/>
				</div>

				<table style="width: 100%">
					<tr>
						<td class="darkstyle" style="width: 10%;">
							<div style="font-size: 300%;">Table of Contents</div>
						</td>
					</tr>
				</table>

				<xsl:for-each select="Sites">
					<table style="width: 100%">
						<tr>
							<td class="darkstyle" style="width: 3%; text-align:center; padding:0px;">
								<div>
									<xsl:value-of select="position()" />
								</div>
							</td>
							<td class="lightstyle" style="width: 95%;">
								<div>

									<xsl:element name="a">
										<xsl:attribute name="href">
											<xsl:choose>
												<xsl:when test="contains(Name, 'https://')">
													<xsl:value-of select="concat('#',substring-after(Name,'https://'))"/>
												</xsl:when>
												<xsl:otherwise>
													<xsl:value-of select="concat('#',substring-after(Name,'http://'))"/>
												</xsl:otherwise>
											</xsl:choose>										
										</xsl:attribute>
										<span>
											<xsl:value-of select="Name"/>
										</span>
									</xsl:element>

								</div>
							</td>
						</tr>
						<tr>
							<td>
							</td>
							<td style="padding:0px;">
								<table style="width: 100%">
									<xsl:for-each select="Alerts/AlertItem">
										<tr>
											<td class="darkstyle" style="width: 3%; text-align:center; padding:0px;">
												<div>:<xsl:value-of select="position()" />
												</div>
											</td>
											<xsl:choose>
												<xsl:when test="Alert[following-sibling::RiskCode='3']">
													<td class="high" style="width: 94%;">
														<div>
															<xsl:element name="a">
																<xsl:attribute name="href">
																	<xsl:choose>
																		<xsl:when test="contains(../../Name, 'https://')">
																			<xsl:value-of select="concat('#', substring-after(../../Name,'https://'), '_', PluginID)"/>
																		</xsl:when>
																		<xsl:otherwise>
																			<xsl:value-of select="concat('#', substring-after(../../Name,'http://'), '_', PluginID)"/>
																		</xsl:otherwise>
																	</xsl:choose>	
																</xsl:attribute>
																<span><xsl:value-of select="Alert"/></span>
															</xsl:element>
														</div>
													</td>
												</xsl:when>
												<xsl:when test="Alert[following-sibling::RiskCode='2']">
													<td class="medium" style="width: 94%;">
														<div>
															<xsl:element name="a">
																<xsl:attribute name="href">
																	<xsl:choose>
																		<xsl:when test="contains(../../Name, 'https://')">
																			<xsl:value-of select="concat('#', substring-after(../../Name,'https://'), '_', PluginID)"/>
																		</xsl:when>
																		<xsl:otherwise>
																			<xsl:value-of select="concat('#', substring-after(../../Name,'http://'), '_', PluginID)"/>
																		</xsl:otherwise>
																	</xsl:choose>	
																</xsl:attribute>
																<span><xsl:value-of select="Alert"/></span>
															</xsl:element>
														</div>
													</td>
												</xsl:when>
												<xsl:when test="Alert[following-sibling::RiskCode='1']">
													<td class="low" style="width: 94%;">
														<div>
															<xsl:element name="a">
																<xsl:attribute name="href">
																	<xsl:choose>
																		<xsl:when test="contains(../../Name, 'https://')">
																			<xsl:value-of select="concat('#', substring-after(../../Name,'https://'), '_', PluginID)"/>
																		</xsl:when>
																		<xsl:otherwise>
																			<xsl:value-of select="concat('#', substring-after(../../Name,'http://'), '_', PluginID)"/>
																		</xsl:otherwise>
																	</xsl:choose>	
																</xsl:attribute>
																<span><xsl:value-of select="Alert"/></span>
															</xsl:element>
														</div>
													</td>
												</xsl:when>
												<xsl:when test="Alert[following-sibling::RiskCode='0']">
													<td class="info" style="width: 94%;">
														<div>
															<xsl:element name="a">
																<xsl:attribute name="href">
																	<xsl:choose>
																		<xsl:when test="contains(../../Name, 'https://')">
																			<xsl:value-of select="concat('#', substring-after(../../Name,'https://'), '_', PluginID)"/>
																		</xsl:when>
																		<xsl:otherwise>
																			<xsl:value-of select="concat('#', substring-after(../../Name,'http://'), '_', PluginID)"/>
																		</xsl:otherwise>
																	</xsl:choose>	
																</xsl:attribute>
																<span><xsl:value-of select="Alert"/></span>
															</xsl:element>
														</div>
													</td>
												</xsl:when>
												<xsl:otherwise>
													<td class="darkstyle" style="width: 94%;">
														<div>
															<xsl:element name="a">
																<xsl:attribute name="href">
																	<xsl:choose>
																		<xsl:when test="contains(../../Name, 'https://')">
																			<xsl:value-of select="concat('#', substring-after(../../Name,'https://'), '_', PluginID)"/>
																		</xsl:when>
																		<xsl:otherwise>
																			<xsl:value-of select="concat('#', substring-after(../../Name,'http://'), '_', PluginID)"/>
																		</xsl:otherwise>
																	</xsl:choose>	
																</xsl:attribute>
																<span><xsl:value-of select="Alert"/></span>
															</xsl:element>
														</div>
													</td>
												</xsl:otherwise>
											</xsl:choose>
										</tr>
									</xsl:for-each>
									<tr><td style="padding: 0px; height: 0px;"><!--XHTML STRICT REQUIRED FOR 1.0 COMPLIANCE IN THE EVENT THAT THERE ARE NO ELEMENTS, THERE TO CLOSE TABLE WE CREATED--></td></tr>
								</table>
							</td>						
						</tr>
					</table>
				</xsl:for-each>
				<div>
					<br/>
				</div>

				<xsl:for-each select="Sites">
					<div>
						<br/>
						<hr/>
					</div>

					<div>
						<xsl:element name="a">
							<xsl:attribute name="name">
								<xsl:choose>
									<xsl:when test="contains(Name, 'https://')">
										<xsl:value-of select="substring-after(Name,'https://')"/>
									</xsl:when>
									<xsl:otherwise>
										<xsl:value-of select="substring-after(Name,'http://')"/>
									</xsl:otherwise>
								</xsl:choose>
							</xsl:attribute>
						</xsl:element>
					</div>

					<div style="font-size: 300%;">Site: <xsl:value-of select="Name"/>
					</div>

					<div>
						<br/>
					</div>
					<div style="font-size: 200%;">Summary of Alerts</div>

					<table width="30%" border="0">
						<tr class="darkstyle"> 
							<td style="width: 50%;">
								<div>Risk Level</div>
							</td>
							<td style="width: 50%; text-align: center;">
								<div>Number of Alerts</div>
							</td>
						</tr>
						<tr class="high"> 
							<td>
								<div>
									<xsl:element name="a">
										<xsl:attribute name="href">
											<xsl:choose>
												<xsl:when test="contains(Name, 'https://')">
													<xsl:value-of select="concat('#', substring-after(Name,'https://'), '_', 'high')"/>
												</xsl:when>
												<xsl:otherwise>
													<xsl:value-of select="concat('#', substring-after(Name,'http://'), '_', 'high')"/>
												</xsl:otherwise>
											</xsl:choose>	
										</xsl:attribute>
										<xsl:text>High</xsl:text>
									</xsl:element>
								</div>
							</td>
							<td style="text-align: center;">
								<div>
									<xsl:value-of select="count(descendant::AlertItem[RiskCode='3'])"/>
								</div>
							</td>
						</tr>
						<tr class="medium"> 
							<td>
								<div>
									<xsl:element name="a">
										<xsl:attribute name="href">
											<xsl:choose>
												<xsl:when test="contains(Name, 'https://')">
													<xsl:value-of select="concat('#', substring-after(Name,'https://'), '_', 'medium')"/>
												</xsl:when>
												<xsl:otherwise>
													<xsl:value-of select="concat('#', substring-after(Name,'http://'), '_', 'medium')"/>
												</xsl:otherwise>
											</xsl:choose>	
										</xsl:attribute>
										<xsl:text>Medium</xsl:text>
									</xsl:element>
								</div>
							</td>
							<td style="text-align: center;">
								<div>
									<xsl:value-of select="count(descendant::AlertItem[RiskCode='2'])"/>
								</div>
							</td>
						</tr>
						<tr class="low"> 
							<td>
								<div>
									<xsl:element name="a">
										<xsl:attribute name="href">
											<xsl:choose>
												<xsl:when test="contains(Name, 'https://')">
													<xsl:value-of select="concat('#', substring-after(Name,'https://'), '_', 'low')"/>
												</xsl:when>
												<xsl:otherwise>
													<xsl:value-of select="concat('#', substring-after(Name,'http://'), '_', 'low')"/>
												</xsl:otherwise>
											</xsl:choose>	
										</xsl:attribute>
										<xsl:text>Low</xsl:text>
									</xsl:element>
								</div>
							</td>
							<td style="text-align: center;">
								<div>
									<xsl:value-of select="count(descendant::AlertItem[RiskCode='1'])"/>
								</div>
							</td>
						</tr>
						<tr class="info"> 
							<td>
								<div>
									<xsl:element name="a">
										<xsl:attribute name="href">
											<xsl:choose>
												<xsl:when test="contains(Name, 'https://')">
													<xsl:value-of select="concat('#', substring-after(Name,'https://'), '_', 'info')"/>
												</xsl:when>
												<xsl:otherwise>
													<xsl:value-of select="concat('#', substring-after(Name,'http://'), '_', 'info')"/>
												</xsl:otherwise>
											</xsl:choose>	
										</xsl:attribute>
										<xsl:text>Informational</xsl:text>
									</xsl:element>

								</div>
							</td>
							<td style="text-align: center;">
								<div>
									<xsl:value-of select="count(descendant::AlertItem[RiskCode='0'])"/>
								</div>
							</td>
						</tr>
					</table>
					<div>
						<br/>
					</div>
					<div style="font-size: 200%;">Alert Details</div>

					<xsl:apply-templates select="descendant::AlertItem">
						<xsl:sort select="RiskCode" data-type="number" order="descending"/>
						<xsl:sort select="Alert"/>
					</xsl:apply-templates>
				</xsl:for-each>
			</body>
		</html>
	</xsl:template>

	<xsl:template match="AlertItem">
		<table width="100%" border="0">
			<xsl:apply-templates select="text()|Alert|CWEID|WASCID|Desc|Solution|Reference|ItemCount|Item"/>
		</table>
	</xsl:template>

	<xsl:template match="Alert[following-sibling::RiskCode='3']">
		<xsl:element name="tr">
			<xsl:attribute name="id">
				<xsl:choose>
					<xsl:when test="contains(../../../Name, 'https://')">
						<xsl:value-of select="concat(substring-after(../../../Name,'https://'), '_', following-sibling::PluginID)"/>
					</xsl:when>
					<xsl:otherwise>
						<xsl:value-of select="concat(substring-after(../../../Name,'http://'), '_', following-sibling::PluginID)"/>
					</xsl:otherwise>
				</xsl:choose>			
			</xsl:attribute>
			<xsl:element name="td">
				<xsl:attribute name="class">high</xsl:attribute>
				<xsl:attribute name="style">width: 15%;</xsl:attribute>
				<xsl:element name="div">
					<xsl:element name="a">
						<xsl:attribute name="name">
							<xsl:choose>
								<xsl:when test="contains(../../../Name, 'https://')">
									<xsl:value-of select="concat(substring-after(../../../Name,'https://'), '_', 'high')"/>
								</xsl:when>
								<xsl:otherwise>
									<xsl:value-of select="concat(substring-after(../../../Name,'http://'), '_', 'high')"/>
								</xsl:otherwise>
							</xsl:choose>
						</xsl:attribute>
					</xsl:element>
					<xsl:value-of select="following-sibling::RiskDesc"/>
				</xsl:element>
			</xsl:element>

			<xsl:element name="td">
				<xsl:attribute name="class">high</xsl:attribute>
				<xsl:element name="div">
					<xsl:apply-templates select="text()"/>
				</xsl:element>
			</xsl:element>

			<xsl:element name="td">
				<xsl:attribute name="class">darkstyle</xsl:attribute>
				<xsl:attribute name="style">width: 3%; text-align:center; padding:0px;</xsl:attribute>
				<xsl:element name="div">
					<xsl:element name="a">
						<xsl:attribute name="href">#top</xsl:attribute>
						<xsl:text>Top</xsl:text>
					</xsl:element>
				</xsl:element>
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="Alert[following-sibling::RiskCode='2']">
		<xsl:element name="tr">
			<xsl:attribute name="id">
				<xsl:choose>
					<xsl:when test="contains(../../../Name, 'https://')">
						<xsl:value-of select="concat(substring-after(../../../Name,'https://'), '_', following-sibling::PluginID)"/>
					</xsl:when>
					<xsl:otherwise>
						<xsl:value-of select="concat(substring-after(../../../Name,'http://'), '_', following-sibling::PluginID)"/>
					</xsl:otherwise>
				</xsl:choose>			
			</xsl:attribute>
			<xsl:element name="td">
				<xsl:attribute name="class">medium</xsl:attribute>
				<xsl:attribute name="style">width: 15%;</xsl:attribute>
				<xsl:element name="div">
					<xsl:element name="a">
						<xsl:attribute name="name">
							<xsl:choose>
								<xsl:when test="contains(../../../Name, 'https://')">
									<xsl:value-of select="concat(substring-after(../../../Name,'https://'), '_', 'medium')"/>
								</xsl:when>
								<xsl:otherwise>
									<xsl:value-of select="concat(substring-after(../../../Name,'https://'), '_', 'medium')"/>
								</xsl:otherwise>
							</xsl:choose>
						</xsl:attribute>
					</xsl:element>
					<xsl:value-of select="following-sibling::RiskDesc"/>
				</xsl:element>
			</xsl:element>

			<xsl:element name="td">
				<xsl:attribute name="class">medium</xsl:attribute>
				<xsl:element name="div">
					<xsl:apply-templates select="text()"/>
				</xsl:element>
			</xsl:element>

			<xsl:element name="td">
				<xsl:attribute name="class">darkstyle</xsl:attribute>
				<xsl:attribute name="style">width: 3%; text-align:center; padding:0px;</xsl:attribute>
				<xsl:element name="div">
					<xsl:element name="a">
						<xsl:attribute name="href">#top</xsl:attribute>
						<xsl:text>Top</xsl:text>
					</xsl:element>
				</xsl:element>
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="Alert[following-sibling::RiskCode='1']">
		<xsl:element name="tr">
			<xsl:attribute name="id">
				<xsl:choose>
					<xsl:when test="contains(../../../Name, 'https://')">
						<xsl:value-of select="concat(substring-after(../../../Name,'https://'), '_', following-sibling::PluginID)"/>
					</xsl:when>
					<xsl:otherwise>
						<xsl:value-of select="concat(substring-after(../../../Name,'http://'), '_', following-sibling::PluginID)"/>
					</xsl:otherwise>
				</xsl:choose>			
			</xsl:attribute>
			<xsl:element name="td">
				<xsl:attribute name="class">low</xsl:attribute>
				<xsl:attribute name="style">width: 15%;</xsl:attribute>
				<xsl:element name="div">
					<xsl:element name="a">
						<xsl:attribute name="name">
							<xsl:choose>
								<xsl:when test="contains(../../../Name, 'https://')">
									<xsl:value-of select="concat(substring-after(../../../Name,'https://'), '_', 'low')"/>
								</xsl:when>
								<xsl:otherwise>
									<xsl:value-of select="concat(substring-after(../../../Name,'http://'), '_', 'low')"/>
								</xsl:otherwise>
							</xsl:choose>
						</xsl:attribute>
					</xsl:element>
					<xsl:value-of select="following-sibling::RiskDesc"/>
				</xsl:element>
			</xsl:element>

			<xsl:element name="td">
				<xsl:attribute name="class">low</xsl:attribute>
				<xsl:element name="div">
					<xsl:apply-templates select="text()"/>
				</xsl:element>
			</xsl:element>

			<xsl:element name="td">
				<xsl:attribute name="class">darkstyle</xsl:attribute>
				<xsl:attribute name="style">width: 3%; text-align:center; padding:0px;</xsl:attribute>
				<xsl:element name="div">
					<xsl:element name="a">
						<xsl:attribute name="href">#top</xsl:attribute>
						<xsl:text>Top</xsl:text>
					</xsl:element>
				</xsl:element>
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="Alert[following-sibling::RiskCode='0']">
		<xsl:element name="tr">
			<xsl:attribute name="id">
				<xsl:choose>
					<xsl:when test="contains(../../../Name, 'https://')">
						<xsl:value-of select="concat(substring-after(../../../Name,'https://'), '_', following-sibling::PluginID)"/>
					</xsl:when>
					<xsl:otherwise>
						<xsl:value-of select="concat(substring-after(../../../Name,'http://'), '_', following-sibling::PluginID)"/>
					</xsl:otherwise>
				</xsl:choose>			
			</xsl:attribute>
			<xsl:element name="td">
				<xsl:attribute name="class">info</xsl:attribute>
				<xsl:attribute name="style">width: 15%;</xsl:attribute>
				<xsl:element name="div">
					<xsl:element name="a">
						<xsl:attribute name="name">
							<xsl:choose>
								<xsl:when test="contains(../../../Name, 'https://')">
									<xsl:value-of select="concat(substring-after(../../../Name,'https://'), '_', 'info')"/>
								</xsl:when>
								<xsl:otherwise>
									<xsl:value-of select="concat(substring-after(../../../Name,'http://'), '_', 'info')"/>
								</xsl:otherwise>
							</xsl:choose>
						</xsl:attribute>
					</xsl:element>
					<xsl:value-of select="following-sibling::RiskDesc"/>
				</xsl:element>
			</xsl:element>

			<xsl:element name="td">
				<xsl:attribute name="class">info</xsl:attribute>
				<xsl:element name="div">
					<xsl:apply-templates select="text()"/>
				</xsl:element>
			</xsl:element>

			<xsl:element name="td">
				<xsl:attribute name="class">darkstyle</xsl:attribute>
				<xsl:attribute name="style">width: 3%; text-align:center; padding:0px;</xsl:attribute>
				<xsl:element name="div">
					<xsl:element name="a">
						<xsl:attribute name="href">#top</xsl:attribute>
						<xsl:text>Top</xsl:text>
					</xsl:element>
				</xsl:element>
			</xsl:element>
		</xsl:element>
	</xsl:template>

	<xsl:template match="Desc">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">
					<div>Description</div>
				</td>
				<td class="lightstyle">
					<pre>
						<xsl:apply-templates select="text()|*"/>
					</pre>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="Solution">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">
					<div>Solution</div>
				</td>
				<td class="lightstyle">
					<pre>
						<xsl:apply-templates select="text()|*"/>
					</pre>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="Reference">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">
					<div>Reference</div>
				</td>
				<td class="lightstyle">
					<xsl:apply-templates select="text()|*"/>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="CWEID">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">
					<div>CWE ID</div>
				</td>
				<td class="lightstyle">
					<xsl:apply-templates select="text()|*"/>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="WASCID">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">
					<div>WASC ID</div>
				</td>
				<td class="lightstyle">
					<xsl:apply-templates select="text()|*"/>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="ItemCount">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">
					<div>Instances</div>
				</td>
				<td class="lightstyle">
					<xsl:apply-templates select="text()|*"/>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>


	<xsl:template match="Item">
		<xsl:if test="text() !=''">
			<tr>
				<td>
					<div/>
				</td>
				<td class="lightstyle" style="padding:0px;">
					<table width="100%">
						<xsl:apply-templates select="text()|URI|Confidence|Param|Attack|Evidence|OtherInfo|RequestHeader|RequestBody|ResponseHeader|ResponseBody"/>
					</table>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="URI">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle" style="width: 15%;">				
					<div>URI</div>
				</td>
				<td class="lightstyle">	
					<xsl:apply-templates select="text()|*"/>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="Confidence">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">	
					<div>Confidence</div>
				</td>
				<td class="lightstyle">	
					<xsl:apply-templates select="text()|*"/>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="Param">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">	
					<div>Parameter</div>
				</td>
				<td class="lightstyle">	
					<xsl:apply-templates select="text()|*"/>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="Attack">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">	
					<div>Attack</div>
				</td>
				<td class="lightstyle">	
					<xsl:apply-templates select="text()|*"/>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="Evidence">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">	
					<div>Evidence</div>
				</td>
				<td class="lightstyle">	
					<xsl:apply-templates select="text()|*"/>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="OtherInfo">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">	
					<div>OtherInfo</div>
				</td>
				<td class="lightstyle">	
					<pre>
						<xsl:value-of select="text()|*" disable-output-escaping="no" />
					</pre>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="RequestHeader">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">	
					<div>RequestHeader</div>
				</td>
				<td class="lightstyle">	
					<pre>
						<xsl:value-of select="text()|*" disable-output-escaping="no" />
					</pre>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="RequestBody">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">	
					<div>RequestBody</div>
				</td>
				<td class="lightstyle">	
					<pre>
						<xsl:value-of select="text()|*" disable-output-escaping="no" />
					</pre>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="ResponseHeader">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">	
					<div>ResponseHeader</div>
				</td>
				<td class="lightstyle">	
					<pre>
						<xsl:value-of select="text()|*" disable-output-escaping="no" />
					</pre>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="ResponseBody">
		<xsl:if test="text() !=''">
			<tr>
				<td class="darkstyle">	
					<div>ResponseBody</div>
				</td>
				<td class="lightstyle">	
					<pre>
						<xsl:value-of select="text()|*" disable-output-escaping="no" />
					</pre>
				</td>
			</tr>
		</xsl:if>
	</xsl:template>

	<xsl:template match="br">
		<div>
			<br/>
		</div>
		<xsl:apply-templates/>
	</xsl:template> 	
</xsl:stylesheet>