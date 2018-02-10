<?xml version="1.0" encoding="UTF-8"?>
<!--
	Created By:	Goran Sarenkapa - JordanGS
	On:			March 10, 2016
	Uasge:		OWASP ZAP ExportReport Plugin
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output method="XML" version="1.0"  encoding="UTF-8" indent="YES" />
	<xsl:key name="KeyItem" match="AlertItem" use="concat(ancestor::Sites/Name, '|', PluginID)" />

	<xsl:template match="/Report">
		<Report>
			<xsl:copy-of select="@*" />
			<Title>
				<xsl:value-of select="Title"/>
			</Title>
			<For>
				<xsl:value-of select="For"/>
			</For>
			<By>
				<xsl:value-of select="By"/>
			</By>
			<ScanDate>
				<xsl:value-of select="ScanDate"/>
			</ScanDate>
			<ScanVersion>
				<xsl:value-of select="ScanVersion"/>
			</ScanVersion>
			<ReportDate>
				<xsl:value-of select="ReportDate"/>
			</ReportDate>
			<ReportVersion>
				<xsl:value-of select="ReportVersion"/>
			</ReportVersion>
			<Desc>
				<xsl:value-of select="Desc"/>
			</Desc>
			<xsl:for-each select="Sites">
				<Sites>
					<xsl:copy-of select="@*" />
					<Host>
						<xsl:value-of select="Host"/>
					</Host>
					<Name>
						<xsl:value-of select="Name"/>
					</Name>
					<Port>
						<xsl:value-of select="Port"/>
					</Port>
					<SSL>
						<xsl:value-of select="SSL"/>
					</SSL>
					<Alerts>
						<xsl:for-each select="Alerts/AlertItem[generate-id() = generate-id(key('KeyItem', concat(ancestor::Sites/Name, '|', PluginID))[1])]">  
							<xsl:sort select="RiskCode" data-type="number" order="descending"/>
							<xsl:sort select="Alert"/>
							
							<AlertItem>
								<!-- RiskCode: Not Visible ......... -->
								<Alert>
									<xsl:value-of select="Alert"/>
								</Alert>
								<RiskCode>
									<xsl:value-of select="RiskCode"/>
								</RiskCode>
								<!-- PluginID: Not Visible ......... -->
								<PluginID>
									<xsl:value-of select="PluginID"/>
								</PluginID>
								<!-- ............................... -->
								<RiskDesc>
									<xsl:value-of select="RiskDesc"/>
								</RiskDesc>
								<Desc>
									<xsl:value-of select="Desc"/>
								</Desc>
								<Solution>
									<xsl:value-of select="Solution"/>
								</Solution>
								<Reference>
									<xsl:value-of select="Reference"/>
								</Reference>
								<ItemCount>
									<xsl:value-of select="count(key('KeyItem', concat(ancestor::Sites/Name, '|', PluginID)))"/>
								</ItemCount>
								<xsl:for-each select="key('KeyItem', concat(ancestor::Sites/Name, '|', PluginID))">
									<Item>
										<URI>
											<xsl:value-of select="URI"/>
										</URI>
										<Confidence>
											<xsl:value-of select="Confidence"/>
										</Confidence>
										<Param>
											<xsl:value-of select="Param"/>
										</Param>  
										<Attack>
											<xsl:value-of select="Attack"/>
										</Attack>          
										<Evidence>
											<xsl:value-of select="Evidence"/>
										</Evidence>
										<OtherInfo>
											<xsl:value-of select="OtherInfo"/>
										</OtherInfo>
										<RequestHeader>
											<xsl:value-of select="RequestHeader"/>
										</RequestHeader>
										<RequestBody>
											<xsl:value-of select="RequestBody"/>
										</RequestBody>
										<ResponseHeader>
											<xsl:value-of select="ResponseHeader"/>
										</ResponseHeader>
										<ResponseBody>
											<xsl:value-of select="ResponseBody"/>
										</ResponseBody>
									</Item>
								</xsl:for-each>
								<CWEID>
									<xsl:value-of select="CWEID"/>
								</CWEID>
								<WASCID>
									<xsl:value-of select="WASCID"/>
								</WASCID>
							</AlertItem>
						</xsl:for-each>
					</Alerts>
				</Sites>
			</xsl:for-each>
		</Report>
	</xsl:template>
</xsl:stylesheet>