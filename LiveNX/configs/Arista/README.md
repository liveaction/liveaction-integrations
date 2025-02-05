Arista IPFIX Configuration Details for LiveNX


•	All devices that support HW based monitoring will be configured accordingly.  Only the 7260, 7060 & 7050 models will have sample flow templates. Based on https://www.arista.com/en/support/product-documentation/supported-features

•	Our research states that both sflow and ipfix can't coexist, as a result, these configs disable sflow before adding ipfix.

•	For the 7260, 7060 & 7050, Sampled IPFIX Tracking has been configured.  

o	We’re starting with a sample rate of 1/1000

o	We can increase/decrease based on performance.

o	Sending the IPFIX templates once every 5 minutes.



•	7010T series switches are supported up to EOS version 4.28

o	Starting with EOS version 4.29, support for the 7010T series has been discontinued. 

o	The last available maintenance release for the 7010T series is EOS 4.28.10.1M. 

o	Arista will continue to provide software bug fixes and support for EOS 4.28 on the 7010T series until June 30, 2026.

o	7010T series switches are supported up to EOS version 4.28, and support for Sampled Flow Tracking with IPFIX export is not available in this version.

o	I created configs based on the chart at the top of the page for HW based IPFIX, but we need your validation for this model.


•	Notes:

o	Configs were built based on mix of best practice and data contained in EOS 4.33.1F User Manual

o	We would like a sample (PCAP) of your Postcard Telemetry so that we can explore supporting the additional telemetry from devices that support it.  It has been excluded from the current templates for performance benefits while we explore related options.
