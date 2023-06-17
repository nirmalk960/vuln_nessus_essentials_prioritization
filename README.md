# vuln_prioritization
Vulnerability Prioritization of Nessus Essentials Scan report CSV & Openvas Scan report CSV using CISA Known Vulnerability List and First EPSS Score 

Introduction
---------------------

Vulnerability Prioritization is very much important and it eliminates a lot of time to fix what. It's always highly recommended to use standard reference to determine which vulnerabilities needs to be fixed prefererably. 

Here We have leveraged 
a) CISA known Vulnerability (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

b) Exploit Prediction Scoring System (EPSS) is a data-driven effort for estimating the likelihood (probability) that a software vulnerability will be exploited in the wild. Our goal is to assist network defenders to better prioritize vulnerability remediation efforts. While other industry standards have been useful for capturing innate characteristics of a vulnerability and provide measures of severity, they are limited in their ability to assess threat. EPSS fills that gap because it uses current threat information from CVE and real-world exploit data. The EPSS model produces a probability score between 0 and 1 (0 and 100%). The higher the score, the greater the probability that a vulnerability will be exploited. 
https://www.first.org/epss/

List to do look up against the Nessus Essential Scan report (Csv Format) to develop a dashboard based on Simple Python Dash Table.

Steps Execution
------------------------------

1) Download the Script in the folder name nessus where the Nessus Essential Scan report for host is present and also similarly in the folder name openvas where the openvas report is present

2) Do Install dependencies using pip install -r requirements.txt

3) Run -: **'python vulnpriority_nessus.py'** for Nessus Essentials

4) Run -: **'python vulnpriority_openvas.py'** for Openvas

Dashboard will be generated as per below image for Nessus Essentials -:

![image](https://github.com/nirmalk960/vuln_nessus_essentials_prioritization/assets/60708289/f87b9135-a64e-4490-90ec-6ed8d53bd568)

Dashboard will be generated as per below image for Openvas -:

![image](https://github.com/nirmalk960/vuln_nessus_essentials_prioritization/assets/60708289/0d03f8c7-f140-40e1-aff4-4b48c65b0771)



