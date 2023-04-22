# vuln_nessus_essentials_prioritization
Vulnerability Prioritization of Nessus Essentials Scan report CSV using CISA Known Vulnerability List and Exploit DB

Introduction
---------------------

Vulnerability Prioritization is very much important and it eliminates a lot of time to fix what. It's always highly recommended to use standard reference to determine which vulnerabilities needs to be fixed prefererably. Here We have leveraged CISA known Vulnerability List to do look up against the Nessus Essential Scan report (Csv Format) to develop a dashboard based on Simple Python Dash Table.

Steps Execution
------------------------------

1) Download the Script in the folder where the Nessus Essential Scan report for host is present.

2) Do Install dependencies using pip install -r requirements.txt

3) Run -: python vulnpriority.py 

Dashboard will be generated as per below image -:

![image](https://user-images.githubusercontent.com/60708289/233787505-ab57fc0e-8fa5-413f-8a35-eb6fee9e15e3.png)

