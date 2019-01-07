-- Head
-- Required NSE libraries

local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local http = require "http"
local json = require "json"

description = [[

This script [Version 1.0.2] allows you to automatically search for CVEs using the API of 
https://www.circl.lu/services/cve-search/ in connection with the found CPEs
using the parameter -sV in NMAP.

This script is part of the FreeOCSAF Project - https://freecybersecurity.org.
Use only with legal authorization and at your own risk! ANY LIABILITY WILL BE REJECTED!

Thanks to cve-search.org and circl.lu for the ingenious api 
and special thanks to the community for many useful ideas that speed up my coding!

Realized functions:
Version 1.0 - Contains the basic functions to quickly find relevant CVEs.
Version 1.0.1 - Includes EDB and MSF in output and minor changes.
Version 1.0.2 - Special CPE formatting and output optimization.

Future functions:
Version 1.1 - Shall contains optional sort by severity (CVSS)
Version 2.0 - Shall support optional the offline DB of cve-search.org.
Version 3.0 - Implementation of your useful ideas.

Usage:
nmap -sV --script freevulnsearch <target>

Output explanation:
CVE-Number	CVSS	OSSTMM	 CVE-Link

CVE-Number:
Common Vulnerabilities and Exposures

OSSTMM:
OSSTMM Category derived from CVSS
Vulnerability (CVSS 8.0 - 10.0)
Weakness (CVSS 6.0 - 7.9)
Concerns (CVSS 4.0 - 5.9)
Exposure (CVSS 2.0 - 3.9)
Information (CVSS 0.0 - 1.9)

CVSS:
Common Vulnerability Scoring System with with the level of severty from 0.0 - 10.0

EDB:
There is an exploit in the Exploit-DB.com

MSF:
There is a module in the Metasploit Framework

CVE-Link:
Additional information on the vulnerability found.

]]

author = "Mathias Gut"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "vuln", "external"}

-- @usage 
-- nmap -sV --script freevulnsearch [--script-args cvss=<min_cvss_value>] <target>
--
-- @output
--
-- 22/tcp   open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
-- | freevulnsearch: 
-- |   CVE-2018-15473	Concerns	5.0	EDB MSF	https://cve.circl.lu/cve/CVE-2018-15473
-- |   CVE-2017-15906	Concerns	5.0		https://cve.circl.lu/cve/CVE-2017-15906
-- |   CVE-2016-10708	Concerns	5.0		https://cve.circl.lu/cve/CVE-2016-10708
-- |   CVE-2010-4755	Concerns	4.0		https://cve.circl.lu/cve/CVE-2010-4755
-- |   CVE-2010-4478	Weakness	7.5		https://cve.circl.lu/cve/CVE-2010-4478
-- |   CVE-2008-5161	Exposure	2.6		https://cve.circl.lu/cve/CVE-2008-5161
-- |_  (cpe:/a:openbsd:openssh:4.7p1)
--


-- Portrule

-- The table port.version contains the CPEs

portrule = function(host, port)
	local portv=port.version
	return portv ~= nil and portv.version ~= nil
end



-- Function to check for CPE correct version.
function func_check_cpe(cpe)
	
	_, count = string.gsub(cpe, ":", " ")
    	if count >= 4 then
	    	return cpe
    	else
	    	return 0
    	end
end

-- Function to check for special CPE formatting.
function func_check_cpe_form(cpe)
	
	local cpe_form
	local sub_form1
	local sub_form2
	local sub_form3
	local cpe_front
	local cpe_version
    	
	_, count = string.gsub(cpe, "-", " ")
	_, count2 = string.gsub(cpe, "%a%d", " ")

    	if count ~= 0 then
		cpe_form = string.gsub(cpe,"-.*","")
	    	return cpe_form
    	elseif count2 ~= 0 then
		sub_form1 = string.gsub(cpe,".*:",":")
		sub_form2 = string.gsub(sub_form1,"%a.*","")
		sub_form3 = string.gsub(sub_form1,sub_form2,"")
		cpe_version = sub_form2 .. ":" .. sub_form3
		cpe_front = string.gsub(cpe,sub_form1,"")
		cpe_form = cpe_front .. cpe_version
		return cpe_form
	else
		return 0
    	end
end
 
-- Function to query CVEs via CPEs with API (circl.lu).
function func_check_cve(cpe)
	
	local url = "https://cve.circl.lu/api/cvefor/"
	local response
	local request
	local status
	local vulnerabilities

	request = url .. cpe

	response = http.get_url(request)
	
	status, vulnerabilities = json.parse(response.body)

	if status ~= true then
		return 1
	elseif type(next(vulnerabilities)) == "nil" then
		return 2
	elseif (status == true and vulnerabilities ~= "") then
		return func_output(vulnerabilities)
	else	
		return 2
	end

end

-- Function to generate the script output.
function func_output(vulnerabilities)
	
	local output_table = {}
	local input_table = {}
	local cve_url= "https://cve.circl.lu/cve/"
	local cve_value
	local cvss
	local cvss_value
	local osstmm_value
	local url_value
	local edb
	local msf
	local exploit
	local i
	local t

	for i,t in ipairs(vulnerabilities) do
 		cve_value = t.id
		cvss = tonumber(t.cvss)
 		url_value = cve_url .. t.id
		edb = t["exploit-db"]
		msf = t.metasploit

		if not cvss then
			cvss_value = ""
			osstmm_value = ""
		else
 			cvss_value = cvss	
			osstmm_value = func_osstmm(cvss)
		end

		if not edb and not msf then
			exploit = ""
		elseif edb and not msf then
			exploit = "EDB"
		elseif not edb and msf then
			exploit = "MSF"
		elseif edb and msf then
			exploit = "EDB MSF"
		end

		output_table = cve_value .. "\t" .. osstmm_value .. "\t" .. cvss_value .. "\t" .. exploit .. "\t" .. url_value
		input_table[i] = output_table 	
	end
                       
	return input_table
end          

-- Function to assign CVSS values to OSSTMM categories
function func_osstmm(cvss)

	if (1.9 >= cvss and cvss >= 0.0) then
		return "Information"
	elseif (3.9 >= cvss and cvss >= 2.0) then
		return "Exposure"
	elseif (5.9 >= cvss and cvss >= 4.0) then
		return "Concerns"
	elseif (7.9 >= cvss and cvss >= 6.0) then
		return "Weakness"
	elseif (10.0 >= cvss and cvss >= 8.0) then
		return "Vulnerability"
	end
end


-- Action
-- Main-Function
action = function(host, port)
    	
	local cpe=""
	local check
	local sort_values
	local form_cpe
	local i

	for i, cpe in ipairs(port.version.cpe) do
		check = func_check_cpe(cpe)
		if check ~= 0 then
			sort_values = func_check_cve(check)
			if sort_values == 1 then
				return "Error with API query. API or network possibly not available."
			elseif sort_values == 2 then
				form_cpe = func_check_cpe_form(check)
				if form_cpe == 0 then
					return "\n  No CVEs found with CPE: [" .. check .. "]" .. "\n  Check other sources like https://www.exploit-db.com"
				else
					sort_values = func_check_cve(form_cpe)
					if sort_values == 2 then
						return "\n  No CVEs found with CPE: [" .. check .. "]" .. "\n  Check other sources like https://www.exploit-db.com"
					else
						table.sort(sort_values, function(a, b) return a>b end) --funktioniert
						table.insert(sort_values, "(" .. form_cpe .. ")")
						return sort_values
					end
				end
			else
				table.sort(sort_values, function(a, b) return a>b end) --funktioniert
				table.insert(sort_values, "(" .. check .. ")")
				return sort_values
			end
		elseif check == 0 then
			return "\n  Check unspecific version manually: [".. cpe .. "]"
		end
	end
end