# BOTS v1 APT Walkthrough: Step-by-Step Investigation

This walkthrough follows the investigation in the order an analyst would work it: from first signs of scanning, through the brute force and compromise, to the OSINT pivots. Each step has the reasoning, the SPL, and a screenshot.



---

## Step 0: Orient Yourself in the Data

Before answering anything, see what exists. This avoids guessing field names later.

```spl
index=botsv1 earliest=0
| stats count by sourcetype
| sort - count
```

**Why:** Shows which sources are available (`stream:http`, `suricata`, `iis`, `fgt_utm`, Sysmon, and so on). Web attack questions point to `stream:http`; endpoint questions point to Sysmon.

![Sourcetype overview](../screenshots/sourcetypes.png)

---


### Q101: What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

**Approach:** The target domain is named in the question, so search web traffic for it and count requests per source IP. A scanner generates far more requests than a normal visitor.

```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com
| stats count by src_ip
| sort - count
```

**Answer:** `40.80.148.42` is the top source by request volume.

![Q101](../Screenshot/source_ip.png)

### Q102: What company created the web vulnerability scanner used by Po1s0n1vy?

**Approach:** Narrow to the suspect IP and inspect the raw HTTP events (headers, request paths) for a tool signature.

```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com scanning src_ip="40.80.148.42"
```

**Finding:** The traffic identifies the scanner as **Acunetix**, so the company is Acunetix.

![Q102](../Screenshot/Company_name.png)

### Q103: What content management system is imreallynotbatman.com likely using??

**Approach:** Look at the URIs the scanner and visitors requested. CMS platforms have recognisable path structures.

```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com scanning src_ip="40.80.148.42"
```

**Finding:** **Joomla**.


![Q103](../Screenshot/Content_management_system.png)

**Phase takeaway:** One IP generating high-volume automated requests is the reconnaissance stage.

### Q104: What is the name of the file that defaced the imreallynotbatman.com website?




### Q105: This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?







### Q109: What is the name of the executable uploaded by Po1s0n1vy?

**Approach:** Executables running on the server show up in Sysmon process creation events. Search Sysmon for the attacker IP and `exe`.

```spl
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" 23.22.63.114 exe
```

**Finding:** `3791.exe`.

![Q109](../Screenshot/Executable_file.png)




