# 🛡️ Suspicious Job Offer OSINT Investigation

This repository documents a real-world OSINT (Open-Source Intelligence) investigation into a suspicious job offer I received via LinkedIn from a recruiter claiming to represent a company called **DataAnnotation**. The objective was to determine the legitimacy of the offer using publicly available tools and threat intelligence techniques.

---

## 📌 Summary

On June 15, 2025, I received a message from someone named *Phoebe R.*, allegedly recruiting for “DataAnnotation.” The offer raised several red flags, prompting a deeper analysis. Although the site itself wasn't flagged as malicious by security tools, the behavioral and structural indicators were concerning.<br><br>
![Screenshot1](https://i.imgur.com/Z0XVhiu.png)


---

## 🚩 Red Flags Identified

- **Too good to be true**: Promised $1,000+ per week, no experience required, and full flexibility.
- **Unverifiable recruiter identity**: The LinkedIn profile was unclickable and lacked any confirmed work history.
- **Suspicious company presence**: The company's LinkedIn page had only 3 posts, no engagement, and comments were disabled — all unusual for a real employer.

---

## 🧠 Threat Mapping (MITRE ATT&CK)

This activity could align with:

- **T1566.003 – Spearphishing via Service**  
  > The attacker may use a third-party service (LinkedIn) to deliver the phishing message.<br><br>
  ![Screenshot2](https://i.imgur.com/PKBrkz6.png)

---

## 🛠️ Tools Used

[VirusTotal](https://virustotal.com) <br><br>
![Screenshot3](https://i.imgur.com/SUhy5bV.png)<br><br>
[urlscan.io](urlscan.io) <br><br>
![Screenshot4](https://i.imgur.com/9QAvScc.png)
[WHOIS Lookup](https://www.whois.com/) <br><br>
![Screenshot5](https://i.imgur.com/2BNnjW5.png)<br><br>
[MITRE ATT&CK Framework](https://attack.mitre.org/techniques/T1566/003/)

---

## 🔍 Analysis Goals

- Assess the credibility of the recruiter
- Verify the legitimacy of the company and job offer
- Identify any behavioral patterns consistent with phishing or social engineering

---

## ✅ Conclusion

While no direct malware or malicious content was detected at the time of analysis, several **social engineering indicators** suggest this is likely a **phishing attempt**. The use of high-paying, low-effort job offers and unverifiable digital presence are hallmarks of this kind of scam.

> **Advice**: Always verify job offers via official channels (e.g., company websites or trusted recruiter emails), and be skeptical of anything that sounds too good to be true.

---

## 📝 Disclaimer

This investigation is based on publicly available information and personal research. It is intended for **cybersecurity education and awareness only**. No accusations are being made against any individuals or entities.

---

## 📎 Original LinkedIn Post

[🔗 Read the LinkedIn post](https://www.linkedin.com/posts/mohamed-alhabib-gharbi_cybersecurity-osint-threatintel-activity-7339950976159621120-0pR6?utm_source=share&utm_medium=member_desktop&rcm=ACoAADw17dYBC_BwCwVpyKu4ICGTpemvNLDJoAI)

---

## 📚 Tags

`#CyberSecurity` `#OSINT` `#ThreatIntel` `#MITREATTACK` `#Phishing` `#CyberSecurityAwareness`
