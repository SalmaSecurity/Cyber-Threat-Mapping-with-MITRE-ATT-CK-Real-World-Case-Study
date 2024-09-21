# Cyber-Threat-Mapping-with-MITRE-ATT-CK-Real-World-Case-Study

## Objective  
This project aims to map real-world cyber threats to the **MITRE ATT&CK framework**, focusing initially on a **narrative report** and later on analyzing **security logs**. By combining thorough threat analysis with automation, we streamline the process of identifying and classifying adversary tactics and techniques. Additionally, the project provides a breakdown of the **MITRE ATT&CK framework**, emphasizing its importance in **defensive strategies** for cybersecurity professionals.

## What is MITRE ATT&CK ?

The first question that comes to mind is: What is **MITRE ATT&CK**?  
MITRE ATT&CK is a comprehensive framework developed by the non-profit organization **MITRE** in 2013. It is based on real-world observations of adversary tactics, techniques, and procedures (TTPs) used in cyberattacks. The framework provides a structured way to document and understand the behavior of cyber adversaries, this helps cybersecurity teams anticipate, detect, and respond to threats more effectively.

## How It Works

**ATT&CK** is an open framework available to anyone at no charge via [attack.mitre.org](https://attack.mitre.org). It provides various features that help organizations and individuals understand adversary behavior in detail.

### 1. ATT&CK Matrices

**ATT&CK** offers three different matrices: **Enterprise**, **Mobile**, and **ICS (Industrial Control Systems)**. These matrices display adversary tactics and techniques in a structured manner.

- **ATT&CK Enterprise**: This matrix covers tactics and techniques for platforms such as Windows, macOS, Linux, PRE, Azure AD, Office 365, Google Workspace, SaaS, IaaS, Networks, and Containers.
- **ATT&CK ICS**: Focuses on Industrial Control Systems, often used in critical infrastructure environments.
- **ATT&CK Mobile**: This matrix covers adversarial techniques involving device access and network-based effects for platforms such as Android and iOS.

#### What are Tactics and Techniques?

- **Tactic (the why)**: This represents the adversary's goals or strategic objectives. Examples include:
  - **Initial Access**: Gaining entry into the target.
  - **Persistence**: Maintaining access to the target.
  - **Privilege Escalation**: Gaining higher-level permissions on the target.

- **Technique (the how)**: Each tactic consists of various techniques that describe the specific methods used to achieve these goals. For example:
  - The **Initial Access** tactic can be achieved using **phishing** (technique) via **spear phishing** (sub-technique of phishing).

### 2. MITRE Groups

MITRE ATT&CK tracks clusters of activity associated with specific **threat actors** known as "groups." For example:
- **ANDARIAL**: A known adversary group whose tactics and techniques are mapped and can be viewed on ATT&CK.

## What is the Importance of Knowing and Using MITRE ATT&CK?

1. **Enhanced Threat Intelligence**: ATT&CK provides a comprehensive repository of adversary tactics and techniques, enabling organizations to better understand the methods employed by threat actors.

2. **Improved Detection and Response**: By mapping known techniques to their detection capabilities, security teams can enhance their monitoring and incident response strategies, leading to quicker and more effective mitigations.

3. **Proactive Defense Strategies**: Knowledge of ATT&CK allows organizations to anticipate potential threats and implement measures to defend against specific tactics that adversaries may employ.

4. **Standardized Language**: ATT&CK offers a common language for discussing adversary behavior, facilitating communication between security teams, threat analysts, and stakeholders.

5. **Training and Awareness**: The framework serves as a valuable resource for training security personnel, helping them to recognize and respond to tactics used in real-world attacks.

6. **Assessment and Improvement**: Organizations can use ATT&CK to assess their security posture, identify gaps in defenses, and prioritize improvements based on real-world threat intelligence.

## What is Mapping and Why is It Important?

**Mapping** in the context of the MITRE ATT&CK framework involves correlating observed adversary behaviors—whether from narrative reports or security logs—to specific tactics and techniques within the framework. This process helps organizations understand how actual attacks align with known adversary behaviors.

### Importance of Mapping

1. Povides a clear view of how threats manifest in the real world, allowing organizations to better prepare for similar attacks.

2. Identify areas where defenses may be lacking and prioritize improvements accordingly.

3. Understanding the tactics and techniques relevant to their environment enables organizations to make informed decisions about security tools and technologies to invest in.

4. Mapping historical incidents helps security teams refine their incident response plans, ensuring they are better prepared for future attacks that employ similar techniques.

5. Proactively seek indicators of compromise (IOCs) associated with specific techniques.

## How to Map to ATT&CK from Narrative Reports?

The first part of this project focuses on mapping cyber threat activity to the MITRE ATT&CK framework using narrative reports. For this purpose, we have selected a real-world case study, the **"STATIC KITTEN Adversary"**, taken from the **CrowdStrike 2024 Threat Hunting Report** (pages 31-35). You can access the report [here](https://www.crowdstrike.com/resources/reports/threat-hunting-report/).

In the following sections, we will analyze this case in detail and map the observed adversary tactics, techniques, and procedures (TTPs) to the relevant ATT&CK framework categories, following the four steps mentioned previously.
















