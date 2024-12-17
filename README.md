# Proactive Discovery and Mitigation of Security Vulnerabilities Leveraged by Software-Defined Networks

The developed system orchestrates automated vulnerability analysis and mitigation through a Security Orchestration, Automation and Response (SOAR) platform, using a vulnerability scanner and applying a mitigation measure, demonstrating VLAN switching through the SDN controller, isolating vulnerable devices.

## Design

It was designed a system with the ideas from the previous section in mind to address some of the identified open issues. The next diagram illustrates the main building blocks and workflow that make up the designed system. It begins with the detection phase, in which the system continuously monitors network devices for vulnerabilities, using active probing tools. The vulnerabilities detected are classified using formats such as CVE, which standardizes the information and allows for easier comparison and prioritization. Once the vulnerabilities have been classified, the system moves on to the analysis phase, where the severity and risk associated with each vulnerability are assessed. This analysis helps to determine the most effective mitigation measure. Based on the results, the mitigation phase is triggered, where appropriate mitigation measures are implemented, such as isolating compromised devices through VLAN changes or blocking malicious traffic.

![screenshot](Figures/simple_flow.png)

The system’s architecture has several fundamental components described in the component diagram. It consists of two primary elements: the SOAR Server and the Security Tools Server. The SOAR Server hosts the SOAR Platform, while the Security Tools Server houses essential tools, including the Vulnerability Scanner and the Device Discovery Module.

![screenshot](Figures/components.png)

The Deployment Diagram is represented next. It provides an overview of how the logical components of the system, previously outlined, are deployed. It highlights the distribution of key services and applications, the interactions between them, and the communication protocols that are used. Components represented in blue have been created or their behavior modified.

![screenshot](Figures/deployment_diagram.png)

## Components 

Caso haja um erro com a socket do GVM podes tentar:
chmod 662 /var/run/gvmd/gvmd.sock


