\# Sigma Rule-to-Telemetry Matrix



\## Purpose



This document maps candidate Sigma rules to their telemetry requirements and identifies the capabilities needed by the synthetic-data framework. Rule selection and feasibility remain provisional until validated through implementation and testing.



\## Inspected Rules



\### 1. Renamed PowerShell Under PowerShell Channel



\- Rule ID: `30a8cb77-8eb3-4cfb-8e79-ad457c5a4592`

\- Log source: Windows `ps\_classic\_start`

\- Relevant ATT\&CK techniques: T1059.001, T1036.003

\- Required data: PowerShell Classic event `Data` containing host and application information.

\- Framework requirements: Represent PowerShell Classic events and preserve the raw or normalized event data required by the rule.

\- Limitation: Process-creation events alone do not establish compatibility with this rule.



\### 2. Potential WMI Lateral Movement — WmiPrvSE Spawned PowerShell



\- Rule ID: `692f0bec-83ba-4d04-af7e-e884a96059b6`

\- Log source: Windows process creation

\- Relevant ATT\&CK techniques: T1047, T1059.001

\- Required data: `ParentImage`, and `Image` or `OriginalFileName`.

\- Framework requirements: Preserve process identity and parent-child relationships.

\- Limitation: The rule includes documented potential false positives.



\### 3. Renamed Visual Studio Code Tunnel Execution



\- Rule ID: `2cf29f11-e356-4f61-98c0-1bdb9393d6da`

\- Log source: Windows process creation

\- Relevant ATT\&CK techniques: T1071.001, T1219

\- Required data: `CommandLine`, `Image`, `OriginalFileName`, and parent-process fields for applicable detection branches.

\- Framework requirements: Represent command-line arguments, executable metadata, parent processes and missing-field cases.

\- Limitation: The rule contains multiple selection branches and exclusions that must be evaluated according to its exact condition.



\### 4. Potential PowerShell Execution Via DLL



\- Rule ID: `6812a10b-60ea-420c-832f-dfcc33b646ba`

\- Log source: Windows process creation

\- Relevant ATT\&CK tag: T1218.011

\- Required data: `Image` or `OriginalFileName`, plus `CommandLine`.

\- Framework requirements: Represent executable metadata and command-line fields and implement the rule's exact matching condition.

\- Limitation: The rule assumes relevant PowerShell commands appear in the command line.



\### 5. Cscript/Wscript Potentially Suspicious Child Process



\- Rule ID: `b6676963-0353-4f88-90f5-36c20d443c6a`

\- Log source: Windows process creation

\- Relevant ATT\&CK tag: `attack.execution`

\- Required data: `ParentImage`, `Image`, and `CommandLine` for applicable detection branches.

\- Framework requirements: Represent process ancestry, command-line indicators and rule-specific exclusions.

\- Limitation: The rule documents possible false positives from administrative and third-party software.



\## Cross-Cutting Requirements



1\. Maintain distinct event-source definitions.

2\. Define a canonical event schema and explicit source-to-canonical field mappings.

3\. Preserve process identifiers, parent-child relationships, timestamps and provenance wherever supported.

4\. Record required, optional and unavailable fields.

5\. Evaluate Sigma conditions and exclusions using the actual rule semantics.

6\. Distinguish a rule match from proof of malicious activity.

7\. Validate generated events independently of Sigma matching.

8\. Record the rule version or source commit used in each experiment.



\## Open Questions



\- Which Windows event sources will be enabled in the isolated reference VM?

\- Which canonical fields can the simulator produce reliably?

\- Which rules can be evaluated directly, and which require additional telemetry?

\- What reference events are available for independent comparison?



\## Status



Initial rule analysis complete. Event-source feasibility, field mappings and detection behaviour remain to be implemented and tested.

