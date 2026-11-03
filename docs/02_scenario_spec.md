\# Scenario Specification and Ground-Truth Labeling Rules



\*\*Project:\*\* Synthetic Windows Attack Telemetry Generation  

\*\*Version:\*\* 0.1  

\*\*Status:\*\* Initial implementation specification



\## 1. Purpose



This document defines the initial attack scenario templates, simulator actions, and ground-truth labeling rules for the synthetic Windows telemetry framework.



The simulator will generate coherent process events with explicit relationships between processes and actions. Labels will be derived from the scenario's known actions rather than inferred from the generated event text.



The initial scope focuses on process-creation telemetry and the five Sigma rules already analyzed in the project.



\## 2. Scope



\### Included



\- Simulated Windows hosts, users, and running processes

\- Process creation and parent-child relationships

\- Attack actions with preconditions and effects

\- Event generation through the canonical event factory

\- Scenario and action provenance

\- Ground-truth labels derived from action-to-technique mappings

\- Positive and negative scenario variants

\- Chronology and process-tree validation

\- Sigma evaluation against generated events



\### Initially excluded



\- Real malware execution

\- Real Windows system modification

\- Network packet simulation

\- Full Windows registry or file-system emulation

\- LLM-generated actions

\- Adaptive attack execution



These capabilities may be added in later stages.



\## 3. Scenario Templates



\### S1 — Renamed PowerShell Execution



\*\*Objective:\*\* Generate telemetry for PowerShell executed under a renamed executable.



\*\*Action sequence:\*\*



1\. Initialize a simulated Windows host and user.

2\. Start a renamed PowerShell executable.

3\. Record its process-creation event.

4\. Preserve the executable's original filename where available.



\*\*Expected event chain:\*\*



`user → renamed PowerShell process`



\*\*Primary technique:\*\* T1059.001 — PowerShell



\*\*Detection target:\*\* Renamed PowerShell detection rule.



\*\*Negative variant:\*\* Start a benign executable with no PowerShell-related characteristics.



\### S2 — WMI-Spawning PowerShell



\*\*Objective:\*\* Simulate PowerShell launched by a WMI provider process.



\*\*Action sequence:\*\*



1\. Initialize a host and user.

2\. Start `WmiPrvSE.exe`.

3\. Spawn a PowerShell child process from the WMI process.

4\. Record both process-creation events.



\*\*Expected event chain:\*\*



`WmiPrvSE.exe → powershell.exe`



\*\*Techniques:\*\*

\- T1047 — Windows Management Instrumentation

\- T1059.001 — PowerShell



\*\*Detection target:\*\* WMI spawning PowerShell.



\*\*Negative variant:\*\* WMI starts a benign child process.



\### S3 — Renamed VS Code Tunnel



\*\*Objective:\*\* Simulate a renamed executable associated with VS Code tunnel activity.



\*\*Action sequence:\*\*



1\. Initialize a host and user.

2\. Start a renamed VS Code tunnel executable.

3\. Record its process-creation event and relevant executable metadata.



\*\*Expected event chain:\*\*



`user → renamed VS Code tunnel process`



\*\*Technique:\*\* T1219.001 — Remote Access Software



\*\*Detection target:\*\* Renamed VS Code tunnel rule.



\*\*Negative variant:\*\* Start a benign executable with no tunnel-related characteristics.



\### S4 — PowerShell Execution Through a DLL



\*\*Objective:\*\* Simulate a PowerShell-related process execution pattern involving a DLL.



\*\*Action sequence:\*\*



1\. Initialize a host and user.

2\. Start the required host process.

3\. Record the process command line and relevant DLL-related arguments.

4\. Preserve parent-child relationships.



\*\*Expected event chain:\*\*



`host process → PowerShell-related execution`



\*\*Technique:\*\* T1059.001 — PowerShell



\*\*Detection target:\*\* PowerShell execution via DLL rule.



\*\*Negative variant:\*\* Start a normal host process without the suspicious DLL-related execution pattern.



\### S5 — WScript or CScript Child Process



\*\*Objective:\*\* Simulate a script-host process spawning a child process.



\*\*Action sequence:\*\*



1\. Initialize a host and user.

2\. Start `wscript.exe` or `cscript.exe`.

3\. Spawn a child process.

4\. Record both events and their parent-child relationship.



\*\*Expected event chain:\*\*



`wscript.exe / cscript.exe → child process`



\*\*Technique:\*\* T1059.005 — Visual Basic



\*\*Detection target:\*\* Suspicious WScript/CScript child process rule.



\*\*Negative variant:\*\* A script host starts a benign child process that does not match the detection rule.



> The scenario's technique mapping represents the intended simulated behavior. It does not claim that every process launch using these names is malicious.



\## 4. Simulator Actions



The simulator will initially support the following primitive actions.



| Action | Preconditions | Effect |

|---|---|---|

| `initialize\_host` | Host does not already exist | Creates host and user state |

| `start\_process` | Host exists; executable is specified | Creates process and emits event |

| `spawn\_child` | Parent process exists and is running | Creates child and emits event |

| `terminate\_process` | Process exists and is running | Marks process as terminated |

| `create\_scheduled\_task` | Host and task definition exist | Creates simulated task state |

| `execute\_scheduled\_task` | Task exists | Starts configured process |



Every action receives a unique `action\_id` and belongs to a `scenario\_id`.



Each action must have explicit preconditions and effects. Invalid actions must fail rather than silently generating inconsistent telemetry.



\## 5. Ground-Truth Labeling



\### 5.1 Action-to-Technique Mapping



Each scenario action may map to zero or more MITRE ATT\&CK techniques.



Example:



| Action | Technique |

|---|---|

| PowerShell execution | T1059.001 |

| WMI-based process launch | T1047 |

| Remote access software execution | T1219.001 |

| VBScript execution | T1059.005 |



The mapping is stored as scenario/action metadata. It is not inferred from the event's command line.



\### 5.2 Event-Level Labels



Each event receives labels derived from the action that produced it.



Rules:



1\. Every event must have a `scenario\_id` and `action\_id` in provenance.

2\. Every labeled event must trace to a known simulator action.

3\. Technique labels are derived from the action-to-technique mapping.

4\. Benign actions receive no attack-technique labels.

5\. A process event must not inherit a technique label merely because its parent has that label.

6\. If an action maps to multiple techniques, the event may contain multiple labels.



\### 5.3 Scenario-Level Labels



Scenario-level labels describe the complete scenario.



They include:



\- Scenario template identifier

\- Intended attack techniques

\- Whether the scenario is benign or attack-oriented

\- Expected Sigma rules

\- Expected detection outcome



These labels are stored in scenario metadata, not copied blindly to every event.



\### 5.4 Triage Labels



Triage labels describe the event or scenario from a detection perspective.



Initial categories:



\- `malicious`

\- `benign`

\- `suspicious`

\- `needs\_review`



Triage labels are distinct from ATT\&CK technique labels. A technique label describes behavior; a triage label describes the security interpretation.



\## 6. Provenance Requirements



Each generated event must include:



\- `origin = synthetic`

\- `scenario\_id`

\- `action\_id`

\- `generator\_version`

\- `parent\_event\_ids`, where applicable



The `run\_id` identifies one complete simulator execution.



A provenance validator must verify that:



1\. Every event references an existing scenario.

2\. Every event references an action in that scenario.

3\. Every labeled event has a valid action-to-technique mapping.

4\. Parent event references exist.

5\. Parent-child process relationships are consistent.



\## 7. Chronology and Process-Tree Rules



The simulator and validators must enforce the following:



\- Every process has a unique process identifier within its host.

\- A child process cannot be created before its parent exists.

\- A child process cannot reference a nonexistent parent.

\- A process cannot be its own parent.

\- Parent and child events must belong to the same host.

\- Child creation timestamps must not precede parent creation timestamps.

\- Event timestamps must be non-decreasing within a process chain.

\- Events from independent chains may be interleaved.

\- Invalid process trees must fail validation.



\## 8. Sigma Evaluation Scope



The initial Sigma evaluator supports the subset required by the selected rules:



\- `endswith`

\- `contains`

\- `contains|all`

\- Null checks

\- Lists as OR

\- `and`, `or`, and `not` conditions



The evaluator must reject unsupported Sigma syntax explicitly rather than silently interpreting it incorrectly.



Each evaluation produces:



\- `rule\_id`

\- `matched`

\- `evaluator\_version`

\- `reason`



The initial tests must include positive and negative events for each selected rule.



\## 9. Acceptance Criteria



The initial simulator milestone is complete when:



1\. Each scenario template can execute without an LLM.

2\. Every action produces the expected simulator state change.

3\. Every generated event validates against the canonical schema.

4\. Every event has traceable provenance.

5\. Ground-truth labels are derived from action mappings.

6\. Process trees and timestamps pass structural validation.

7\. Deliberately invalid process trees fail validation.

8\. The scenario runner can serialize output as JSONL.

9\. Sigma evaluation produces expected results for hand-built positive and negative examples.

10\. A demo script runs at least one attack scenario and one benign scenario.



\## 10. Implementation Order



1\. Implement simulator state.

2\. Implement primitive actions.

3\. Implement action-to-technique mapping and label derivation.

4\. Implement provenance generation.

5\. Implement scenario runner.

6\. Implement chronology and process-tree validators.

7\. Implement Sigma evaluator.

8\. Add scenario integration tests.

9\. Produce the first generated JSONL dataset.



