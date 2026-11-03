\# Canonical Event Schema Specification



\## 1. Purpose



Define a consistent event representation for synthetic Windows security telemetry. The schema must support scenario generation, event rendering, provenance tracking, structural validation, chronology checks, process-tree validation, Sigma evaluation and comparison with reference telemetry.



The schema must preserve source-specific information rather than forcing every event source into an identical structure.



\## 2. Design Principles



\- Preserve the original source event wherever available.

\- Separate canonical fields from source-specific fields.

\- Represent missing, unavailable and not-applicable fields distinctly where feasible.

\- Use consistent timestamp formats and explicit timezone handling.

\- Preserve event provenance and links to the scenario and simulated action that produced each event.

\- Do not imply that a generated event was collected from a real machine.

\- Keep detection labels separate from the event itself.

\- Version the schema and validate changes through tests.



\## 3. Proposed Event Structure



Each canonical event should support the following logical groups.



\### A. Event identity



\- `event\_id`: Unique identifier for the event.

\- `schema\_version`: Version of the canonical schema.

\- `event\_source`: Source family, such as process creation or PowerShell Classic.

\- `event\_type`: Normalized event type.

\- `timestamp`: Event occurrence time.

\- `host\_id`: Identifier for the simulated or reference host.



\### B. Process information



\- `process\_id`: Process identifier, when available.

\- `process\_guid`: Stable process identifier, when available.

\- `image`: Executable path or image name.

\- `original\_file\_name`: Original executable metadata, when available.

\- `command\_line`: Command-line information, when available.

\- `parent\_process\_id`: Parent process identifier, when available.

\- `parent\_process\_guid`: Parent process identifier in GUID form, when available.

\- `parent\_image`: Parent executable path or image name.

\- `parent\_command\_line`: Parent command line, when available.

\- `user`: Associated user, when available.



\### C. Source-specific information



\- `source\_event\_id`: Original source event identifier, when available.

\- `channel`: Original Windows event channel, when available.

\- `event\_code`: Original event identifier or code, when available.

\- `raw\_event`: Original source record or its preserved representation.

\- `source\_fields`: Additional fields that do not map directly to canonical fields.



\### D. Provenance



\- `origin`: Explicit origin, such as `synthetic` or `reference`.

\- `scenario\_id`: Scenario that produced the event, when applicable.

\- `action\_id`: Simulated action associated with the event, when applicable.

\- `generator\_version`: Generator version, when applicable.

\- `run\_id`: Generation or collection run identifier.

\- `parent\_event\_ids`: Related event identifiers, when applicable.



\### E. Labels and evaluation



\- `ground\_truth\_labels`: Expected scenario or behaviour labels.

\- `detection\_results`: Separate evaluation results, including the rule identifier, match outcome and evaluator version.



These fields describe the intended logical structure. Their exact data types, requiredness and nested representation must be defined in the machine-readable schema.



\## 4. Event-Source Requirements



\### Windows process creation



Support executable identity, command line, process identifiers, parent-process information, timestamp and original event metadata where available.



\### PowerShell Classic



Preserve the original event data and channel information. Support normalized extraction of host and application information without discarding the raw source representation.



\### Future event sources



Additional sources must be introduced through explicit mappings and source-specific validation rather than silently overloading existing fields.



\## 5. Validation Requirements



The implementation must eventually validate:



1\. Schema version and field types.

2\. Required fields for each event source.

3\. Timestamp format and chronology.

4\. Process-parent relationships.

5\. Provenance consistency.

6\. Source-to-canonical field mappings.

7\. Separation of event data, ground truth and detection results.



\## 6. Open Design Decisions



\- Exact required and optional fields per event source.

\- Timestamp precision and timezone policy.

\- Representation of unknown versus not-applicable fields.

\- Canonical schema format and validation library.

\- How reference events retain their original record and collection metadata.



\## Status



Logical schema specification drafted. Machine-readable schema and implementation remain pending.

