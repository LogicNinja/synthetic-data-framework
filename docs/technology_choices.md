# Model and retrieval technology choices

## Current foundation

- **Scenario generation:** the project uses `GrokResponsesClient`, a small direct xAI Responses API client. This is the confirmed integration; LangChain is not required to use the current Scenario Agent.
- **Prompt optimization:** DSPy is deferred. The project first establishes fixed B0/B1 prompt baselines and validates them against the current scenario schema. DSPy should be added only if prompt optimization becomes an explicit experiment.
- **Retrieval:** no vector database is configured. Current local knowledge sources and rules are loaded from files, which is sufficient for the present corpus and avoids adding embedding and database operations before a retrieval use case is defined.

These choices keep the current generation path reproducible and dependency-light. They do not prevent later integrations. Revisit DSPy or vector search when an experiment requires optimized prompts or semantic retrieval and defines comparison metrics for that addition.
