# TIDEMARK Variant C W6 Deployment Architecture

**Status:** W6 communication surface
**Scope:** Evidence traversal, not a production deployment specification

This diagram keeps three provenance and time regions structurally separate: `CURRENT_OFFLINE`, `HISTORICAL_LIVE_GEMINI_ADK`, and `HISTORICAL_CLOUD_PROVIDER_FREE`. `HISTORICAL_OFFLINE_GOOGLE_ADK` remains a distinct provenance class for the Order 11 evidence indexed by the W6 package; it is not presented as live Gemini evidence here.

```mermaid
flowchart LR
    subgraph CURRENT_REGION["CURRENT_OFFLINE"]
        OPERATOR_CURRENT["OPERATOR_CURRENT | untrusted operator"]
        OFFLINE_DEMO_CURRENT["OFFLINE_DEMO_CURRENT | trusted runtime: protected-role recognition; trusted reference store/resolution; immutable policy decision; sealed prepared call/private binding; execution-time revalidation; durable evidence before effect; local single-use consumption; authoritative bounded effect boundary"]
        UI_CURRENT["UI_CURRENT | untrusted browser | masked evidence/projection"]
        W6_PACKAGE_CURRENT["W6_PACKAGE_CURRENT | current offline traversal/index"]
        OPERATOR_CURRENT --> OFFLINE_DEMO_CURRENT
        OFFLINE_DEMO_CURRENT --> UI_CURRENT
        W6_PACKAGE_CURRENT --> UI_CURRENT
    end

    subgraph LIVE_REGION["HISTORICAL_LIVE_GEMINI_ADK"]
        GEMINI_HIST["GEMINI_HIST | Gemini 3.6 Flash | HISTORICAL"]
        GEMINI_API_HIST["GEMINI_API_HIST | Gemini Developer API | HISTORICAL"]
        ADK_HIST["ADK_HIST | Google ADK 1.18.0 | HISTORICAL"]
        TIDEMARK_LIVE_HIST["TIDEMARK_LIVE_HIST | trusted TIDEMARK runtime"]
        SCHEDULE_PAYMENT_HIST["SCHEDULE_PAYMENT_HIST | schedule_payment"]
        SYNTHETIC_PAYMENT_HIST["SYNTHETIC_PAYMENT_HIST | synthetic bounded effect"]
        ORDER12_EVIDENCE["ORDER12_EVIDENCE | masked evidence/projection"]
        GEMINI_HIST --> GEMINI_API_HIST
        GEMINI_API_HIST --> ADK_HIST
        ADK_HIST --> TIDEMARK_LIVE_HIST
        TIDEMARK_LIVE_HIST --> SCHEDULE_PAYMENT_HIST
        SCHEDULE_PAYMENT_HIST --> SYNTHETIC_PAYMENT_HIST
        SYNTHETIC_PAYMENT_HIST --> ORDER12_EVIDENCE
    end

    subgraph CLOUD_REGION["HISTORICAL_CLOUD_PROVIDER_FREE | PROVIDER-FREE | GEMINI_CALLS=0"]
        CLOUD_OPERATOR_HIST["CLOUD_OPERATOR_HIST | historical operator invocation"]
        CLOUD_RUN_JOB_HIST["CLOUD_RUN_JOB_HIST | Cloud Run Job | europe-west1 | HISTORICAL | REMOVED AFTER PROOF"]
        CLOUD_PROOF_ENTRYPOINT_HIST["CLOUD_PROOF_ENTRYPOINT_HIST | provider-free proof entrypoint"]
        ORDER21_EVIDENCE["ORDER21_EVIDENCE | masked evidence/projection"]
        CLOUD_OPERATOR_HIST --> CLOUD_RUN_JOB_HIST
        CLOUD_RUN_JOB_HIST --> CLOUD_PROOF_ENTRYPOINT_HIST
        CLOUD_PROOF_ENTRYPOINT_HIST --> ORDER21_EVIDENCE
    end

    ORDER12_EVIDENCE --> W6_PACKAGE_CURRENT
    ORDER21_EVIDENCE --> W6_PACKAGE_CURRENT
```

The Order 12 chain records the historical live Gemini Developer API and Google ADK path. The independent Order 21 chain records a provider-free Cloud Run Job proof with `GEMINI_CALLS=0`; the resource was `REMOVED AFTER PROOF`. No directed edge connects the Gemini/API/ADK historical chain to the Cloud Run Job.

The diagram creates no evidence fact and grants no authority. It does not describe current Gemini execution, a present Cloud Run resource, a public endpoint, cloud persistence, or a production deployment specification.
