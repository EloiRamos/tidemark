# Order 21 Cloud Deployment Proof v1.0

**Status:** Implemented; final independent review complete; ready for human commit
**Evidence date:** 2026-08-09
**Starting revision:** `73c11c6`
**Deployment project alias:** `Gemini API`

## 1. Scope and authority

This package records the redacted semantic evidence for the bounded Order 21
Google Cloud deployment. The human owner's delivery-mode amendment is
persisted in the Order 20 approval record. The amendment allowed standard
temporary Cloud Build source staging, at most three justified build attempts,
up to EUR 50 of eligible Google Cloud Free Trial consumption, and EUR 0
personal out-of-pocket spend. It did not authorize a paid billing upgrade,
Gemini Prepay, a live provider request, a public endpoint, a runtime secret, a
service-account key, persistent application storage, or Order 22 work.

## 2. Budget and funding gate

The existing one-project EUR 10.00 alerts-only budget passed exact semantic
Budget API v1 read-back before deployment. Configuration-level notification
verification passed through the verified owner recipient path. Observed email
delivery remains future evidence if a threshold is reached naturally.

```text
BUDGET_CREATED=true
BUDGET_ALERT_CONFIGURED=true
BUDGET_NOTIFICATION_PATH_VERIFIED=true
BUDGET_ALERT_DELIVERY_OBSERVED=false
BUDGET_ALERT_VERIFIED=true
PAID_BILLING_UPGRADE_PERFORMED=false
GOOGLE_AI_STUDIO_BILLING_CHANGED=false
```

## 3. Image build and publication

One standard regional Cloud Build submission used one temporary source-staging
bucket and one reviewed Dockerfile. The single API build attempt succeeded and
published exactly one image to the temporary regional Artifact Registry
repository. The build identity received repository-scoped writer authority
only for the build window, and that authority was revoked after publication.

The remote OCI manifest and config proved `linux/amd64`; the published digest
matched the build result and the digest pinned into the Cloud Run Job. The
compressed image was below the approved 400 MiB ceiling. The provider-free
entrypoint contained no Gemini credential, runtime secret, protected value, or
private path.

```text
CLOUD_BUILD_ATTEMPTS=1
CLOUD_BUILD_SUCCEEDED=true
STANDARD_CLOUD_BUILD_SOURCE_STAGING_USED=true
IMAGE_PLATFORM=linux/amd64
IMAGE_PLATFORM_VERIFIED=true
IMAGE_DIGEST_VERIFIED=true
IMAGE_SIZE_BOUND_VERIFIED=true
SERVICE_ACCOUNT_KEY_CREATED=false
```

## 4. Deployment configuration

One private Cloud Run Job was created in `europe-west1` using one keyless
runtime service account and the pinned image digest. Read-back before execution
and after redeploy established the following contract:

```text
CLOUD_RUN_TASK_COUNT=1
CLOUD_RUN_PARALLELISM=1
CLOUD_RUN_MAX_RETRIES=0
CLOUD_RUN_TIMEOUT_SECONDS=60
CLOUD_RUN_CPU=1
CLOUD_RUN_MEMORY=512Mi
PUBLIC_ENDPOINT=false
PERSISTENCE=false
RUNTIME_SECRET=false
DIRECT_VPC_EGRESS=false
EXECUTION_OVERRIDE_USED=false
```

The runtime identity had no project resource roles and no user-managed key.
The human operator held only the job-scoped invocation role during proof
execution. Temporary deploy, policy, reader, build, repository, and
service-account lifecycle authority was revoked at its documented checkpoint.

## 5. Execution, equivalence, and replay proof

Two manual Cloud Run executions were used: one before rollback and one after
redeploy. Both succeeded with automatic retries disabled and no execution
override. Their structured allowlisted proof envelopes had the same canonical
digest as the equal-input local proof.

Each proof envelope verified all six required deterministic scenarios. The
replay case recorded one execution start, one payment, and explicit replay
rejection. Both executions remained provider-free and made no application
network call.

```text
TOTAL_CLOUD_EXECUTIONS=2
MAX_CLOUD_EXECUTIONS=4
ALL_REQUIRED_SCENARIOS_VERIFIED=true
LOCAL_CLOUD_SEMANTIC_EQUIVALENCE=true
REPLAY_TOTAL_EXECUTION_START_COUNT=1
REPLAY_TOTAL_PAYMENT_COUNT=1
REPLAY_REJECTION_PRESENT=true
LIVE_MODEL_USED=false
GEMINI_CALLS=0
APPLICATION_NETWORK_CALLS=0
```

## 6. Rollback, redeploy, and shutdown

The rollback checkpoint positively proved the first job absent after deletion.
The job was then recreated from the captured configuration and pinned digest,
read back with the exact approved configuration, and executed successfully a
second time. This completed the rollback/redeploy proof.

Final cleanup permanently removed the job and job-scoped invoker binding, the
image and Artifact Registry repository, the keyless runtime service account,
the temporary Cloud Build source bucket and staged objects, and all temporary
project IAM bindings. Order 21 temporary Cloud Shell files were also removed.
The non-billable budget and enabled APIs remain for final billing
reconciliation; retained platform build/log history is not an active billable
deployment resource.

```text
ROLLBACK_ABSENCE_CHECKPOINT_VERIFIED=true
ROLLBACK_REDEPLOY_VERIFIED=true
SHUTDOWN_VERIFIED=true
CLOUD_RUN_JOB_COUNT_AFTER_SHUTDOWN=0
ARTIFACT_REGISTRY_REPOSITORY_COUNT_AFTER_SHUTDOWN=0
RUNTIME_SERVICE_ACCOUNT_COUNT_AFTER_SHUTDOWN=0
CLOUD_BUILD_STAGING_BUCKET_COUNT_AFTER_SHUTDOWN=0
TEMPORARY_IAM_BINDING_COUNT_AFTER_SHUTDOWN=0
CONTINUING_BILLABLE_RESOURCE_PRESENT=false
```

## 7. Cost observation and review boundary

The authenticated Google Cloud dashboard showed EUR 0.00 after the successful
build, after proof execution, and after final shutdown. Personal out-of-pocket
spend remained EUR 0. No paid billing upgrade, Gemini Prepay activation,
hackathon-credit redemption, or live provider request occurred.

The Budget API, Cloud Run Admin API, Artifact Registry API, and Cloud Build API
remain enabled. No API was disabled as a cost optimization. The existing budget
remains the final-reconciliation control and was not changed during deployment
or cleanup.

```text
ORDER_21_CLOUD_CONSUMPTION_EUR=0.00
ORDER_21_CLOUD_CONSUMPTION_CAP_EUR=50
PERSONAL_SPEND_EUR=0
ZERO_PERSONAL_SPEND_BOUND_VERIFIED=true
ORDER_21_IMPLEMENTED=true
READY_FOR_FINAL_INDEPENDENT_ORDER_21_REVIEW=true
ORDER_22_STARTED=false
```

## 8. Repository verification and closure

An independent model-assisted review completed the final Order 21 review with
`PASS_WITH_NON_BLOCKING_FINDINGS`. The review recorded no blocker, high,
medium, or low finding and one non-blocking NOTE. The review was based on the
repository and the persisted redacted evidence; it did not independently use
web research, browser access, or Google Cloud. NOTE-1 is not remediated and
remains future-strengthening evidence only.

No staging, commit, push, publication, or Order 22 action is part of this
package or closure update.

```text
GIT_DIFF_CHECK_PASS=true
PREVIOUS_TEST_COUNT=834
TOTAL_TEST_COUNT=834
TEST_FAILURES=0
TEST_WARNINGS=0
SENSITIVE_IDENTIFIER_SCAN_PASS=true
```

```text
FINAL_INDEPENDENT_ORDER_21_REVIEW_COMPLETE=true
FINAL_INDEPENDENT_ORDER_21_REVIEW_VERDICT=PASS_WITH_NON_BLOCKING_FINDINGS

OPEN_BLOCKER_FINDINGS=0
OPEN_HIGH_FINDINGS=0
OPEN_MEDIUM_FINDINGS=0
OPEN_LOW_FINDINGS=0
NOTE_FINDINGS=1

ORDER_21_IMPLEMENTED=true
ORDER_21_CLOSURE_RECOMMENDATION=READY_FOR_HUMAN_COMMIT
READY_FOR_HUMAN_COMMIT=true

NOTE_1_REMEDIATED=false
NOTE_1_BLOCKING=false
ORDER_22_STARTED=false
```
