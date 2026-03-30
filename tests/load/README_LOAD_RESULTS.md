# Load Test Results

## Test Configuration
- **Tool:** Locust 2.31.0
- **Users:** 50 concurrent
- **Spawn rate:** 5 users/second
- **Duration:** 3-5 minutes
- **User mix:** 70% normal, 20% enumeration bots, 10% credential stuffers

## Results

| Metric | Value |
|--------|-------|
| Sustained RPS | [FILL AFTER TEST] |
| Total requests | [FILL AFTER TEST] |
| Median latency (POST /v1/analyze) | [FILL]ms |
| P95 latency | [FILL]ms |
| P99 latency | [FILL]ms |
| Failure rate | [FILL]% |

## Detection Accuracy

| Metric | Value |
|--------|-------|
| Block rate | [FILL]% |
| Attack sessions detected | [FILL] |
| Enumeration detected | [YES/NO] |
| Credential stuffing detected | [YES/NO] |
| Normal user false positive rate | [FILL]% |

## Notes
- [Add any observations about the test]
- [e.g., "Detection kicked in after ~15 seconds of worker processing"]