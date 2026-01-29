# cons.md

## 1. IPv6 Not Fully Supported

**Limitation:** IPv6 addresses detected but not validated or normalized per RFC 4291.

**Impact:** No subnet inference or reverse PTR for IPv6. Modern dual-stack networks lose portion of inventory data.

**Tradeoff:** IPv4 validation is straightforward while IPv6 is complex with compression rules, zone IDs, and multiple valid representations.


---

## 2. LLM Request Limits and Semantic Ambiguity

**Limitation:** The number of API requests is constrained by daily quotas, limiting throughput for large datasets. The model struggles to distinguish between person names and team names when both are proper nouns.

**Impact:** Enterprise-scale inventories cannot be processed in single execution and require multi-day runs. Every owner field triggers an API call even for simple cases that don't require contextual understanding. Department names may be incorrectly classified as person names when grammatical patterns are identical, leading to misattribution in owner fields.

**Tradeoff:** API-based approach enables access to state-of-the-art models without infrastructure investment. Universal LLM usage for owner parsing ensures consistent handling across varying formats. Request constraints demonstrate cost-conscious engineering while model limitations reflect inherent challenges in natural language understanding.


---

## 3. No Accuracy Validation or Learning Feedback Loop

**Limitation:** No mechanism to verify if LLM classifications were correct or improve over time.

**Impact:** Misclassifications persist undetected. Cannot measure accuracy rate. No prioritized review for low-confidence results.

**Tradeoff:** Feedback infrastructure exceeds assignment scope. LLM confidence scores provide basic guidance for which records need review.

**Mitigation:** Build review queue for low-confidence results, store corrections as ground truth, use verified examples for few-shot learning in prompts, track accuracy metrics over time.