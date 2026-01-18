# Agent Design

## Philosophy

The VulnPulse agent is a **tool-routing RAG system**, not a generative chatbot. It classifies user intent, executes deterministic tools, and synthesizes structured responses.

## Design Principles

1. **Explicit over implicit**: Route to specific tools based on clear patterns, not LLM inference
2. **Retrieval-first**: All answers grounded in database queries or vector search
3. **Composable tools**: Each tool has single responsibility, can be combined
4. **Transparent reasoning**: Show which tools were used and why

## Intent Classification

### Rule-Based Router

```python
if contains_cve_id(query) and count == 1:
    → CVE_LOOKUP
elif contains_cve_id(query) and count > 1:
    → COMPARISON
elif contains_trend_keywords(query):
    → TREND_ANALYSIS
elif contains_filter_keywords(query):
    → FILTERED_SEARCH
else:
    → SEMANTIC_SEARCH
```

### Pattern Extraction

**CVE ID Pattern**: `CVE-\d{4}-\d{4,}` (e.g., CVE-2024-3094)

**Trend Keywords**: `recent`, `new`, `latest`, `this month`, `this week`, `trending`, `exploited`

**Filter Keywords**:
- Risk tiers: `critical`, `high`, `medium`, `low`
- KEV: `kev`, `exploited`, `known exploited`, `cisa`
- Vendors: Extracted via known vendor list or capitalized words
- Date: `last N days`, `since YYYY-MM-DD`, `this month`

### Why Not LLM Classification?

- **Deterministic**: Same query always routes the same way
- **Fast**: No API calls, instant routing
- **Debuggable**: Easy to trace why a query routed to a tool
- **Cost**: Zero inference cost for routing

## Tool Design

### CVE Lookup Tool
```
Input:  cve_id: str
Output: {cve_id, description, cvss_v3_score, epss_score, kev_flag, 
         risk_score, risk_tier, vendors[], products[], published, cwe_id}
Query:  SELECT * FROM vuln_enriched WHERE cve_id = ?
Format: Markdown card with risk badge, signals table, description
```

### SQL Query Tool
```
Input:  QueryFilters {
          vendors: list[str], products: list[str], risk_tiers: list[str],
          kev_only: bool, min_cvss: float, min_epss: float,
          date_from: date, date_to: date, limit: int
        }
Output: list[{cve_id, description, risk_score, risk_tier, kev_flag}]
Query:  Dynamic WHERE clause: vendor IN (...) AND risk_tier IN (...) ...
Format: Markdown table sorted by risk_score DESC
```

### Vector Search Tool
```
Input:  query: str, num_results: int, kev_only: bool, min_cvss: float
Output: list[{cve_id, score, description, risk_tier, kev_flag}]
Query:  Vector similarity on cve_documents_index with metadata filters
Format: Numbered list with similarity score and KEV badge
```

### Comparison Tool
```
Input:  cve_ids: list[str] (2-5 CVEs)
Output: {ranked: [{cve_id, risk_score, rationale}], recommendation: str}
Query:  Batch lookup from vuln_enriched, sort by risk_score
Format: Comparison table + "Prioritize X because..." recommendation
```

### Rationale Generation
Priority reasoning considers (in order):
1. KEV status (actively exploited = highest priority)
2. Ransomware association (from KEV notes)
3. EPSS score (exploitation probability)
4. CVSS severity (technical impact)

## Orchestration Flow

```
User Query
    ↓
┌─────────────────┐
│  Intent Router  │ ← Pattern matching, keyword extraction
└────────┬────────┘
         ↓
┌─────────────────┐
│  Tool Executor  │ ← Spark SQL / Vector Search client
└────────┬────────┘
         ↓
┌─────────────────┐
│   Synthesizer   │ ← Format + combine outputs
└────────┬────────┘
         ↓
    Markdown Response
```

## Response Synthesis

### Structure

```markdown
[Tool 1 Output]

---

[Tool 2 Output]

---

**Summary**: [High-level takeaway]
```

### Error Handling

| Scenario | Response |
|----------|----------|
| No results | Suggest broader filters or alternative keywords |
| CVE not found | "CVE-XXXX not found. Verify the ID or check if it's recent." |
| Vector Search unavailable | Fall back to SQL filtered search |
| Partial failure | Show successful outputs, note which tool failed |
| Invalid CVE format | "Invalid format. CVE IDs look like: CVE-2024-1234" |

## Query Examples

| User Query | Intent | Tools Used | Output |
|------------|--------|------------|--------|
| "What is CVE-2024-3094?" | CVE_LOOKUP | cve_lookup | Single CVE card |
| "Critical Apache vulns" | FILTERED_SEARCH | sql_query(risk_tier=CRITICAL, vendor=Apache) | Table of results |
| "Auth bypass in web apps" | SEMANTIC_SEARCH | vector_search("authentication bypass web") | Ranked list |
| "Compare CVE-X and CVE-Y" | COMPARISON | comparison([X, Y]) | Risk-ranked comparison |
| "What's exploited this month?" | TREND_ANALYSIS | sql_query(kev_only=True, date_from=30d ago) | Recent KEV list |

## Future Enhancements

- **Multi-turn context**: Remember previous queries in session
- **Clarification questions**: Ask user to disambiguate when intent unclear
- **Proactive insights**: "Did you know X is also affected?"
- **Export actions**: "Save these results to CSV"

## Non-Goals

- **General chat**: Not a conversational assistant, focused on vulnerability queries
- **Generative answers**: No hallucination risk, all data from database
- **Complex reasoning**: No multi-hop inference, just retrieval + formatting
