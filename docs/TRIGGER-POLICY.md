# WF003: selected review-sensitive trigger additions

WF003 reports a newly declared event name from this explicit set. It is a review
policy over configured changes, not a complete event-risk model. Adding an event
does not itself grant a write token, make a secret available, or prove an exploit.

| Event | Why a new declaration merits review |
|---|---|
| `pull_request_target` | Runs in the base-repository context for pull request activity. Review handling of proposed code and contributor-controlled data. |
| `workflow_run` | A follow-up workflow can have access unavailable to the workflow that triggered it. Review artifacts and other inputs crossing that boundary. |
| `issue_comment` | Issue and PR conversation comments can invoke a default-branch workflow. Review actor checks, comment data, and any token or secret use. |
| `issues` | Issue activity can invoke a default-branch workflow. Review which activity and actors can reach its jobs. |
| `discussion` | Discussion activity can invoke a default-branch workflow. Review actor checks and use of discussion data. |
| `discussion_comment` | Discussion comments can invoke a default-branch workflow. Review actor checks and use of comment data. |

These six events are the complete WF003 event set.

## Boundaries

- Only additions count. Existing events, removal, and declaration reordering do
  not create a WF003 finding.
- Activity types, branch/path filters, job conditions and actor authorization are
  not evaluated. For example, adding `issues: {types: [labeled]}` still flags the
  new event even though labeling can require a trusted actor. This can be useful
  review context without being a privilege escalation.
- Findings are independent of token scopes. An event addition is reported even
  with explicit `permissions: {}`; unknown token defaults keep the overall result
  incomplete while preserving the known trigger addition.
- `pull_request`, `pull_request_review` and `pull_request_review_comment` use PR
  merge contexts with documented fork token/secret restrictions. They are not
  treated as equivalent to the selected default/base-branch boundaries. Their
  exclusion does not establish safety or cover every repository setting.
- Other events, existing-trigger filter changes, executed code and reusable
  workflow internals remain outside this trigger policy. `analysis: complete`
  means the supported comparisons completed, not that all workflow risks were
  assessed. Every JSON report identifies the selected event set in limitations.

GitHub's [event reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
documents execution refs, event types, and fork behavior. Token access also
depends on [permission declarations and repository settings](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions).

This extension is covered by local regressions and hosted consumer/contract runs,
not an independent incident corpus or a measured maintainer-usefulness claim.
Keep the evaluated full pilot pin fixed during the advisory trial.
