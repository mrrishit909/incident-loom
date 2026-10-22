import { Icon } from "../components/Icon";
import type { AppConfig } from "../config";
import type { SiteData } from "../data/site";
import { routeHref } from "../routing";

export function HistoryView({ site, config }: { site: SiteData; config: AppConfig }) {
  const included = new Set(site.snapshot.runs_included);
  return (
    <div className="il-page" style={{ maxWidth: 1000 }}>
      <div className="il-section-head">
        <h1 className="il-h1">Every investigation run, including the ones that failed.</h1>
        <p className="il-prose">The ledger lists every recorded attempt. The {included.size} most recent completed runs are in this site's snapshot; older results stay on the state branch.</p>
      </div>
      <ol className="il-list" aria-label="Run ledger, newest first">
        {site.index.map((r) => (
          <li key={r.run_id} className="il-card">
            <div className="il-toolbar" style={{ justifyContent: "space-between" }}>
              {included.has(r.run_id) ? <a className="il-mono il-wrap" href={routeHref({ view: "run", runId: r.run_id, section: "incidents" })}>{r.run_id}</a> : <span className="il-mono il-wrap">{r.run_id}</span>}
              <span className={`il-tag ${r.status === "completed" ? "il-tone-benign" : r.status === "failed" ? "il-tone-hostile" : "il-tone-uncertain"}`}>{r.status}</span>
            </div>
            <p className="il-small">Attempt {r.attempt}, created {r.created_at.replace("T", " ").replace("Z", " UTC")}, source {r.source}{r.issue ? <> from <a href={`${config.repoUrl}/issues/${r.issue}`}>issue #{r.issue}</a></> : null}</p>
            {r.headline && <p>{r.headline}</p>}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function RequestView({ config }: { config: AppConfig }) {
  return (
    <div className="il-page" style={{ maxWidth: 780 }}>
      <div className="il-section-head">
        <h1 className="il-h1">Request an investigation run.</h1>
        <p className="il-prose">
          This site is read-only. A new run is a GitHub issue that picks how many of the committed daily event batches to replay, whether to correct
          each source's declared clock offset, and whether to stop and resume from the checkpoint partway through. A GitHub Actions workflow runs it
          and publishes the result here. Opening an issue needs a GitHub account.
        </p>
      </div>
      <p className="il-prose">
        The repository owner's requests start automatically. Anyone else's request waits, labelled blocked, until the owner approves it. Runs read
        synthetic batches only, never touch a real system, and cannot start paid AI inference.
      </p>
      <ol className="il-list" style={{ listStyle: "decimal", paddingLeft: 20 }}>
        <li>The intake workflow validates the form against the request schema and labels the issue requested, or blocked with the reason.</li>
        <li>Identical parameters on the current engine link to the existing run instead of running again.</li>
        <li>The run replays the batches on a GitHub-hosted runner, validates its outputs and writes them to the state branch.</li>
        <li>The site redeploys and the issue gets a link to the result, with the evidence kept either way.</li>
      </ol>
      <div className="il-toolbar">
        <a className="il-btn il-btn-primary" href={`${config.repoUrl}/issues/new?template=run-request.yml`}><Icon name="github" /> Open the run request form on GitHub</a>
        <a className="il-btn" href={`${config.repoUrl}/issues?q=label%3Atype%3Arun`}>See existing requests</a>
      </div>
      <p className="il-small">Limits keep the workspace inside GitHub's free tier: at most 40 runs a month, 5 at a time, 2 MB of results per run.</p>
    </div>
  );
}

export function AboutView({ config }: { config: AppConfig }) {
  const rows: [string, string, string][] = [
    ["Incidents, timelines, hypotheses, entities, metrics, replay", "Cached", "A static snapshot of the state branch, rebuilt after each run; its time is shown in the footer."],
    ["New runs", "Live, owner-authorized", "Through GitHub Issues and Actions, over committed synthetic batches only."],
    ["Your own logs", "Not supported", "The repository and site are public; nothing private is ever uploaded."],
    ["Response actions against real systems", "Not supported", "By design: the workspace investigates, it never acts."],
    ["AI grading of the site", "Unavailable", "Optional; runs only if the owner configures inference credentials."],
  ];
  return (
    <div className="il-page" style={{ maxWidth: 880 }}>
      <div className="il-section-head">
        <h1 className="il-h1">How the loom works, and what it does not claim.</h1>
        <p className="il-prose">
          Four synthetic sources (identity sign-ins, cloud audit, host authentication and resource access) arrive as append-only daily batches. Each
          record is parsed, normalized to one event schema, corrected for its source's declared clock offset, de-duplicated across deliveries, or
          quarantined with a reason. Correlation rules flag patterns; flagged events are grouped into incidents with an ordered timeline, hypotheses
          that cite their events, alternative explanations, and the gaps that lower confidence.
        </p>
      </div>
      <ul className="il-list il-prose" style={{ listStyle: "disc", paddingLeft: 20 }}>
        <li>Every event, user, host, address and label is synthetic, for a fictional organisation, using documentation address ranges.</li>
        <li>Links between events are causal only when the records share a session, request, process or parent id; otherwise the site states only their order.</li>
        <li>A silent source becomes an explicit gap; no event is ever invented to fill it.</li>
        <li>Detector precision and recall are measured on held-out synthetic scenarios the thresholds were not chosen on, and describe only this synthetic data.</li>
      </ul>
      <div className="il-table-wrap" tabIndex={0} role="region" aria-label="Capability status">
        <table className="il-table">
          <thead><tr><th scope="col">Capability</th><th scope="col">Status</th><th scope="col">Detail</th></tr></thead>
          <tbody>{rows.map(([a, b, c]) => <tr key={a}><th scope="row" style={{ fontWeight: 500 }}>{a}</th><td>{b}</td><td>{c}</td></tr>)}</tbody>
        </table>
      </div>
      <p className="il-small">Source, workflows and documentation: <a href={config.repoUrl}>{config.repoUrl.replace("https://", "")}</a></p>
    </div>
  );
}
