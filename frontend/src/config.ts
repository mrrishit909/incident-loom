export type Theme = "light" | "dark" | "auto";
export type Routing = "hash" | "memory";

/** Everything a host page can configure when embedding the app. */
export interface AppConfig {
  /** Public path the app is served from (used for links back to the standalone site). */
  basePath: string;
  /** Base URL of the published data snapshot (directory containing snapshot.json). */
  dataUrl: string;
  theme: Theme;
  /** Render the app's own header, navigation and footer. Hosts with their own chrome set false. */
  showShell: boolean;
  /** "hash" keeps deep links in the URL; "memory" never touches the host's location. */
  routing: Routing;
  repoUrl: string;
  siteUrl: string;
}

export const REPO_URL = "https://github.com/mrrishit909/incident-loom";
export const SITE_URL = "https://mrrishit909.github.io/incident-loom/";

export function resolveConfig(partial: Partial<AppConfig> = {}): AppConfig {
  const basePath = partial.basePath ?? import.meta.env.BASE_URL ?? "/";
  return {
    basePath,
    dataUrl: partial.dataUrl ?? `${basePath.replace(/\/?$/, "/")}data/`,
    theme: partial.theme ?? "dark", // dark-first workspace; System and Light are one click away in the footer
    showShell: partial.showShell ?? true,
    routing: partial.routing ?? "hash",
    repoUrl: partial.repoUrl ?? REPO_URL,
    siteUrl: partial.siteUrl ?? SITE_URL,
  };
}
