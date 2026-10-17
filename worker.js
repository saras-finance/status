export default {
  async fetch(request, env) {
    return env.ASSETS.fetch(request);
  },

  async scheduled(event, env, ctx) {
    if (!env.GITHUB_TOKEN) {
      console.error("Missing GITHUB_TOKEN secret in Cloudflare Worker environment.");
      return;
    }

    const url = "https://api.github.com/repos/saras-finance/status/actions/workflows/status-monitor.yml/dispatches";
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
        "User-Agent": "SarasFinance-Status-Cloudflare-Cron",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ref: "main" }),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`GitHub dispatch failed (${response.status}): ${text}`);
    } else {
      console.log("Successfully triggered GitHub Actions status-monitor.yml workflow.");
    }
  },
};
