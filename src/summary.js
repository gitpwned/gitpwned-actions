const core = require("@actions/core");
const { readFileSync } = require("fs");

async function Write(exitCode, eventJSON) {
  const repo_url = eventJSON.repository.html_url;
  const EXIT_CODE_NO_PWNED_DETECTED = 0;
  const EXIT_CODE_GITPWNED_ERROR = 1;
  const EXIT_CODE_PWNED_DETECTED = 2;

  if (exitCode == EXIT_CODE_PWNED_DETECTED) {
    let resultsRows = [[]];
    let resultsHeader = [
      { data: "Rule ID", header: true },
      { data: "Commit", header: true },
      { data: "Secret URL", header: true },
      { data: "Start Line", header: true },
      { data: "Author", header: true },
      { data: "Date", header: true },
      { data: "Email", header: true },
      { data: "File", header: true },
    ];
    const sarif = JSON.parse(readFileSync("results.sarif", "utf8"));
    sarif.runs[0].results.forEach((result) => {
      const commitSha = result.partialFingerprints.commitSha;
      const commitURL = `${repo_url}/commit/${commitSha}`;
      const secretURL = `${repo_url}/blob/${commitSha}/${result.locations[0].physicalLocation.artifactLocation.uri}#L${result.locations[0].physicalLocation.region.startLine}`;
      const fileURL = `${repo_url}/blob/${commitSha}/${result.locations[0].physicalLocation.artifactLocation.uri}`;
      resultsRows.push([
        result.ruleId,
        `<a href="${commitURL}">${commitSha.substring(0, 7)}</a>`,
        `<a href="${secretURL}">View Secret</a>`,
        result.locations[0].physicalLocation.region.startLine.toString(),
        result.partialFingerprints.author,
        result.partialFingerprints.date,
        result.partialFingerprints.email,
        `<a href="${fileURL}">${result.locations[0].physicalLocation.artifactLocation.uri}</a>`,
      ]);
    });
    await core.summary
      .addHeading("🛑 Gitpwned detected secrets 🛑")
      .addTable([resultsHeader, ...resultsRows])
      .write();
  } else if (exitCode == EXIT_CODE_NO_PWNED_DETECTED) {
    await core.summary.addHeading("No leaks detected ✅").write();
  } else if (exitCode == EXIT_CODE_GITPWNED_ERROR) {
    await core.summary.addHeading(`❌ Gitpwned exited with error. Exit code [${exitCode}]`).write();
  } else {
    await core.summary.addHeading(`❌ Gitpwned exited with unexpected exit code [${exitCode}]`).write();
  }
}

module.exports.Write = Write;
