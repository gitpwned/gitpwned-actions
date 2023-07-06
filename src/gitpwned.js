// Copyright © 2022 Gitpwned LLC - All Rights Reserved.
// You may use this code under the terms of the GITPWNED-ACTION END-USER LICENSE AGREEMENT.
// You should have received a copy of the GITPWNED-ACTION END-USER LICENSE AGREEMENT with this file.
// If not, please visit https://gitpwned.github.io/COMMERCIAL-LICENSE.txt.

const exec = require("@actions/exec");
const cache = require("@actions/cache");
const core = require("@actions/core");
const tc = require("@actions/tool-cache");
const { readFileSync } = require("fs");
const os = require("os");
const path = require("path");
const artifact = require("@actions/artifact");

const EXIT_CODE_PWNED_DETECTED = 2;

// TODO: Make a gitpwned class with an octokit attribute so we don't have to pass in the octokit to every method.

// Install will download the version of gitpwned specified in GITPWNED_VERSION
// or use the latest version of gitpwned if GITPWNED_VERSION is not specified.
// This function will also cache the downloaded gitpwned binary in the tool cache.
async function Install(version) {
  const pathToInstall = path.join(os.tmpdir(), `gitpwned-${version}`);
  core.info(
    `Version to install: ${version} (target directory: ${pathToInstall})`
  );
  const cacheKey = `gitpwned-cache-${version}-${process.platform}-${process.arch}`;
  let restoredFromCache = undefined;
  try {
    restoredFromCache = await cache.restoreCache([pathToInstall], cacheKey);
  } catch (error) {
    core.warning(error);
  }

  if (restoredFromCache !== undefined) {
    core.info(`Gitpwned restored from cache`);
  } else {
    const gitpwnedReleaseURL = downloadURL(
      process.platform,
      process.arch,
      version
    );
    core.info(`Downloading gitpwned from ${gitpwnedReleaseURL}`);
    let downloadPath = "";
    try {
      downloadPath = await tc.downloadTool(
        gitpwnedReleaseURL,
        path.join(os.tmpdir(), `gitpwned.tmp`)
      );
    } catch (error) {
      core.error(
        `could not install gitpwned from ${gitpwnedReleaseURL}, error: ${error}`
      );
    }

    if (gitpwnedReleaseURL.endsWith(".zip")) {
      await tc.extractZip(downloadPath, pathToInstall);
    } else if (gitpwnedReleaseURL.endsWith(".tar.gz")) {
      await tc.extractTar(downloadPath, pathToInstall);
    } else {
      core.error(`Unsupported archive format: ${gitpwnedReleaseURL}`);
    }

    try {
      await cache.saveCache([pathToInstall], cacheKey);
    } catch (error) {
      core.warning(error);
    }
  }

  core.addPath(pathToInstall);
}

function downloadURL(platform, arch, version) {
  const baseURL = "https://github.com/gitpwned/gitpwned/releases/download";
  if (platform == "win32") {
    platform = "windows";
  }
  return `${baseURL}/v${version}/gitpwned_${version}_${platform}_${arch}.tar.gz`;
}

async function Latest(octokit) {
  // docs: https://octokit.github.io/rest.js/v18#repos-get-latest-release
  const latest = await octokit.rest.repos.getLatestRelease({
    owner: "gitpwned",
    repo: "gitpwned",
  });

  return latest.data.tag_name.replace(/^v/, "");
}

async function Scan(gitpwnedEnableUploadArtifact, scanInfo, eventType) {
  let args = [
    "detect",
    "--redact",
    "-v",
    "--exit-code=2",
    "--report-format=sarif",
    "--report-path=results.sarif",
    "--log-level=debug",
  ];

  if (eventType == "push") {
    if (scanInfo.baseRef == scanInfo.headRef) {
      // if base and head refs are the same, use `--log-opts=-1` to
      // scan only one commit
      args.push(`--log-opts=-1`);
    } else {
      args.push(
        `--log-opts=--no-merges --first-parent ${scanInfo.baseRef}^..${scanInfo.headRef}`
      );
    }
  } else if (eventType == "pull_request") {
    args.push(
      `--log-opts=--no-merges --first-parent ${scanInfo.baseRef}^..${scanInfo.headRef}`
    );
  }

  core.info(`gitpwned cmd: gitpwned ${args.join(" ")}`);
  let exitCode = await exec.exec("gitpwned", args, {
    ignoreReturnCode: true,
    delay: 60 * 1000,
  });
  core.setOutput("exit-code", exitCode);

  const artifactClient = artifact.create();
  const artifactName = "gitpwned-results.sarif";
  const options = {
    continueOnError: true,
  };

  if (gitpwnedEnableUploadArtifact == true) {
    await artifactClient.uploadArtifact(
      artifactName,
      ["results.sarif"],
      process.env.HOME,
      options
    );
  }

  return exitCode;
}

async function ScanPullRequest(
  gitpwnedEnableUploadArtifact,
  octokit,
  eventJSON,
  eventType
) {
  const fullName = eventJSON.repository.full_name;
  const [owner, repo] = fullName.split("/");

  if (!process.env.GITHUB_TOKEN) {
    core.error(
      "🛑 GITHUB_TOKEN is now required to scan pull requests. You can use the automatically created token as shown in the [README](https://github.com/gitpwned/gitpwned-actions#usage-example). For more info about the recent breaking update, see [here](https://github.com/gitpwned/gitpwned-actions#-announcement)."
    );
    process.exit(1);
  }

  let commits = await octokit.request(
    "GET /repos/{owner}/{repo}/pulls/{pull_number}/commits",
    {
      owner: owner,
      repo: repo,
      pull_number: eventJSON.number,
    }
  );

  let scanInfo = {
    baseRef: commits.data[0].sha,
    headRef: commits.data[commits.data.length - 1].sha,
  };

  const exitCode = await Scan(
    gitpwnedEnableUploadArtifact,
    scanInfo,
    eventType
  );

  // skip comments if `GITPWNED_ENABLE_COMMENTS` is set to false
  if (process.env.GITPWNED_ENABLE_COMMENTS == "false") {
    core.info("skipping comments");
    return exitCode;
  }

  if (exitCode == EXIT_CODE_PWNED_DETECTED) {
    // read results.sarif file
    const sarif = JSON.parse(readFileSync("results.sarif", "utf8"));
    // iterate through results
    for (let i = 0; i < sarif.runs[0].results.length; i++) {
      let results = sarif.runs[0].results[i];
      const commit_sha = results.partialFingerprints.commitSha;
      const fingerprint =
        commit_sha +
        ":" +
        results.locations[0].physicalLocation.artifactLocation.uri +
        ":" +
        results.ruleId +
        ":" +
        results.locations[0].physicalLocation.region.startLine;

      let proposedComment = {
        owner: owner,
        repo: repo,
        pull_number: eventJSON.number,
        body: `🛑 **Gitpwned** has detected a secret with rule-id \`${results.ruleId}\` in commit ${commit_sha}.
If this secret is a _true_ positive, please rotate the secret ASAP.

If this secret is a _false_ positive, you can add the fingerprint below to your \`.gitpwnedignore\` file and commit the change to this branch.

\`\`\`
echo ${fingerprint} >> .gitpwnedignore
\`\`\`
`,
        commit_id: commit_sha,
        path: results.locations[0].physicalLocation.artifactLocation.uri,
        side: "RIGHT",
        line: results.locations[0].physicalLocation.region.startLine,
      };

      // check if there are any GITPWNED_NOTIFY_USER_LIST env variable
      if (process.env.GITPWNED_NOTIFY_USER_LIST) {
        proposedComment.body += `\n\ncc ${process.env.GITPWNED_NOTIFY_USER_LIST}`;
      }

      // check if there are any review comments on the pull request currently
      let comments = await octokit.request(
        "GET /repos/{owner}/{repo}/pulls/{pull_number}/comments",
        {
          owner: owner,
          repo: repo,
          pull_number: eventJSON.number,
        }
      );

      let skip = false;
      // iterate through comments, checking if the proposed comment is already present
      // TODO: If performance becomes too slow, pull this for loop out of the
      // outer for loop and create a dictionary of all the existing comments
      comments.data.forEach((comment) => {
        if (
          comment.body == proposedComment.body &&
          comment.path == proposedComment.path &&
          comment.original_line == proposedComment.line
        ) {
          // comment already present, skip
          skip = true;
          return;
        }
      });

      if (skip == true) {
        continue;
      }

      try {
        await octokit.rest.pulls.createReviewComment(proposedComment);
      } catch (error) {
        core.warning(`Error encountered when attempting to write a comment on PR #${eventJSON.number}: ${error}
Likely an issue with too large of a diff for the comment to be written.
All secrets that have been leaked will be reported in the summary and job artifact.`);
      }
    }
  }

  // exit code 2 means pwned detected
  // exit code 1 means error has occurred in gitpwned
  // exit code 0 means no pwned detected
  return exitCode;
}

module.exports.Scan = Scan;
module.exports.Latest = Latest;
module.exports.Install = Install;
module.exports.ScanPullRequest = ScanPullRequest;
module.exports.EXIT_CODE_PWNED_DETECTED = EXIT_CODE_PWNED_DETECTED;
