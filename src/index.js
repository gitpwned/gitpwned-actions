// Copyright © 2023 Gitpwned LLC - All Rights Reserved.
// You may use this code under the terms of the GITPWNED-ACTION END-USER LICENSE AGREEMENT.
// You should have received a copy of the GITPWNED-ACTION END-USER LICENSE AGREEMENT with this file.
// If not, please visit https://gitpwned.github.io/COMMERCIAL-LICENSE.txt.

const { Octokit } = require("@octokit/rest");
const { readFileSync } = require("fs");
const core = require("@actions/core");
const summary = require("./summary.js");
const keygen = require("./keygen.js");
const gitpwned = require("./gitpwned.js");

let gitpwnedEnableSummary = true;
if (
  process.env.GITPWNED_ENABLE_SUMMARY == "false" ||
  process.env.GITPWNED_ENABLE_SUMMARY == 0
) {
  core.debug("Disabling GitHub Actions Summary.");
  gitpwnedEnableSummary = false;
}

let gitpwnedEnableUploadArtifact = true;
if (
  process.env.GITPWNED_ENABLE_UPLOAD_ARTIFACT == "false" ||
  process.env.GITPWNED_ENABLE_UPLOAD_ARTIFACT == 0
) {
  core.debug("Disabling uploading of results.sarif artifact.");
  gitpwnedEnableUploadArtifact = false;
}

// Event JSON example: https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads#webhook-payload-example-32
let eventJSON = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"));

// Examples of event types: "workflow_dispatch", "push", "pull_request", etc
const eventType = process.env.GITHUB_EVENT_NAME;
const supportedEvents = [
  "push",
  "pull_request",
  "workflow_dispatch",
  "schedule",
];

if (!supportedEvents.includes(eventType)) {
  core.error(`ERROR: The [${eventType}] event is not yet supported`);
  process.exit(1);
}

// Determine if the github user is an individual or an organization
let githubUsername = "";

// eventJSON.repository is undefined for scheduled events
if (eventType == "schedule") {
  githubUsername = process.env.GITHUB_REPOSITORY_OWNER;
  eventJSON.repository = {
    owner: {
      login: process.env.GITHUB_REPOSITORY_OWNER,
    },
    full_name: process.env.GITHUB_REPOSITORY,
  };
  let repoName = process.env.GITHUB_REPOSITORY;
  repoName = repoName.replace(`${process.env.GITHUB_REPOSITORY_OWNER}/`, "");
  // update repo name
  process.env.GITHUB_REPOSITORY = repoName;
} else {
  githubUsername = eventJSON.repository.owner.login;
}

const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN,
  baseUrl: process.env.GITHUB_API_URL,
});

var shouldValidate = true;

// Docs: https://docs.github.com/en/rest/users/users#get-a-user
octokit
  .request("GET /users/{username}", {
    username: githubUsername,
  })
  .then((user) => {
    const githubUserType = user.data.type;

    switch (githubUserType) {
      case "Organization":
        core.info(
          `[${githubUsername}] is an organization. License key is required.`
        );
        break;
      case "User":
        core.info(
          `[${githubUsername}] is an individual user. No license key is required.`
        );
        shouldValidate = false;
        break;
      default:
        core.warning(
          `[${githubUsername}] is an unexpected type [${githubUserType}]. License key validation will be enforced 🤷.`
        );
        core.debug(`GitHub GET user API returned [${JSON.stringify(user)}]`);
    }
  })
  .catch((err) => {
    core.warning(
      `Get user [${githubUsername}] failed with error [${err}]. License key validation will be enforced 🤷.`
    );
  })
  .finally(() => {
    // check if a gitpwned license is available, if not log error message
    if (shouldValidate && !process.env.GITPWNED_LICENSE) {
      core.error(
        "🛑 missing gitpwned license. Go grab one at gitpwned.io and store it as a GitHub Secret named GITPWNED_LICENSE. For more info about the recent breaking update, see [here](https://github.com/gitpwned/gitpwned-action#-announcement)."
      );
      process.exit(1);
    }

    start();
  });

// start validates the license first and then starts the scan
// if license is valid
async function start() {
  // validate key first
  if (shouldValidate) {
    core.debug(
      `eventJSON.repository.full_name: ${eventJSON.repository.full_name}`
    );
    await keygen.ValidateKey(eventJSON);
  }

  // default exit code, this value will be overwritten if gitpwned
  // detects leaks or errors
  let exitCode = 0;

  // check gitpwned version

  let gitpwnedVersion = process.env.GITPWNED_VERSION || "8.16.1";
  if (gitpwnedVersion === "latest") {
    gitpwnedVersion = await gitpwned.Latest(octokit);
  }
  core.info("gitpwned version: " + gitpwnedVersion);
  let gitpwnedPath = await gitpwned.Install(gitpwnedVersion);

  // default scanInfo
  let scanInfo = {
    gitpwnedPath: gitpwnedPath,
  };

  // determine how to run gitpwned based on event type
  core.info("event type: " + eventType);
  if (eventType === "push") {
    // check if eventsJSON.commits is empty, if it is send a info message
    // saying we don't have to run gitpwned
    if (eventJSON.commits.length === 0) {
      core.info("No commits to scan");
      process.exit(0);
    }

    scanInfo = {
      baseRef: eventJSON.commits[0].id,
      headRef: eventJSON.commits[eventJSON.commits.length - 1].id,
    };
    exitCode = await gitpwned.Scan(
      gitpwnedEnableUploadArtifact,
      scanInfo,
      eventType
    );
  } else if (eventType === "workflow_dispatch" || eventType === "schedule") {
    exitCode = await gitpwned.Scan(
      gitpwnedEnableUploadArtifact,
      scanInfo,
      eventType
    );
  } else if (eventType === "pull_request") {
    exitCode = await gitpwned.ScanPullRequest(
      gitpwnedEnableUploadArtifact,
      octokit,
      eventJSON,
      eventType
    );
  }

  // after gitpwned scan, update the job summary
  if (gitpwnedEnableSummary == true) {
    await summary.Write(exitCode, eventJSON);
  }

  if (exitCode == 0) {
    core.info("✅ No leaks detected");
  } else if (exitCode == gitpwned.EXIT_CODE_PWNED_DETECTED) {
    core.warning("🛑 Leaks detected, see job summary for details");
    process.exit(1);
  } else {
    core.error(`ERROR: Unexpected exit code [${exitCode}]`);
    process.exit(exitCode);
  }
}
