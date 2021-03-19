///
/// zian - A minimal pull request build dispatcher for sourcehut's build service
/// Copyright (C) 2021 Austin Ray <austin@austinray.io>
///
/// This program is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published
/// by the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// This program is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
///
/// You should have received a copy of the GNU Affero General Public License
/// along with this program.  If not, see <https://www.gnu.org/licenses/>.
///
use serde::{Deserialize, Serialize};

/// Webhook's `pull_request.head.repo` field
#[derive(Deserialize, Serialize)]
pub struct GitHubRepo {
    /// Full name of a repository e.g. Austin-Ray/zian
    pub full_name: String,
}

/// Webhook's `pull_request.head` or `pull_request.base` field.
#[derive(Deserialize, Serialize)]
pub struct GitHubRepoMeta {
    /// Nested meta data without any user information.
    pub repo: GitHubRepo,
}

/// Webhook's `pull_request` field's relevant data.
#[derive(Deserialize, Serialize)]
pub struct GitHubPullRequest {
    /// URL to pull request.
    pub url: String,
    /// Pull request number for repository.
    pub number: i32,
    /// Title of pull request.
    pub title: String,
    /// Body content of pull request.
    pub body: String,
    /// Repository meta data for target branch
    pub head: GitHubRepoMeta,
    /// Repository meta data for the base branch.
    pub base: GitHubRepoMeta,
}

/// Struct representation of GitHub's pull request webhook payload
///
/// Contains the minimal amount of fields needed for service operation.
///
/// Example payload available in `tests/resources/github-webhook.json`
#[derive(Serialize, Deserialize)]
pub struct GitHubPullRequestWebhook {
    /// Action triggering the webhook
    pub action: String,
    /// `pull_request` field in webhook.
    /// Contains all relevant information except `action`
    pub pull_request: GitHubPullRequest,
}
