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
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use async_trait::async_trait;
use hmac::{Hmac, Mac, NewMac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Webhook's `pull_request.head.repo` field
#[derive(Deserialize, Serialize, Debug)]
pub struct GitHubRepo {
    /// Full name of a repository e.g. Austin-Ray/zian
    pub full_name: String,
}

/// Webhook's `pull_request.head` or `pull_request.base` field.
#[derive(Deserialize, Serialize, Debug)]
pub struct GitHubRepoMeta {
    /// Nested meta data without any user information.
    pub repo: GitHubRepo,
}

/// Webhook's `pull_request` field's relevant data.
#[derive(Deserialize, Serialize, Debug)]
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
#[derive(Serialize, Deserialize, Debug)]
pub struct GitHubPullRequestWebhook {
    /// Action triggering the webhook
    pub action: String,
    /// `pull_request` field in webhook.
    /// Contains all relevant information except `action`
    pub pull_request: GitHubPullRequest,
}

#[derive(Serialize, Deserialize)]
pub struct GitHubFile {
    pub filename: String,
    pub status: String,
}

/// Configuration of Application.
pub struct AppConfig {
    /// Webhook secret in GitHub.
    pub github_secret: String,
    pub pr_checker: Box<dyn PullRequestChecker>,
}

/// Client for interacting with GitHub's pull request REST API.
#[async_trait]
pub trait GitHubPullRequestClient {
    /// Retrieve list of files at a given pull request [url]
    async fn files(&self, url: &str) -> Result<Vec<GitHubFile>, Box<dyn std::error::Error>>;
}

pub struct IGitHubPullRequestClient;

#[async_trait]
impl GitHubPullRequestClient for IGitHubPullRequestClient {
    /// Retrieve list of files at a given pull request [url]
    async fn files(&self, url: &str) -> Result<Vec<GitHubFile>, Box<dyn std::error::Error>> {
        let files_url = format!("{}/files", url);
        Ok(reqwest::get(files_url)
            .await?
            .json::<Vec<GitHubFile>>()
            .await?)
    }
}

#[async_trait]
pub trait PullRequestChecker {
    /// Check a PR at a provided [url] for forbidden modifications.
    async fn is_safe_pull_request(&self, url: &str) -> Result<bool, Box<dyn std::error::Error>>;
}

pub struct GitHubPullRequestChecker {
    pub github_client: Box<dyn GitHubPullRequestClient + Send + Sync>,
}

#[async_trait]
impl PullRequestChecker for GitHubPullRequestChecker {
    async fn is_safe_pull_request(&self, url: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // Found a forbidden file.
        Ok(self
            .github_client
            .files(url)
            .await?
            .iter()
            .any(|x| !is_safe_file(&x.filename)))
    }
}

fn verify_signature_sha256(
    secret: &str,
    payload: &str,
    signature: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut mac: Hmac<Sha256> =
        Hmac::new_varkey(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());

    let hex_decode = hex::decode(signature)?;

    Ok(mac.verify(&hex_decode).is_ok())
}

fn is_safe_file(filename: &str) -> bool {
    filename == ".build.yml" || filename.starts_with(".builds/")
}

#[post("/github/pull_request")]
pub async fn github_pull_request_webhook(
    request: HttpRequest,
    raw_payload: String,
    config: web::Data<AppConfig>,
) -> HttpResponse {
    let headers = request.headers();
    let payload: GitHubPullRequestWebhook = match serde_json::from_str(&raw_payload) {
        Ok(payload) => payload,
        Err(_) => return HttpResponse::BadRequest().finish(),
    };

    let sig_header = match headers.get("X-HUB-SIGNATURE-256") {
        Some(header) => match header.to_str() {
            Ok(sig) => sig,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        },
        None => return HttpResponse::Forbidden().body("No signature provided."),
    };

    let (_, sig) = sig_header.split_at("sha256=".len());

    let secret = &config.github_secret;

    let valid_sig = match verify_signature_sha256(&secret, &raw_payload, &sig) {
        Ok(result) => result,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if !valid_sig {
        return HttpResponse::Forbidden().body("Invalid signature.");
    }

    // TODO: Refactor this nastiness.
    let pr_checker = &config.pr_checker;
    match pr_checker
        .is_safe_pull_request(&payload.pull_request.url)
        .await
    {
        Ok(valid) => {
            if !valid {
                return HttpResponse::Forbidden().body("Pull request can expose secrets!");
            }
        }
        Err(_) => return HttpResponse::InternalServerError().finish(),
    }

    HttpResponse::Ok().finish()
}

#[get("/")]
async fn hello_world() -> impl Responder {
    "hello, world!"
}
