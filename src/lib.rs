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
pub mod services;

use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use async_trait::async_trait;
use hmac::{Hmac, Mac, NewMac};
use serde::{Deserialize, Serialize};
use services::srchut::SrcHutClient;
use sha2::Sha256;
use thiserror::Error;

/// Webhook's `pull_request.head.repo` field
#[derive(Deserialize, Serialize, Debug)]
pub struct GitHubRepo {
    /// Full name of a repository e.g. Austin-Ray/zian
    pub full_name: String,
    pub private: bool,
}

/// Webhook's `pull_request.head` or `pull_request.base` field.
#[derive(Deserialize, Serialize, Debug)]
pub struct GitHubRepoMeta {
    /// Nested meta data without any user information.
    pub sha: String,
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
    pub dispatcher: Box<dyn DispatcherService>,
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

#[derive(Serialize, Deserialize)]
struct GitHubRepoFile {
    content: String,
    encoding: String,
}

async fn grab_build_file_content(
    repo_name: &str,
    git_sha: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let build_file = ".build.yml";
    let mut build_file_content = vec![];

    let req_url = format!(
        "https://api.github.com/repos/{}/contents/{}?ref={}",
        repo_name, build_file, git_sha
    );

    let content = reqwest::get(req_url)
        .await?
        .json::<GitHubRepoFile>()
        .await?;

    build_file_content.push(String::from_utf8(base64::decode(content.content)?)?);

    Ok(build_file_content)
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

    if let Err(e) = config
        .dispatcher
        .dispatch_pull_request(&payload, &raw_payload, headers)
        .await
    {
        return match e {
            DispatcherErr::NotSafe => HttpResponse::Forbidden().body(format!("{}", e)),
            DispatcherErr::Unrecoverable => HttpResponse::InternalServerError().finish(),
        };
    }

    HttpResponse::Ok().finish()
}

#[get("/")]
async fn hello_world() -> impl Responder {
    "hello, world!"
}

async fn is_safe_pull_request(
    github_client: &(dyn GitHubPullRequestClient + Send + Sync),
    url: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Found a forbidden file.
    Ok(github_client
        .files(url)
        .await?
        .iter()
        .any(|x| !is_safe_file(&x.filename)))
}

#[derive(Error, Debug)]
pub enum DispatcherErr {
    #[error("Pull request may expose secrets.")]
    NotSafe,
    #[error("")]
    Unrecoverable,
}

#[async_trait]
pub trait DispatcherService {
    async fn dispatch_pull_request(
        &self,
        webhook: &GitHubPullRequestWebhook,
        raw_webhook: &str,
        headers: &actix_web::http::header::HeaderMap,
    ) -> Result<(), DispatcherErr>;
}

pub struct IDispatcherService {
    pub github_client: Box<dyn GitHubPullRequestClient + Send + Sync>,
    pub srchut_client: Box<dyn SrcHutClient + Send + Sync>,
}

#[async_trait]
impl DispatcherService for IDispatcherService {
    async fn dispatch_pull_request(
        &self,
        webhook: &GitHubPullRequestWebhook,
        _raw_payload: &str,
        _headers: &actix_web::http::header::HeaderMap,
    ) -> Result<(), DispatcherErr> {
        let ghc = &self.github_client;
        let shc = &self.srchut_client;

        let is_safe: bool = is_safe_pull_request(ghc.as_ref(), &webhook.pull_request.url)
            .await
            .map_err(|_| DispatcherErr::Unrecoverable)?;

        if !is_safe {
            return Err(DispatcherErr::NotSafe);
        }

        let head_repo = &webhook.pull_request.head;

        let build_files_content =
            match grab_build_file_content(&head_repo.repo.full_name, &head_repo.sha).await {
                Ok(content) => content,
                Err(_) => return Err(DispatcherErr::Unrecoverable),
            };

        shc.submit_builds(&build_files_content)
            .await
            .map_err(|_| DispatcherErr::Unrecoverable)?;

        Ok(())
    }
}

pub struct ShimDispatcherService {
    pub srchut_endpoint: String,
    pub github_client: Box<dyn GitHubPullRequestClient + Send + Sync>,
}

#[async_trait]
impl DispatcherService for ShimDispatcherService {
    async fn dispatch_pull_request(
        &self,
        webhook: &GitHubPullRequestWebhook,
        raw_payload: &str,
        headers: &actix_web::http::header::HeaderMap,
    ) -> Result<(), DispatcherErr> {
        let ghc = &self.github_client;
        let is_safe: bool = is_safe_pull_request(ghc.as_ref(), &webhook.pull_request.url)
            .await
            .map_err(|_| DispatcherErr::Unrecoverable)?;

        if !is_safe {
            return Err(DispatcherErr::NotSafe);
        }

        let mut v: serde_json::Value =
            serde_json::from_str(raw_payload).map_err(|_| DispatcherErr::Unrecoverable)?;

        // Lie to SourceHut
        v["pull_request"]["base"]["repo"]["private"] = serde_json::json!(true);

        let resp = reqwest::Client::new()
            .post(&self.srchut_endpoint)
            .header(
                "X-GitHub-Event",
                headers
                    .get("X-GitHub-Event")
                    .ok_or(DispatcherErr::Unrecoverable)?,
            )
            .header(
                "X-GitHub-Delivery",
                headers
                    .get("X-GitHub-Delivery")
                    .ok_or(DispatcherErr::Unrecoverable)?,
            )
            .json(&v)
            .send()
            .await;

        if resp.is_err() {
            return Err(DispatcherErr::Unrecoverable);
        }

        Ok(())
    }
}
