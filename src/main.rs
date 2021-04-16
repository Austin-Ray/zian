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
use actix_web::{App, HttpServer};
use structopt::StructOpt;
use thiserror::Error;
use zian::services::srchut::ISrcHutClient;
use zian::{
    github_pull_request_webhook, hello_world, AppConfig, DispatcherService, IDispatcherService,
    IGitHubPullRequestClient, ShimDispatcherService,
};

#[derive(StructOpt)]
struct Opt {
    /// Disable webhook signature verification.
    #[structopt(long)]
    insecure: bool,

    #[structopt(
        long = "github-secret",
        env = "GITHUB_SECRET",
        hide_env_values = true,
        required_if("insecure", "false")
    )]
    github_secret: Option<String>,

    #[structopt(short, long, default_value = "8080")]
    port: u16,

    #[structopt(short, long)]
    shim: bool,

    #[structopt(
        long = "sourcehut-webhook",
        required_if("shim", "true"),
        env = "SOURCEHUT_WEBHOOK",
        hide_env_values = true
    )]
    srchut_webhook: Option<String>,

    #[structopt(
        long = "sourcehut-secret",
        required_if("shim", "false"),
        env = "SOURCEHUT_SECRET",
        hide_env_values = true
    )]
    srchut_secret: Option<String>,
}

#[derive(Error, Debug)]
pub enum DispatcherErr {
    #[error("No sourcehut endpoint found in shim mode.")]
    NoSrcHutEndpoint,
    #[error("No sourcehut secret found.")]
    NoSrcSecret,
}

fn create_dispatcher(
    shim: bool,
    srchut_secret: &Option<String>,
    srchut_webhook: &Option<String>,
) -> Result<Box<dyn DispatcherService>, DispatcherErr> {
    let github_client = Box::new(IGitHubPullRequestClient {});
    if shim {
        match srchut_webhook {
            Some(webhook_url) => Ok(Box::new(ShimDispatcherService {
                github_client,
                srchut_endpoint: webhook_url.to_string(),
            })),
            None => Err(DispatcherErr::NoSrcHutEndpoint),
        }
    } else {
        let srchut_client = match &srchut_secret {
            Some(secret) => Ok(Box::new(ISrcHutClient {
                access_token: format!("{}", secret),
            })),
            None => Err(DispatcherErr::NoSrcSecret),
        }?;

        Ok(Box::new(IDispatcherService {
            github_client,
            srchut_client,
        }))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Webhook Control flow
    // ------------
    // 1. Pull request event comes from GitHub
    // 2. Server verifies secret header (X-Hub-Signature-256) from request.
    //    If not, HTTP 400
    // 3. Server checks if project is in allow-list (might not be necessary.)
    //    If not, HTTP 403 - project not supported.
    // 4. Server verifies list of modified files doesn't include:
    //    - `.build.yml`
    //    - `.builds/`
    //    If not, 403 - protected file modified
    // 5. Server verifies pull request has:
    //    - `.build.yml` or
    //    - `.builds/`
    // 6. Infuse build manifests with additional environment variables:
    //    - GITHUB_DELIVERY
    //    - GITHUB_EVENT
    //    - GITHUB_PR_NUMBER
    //    - GITHUB_PR_TITLE
    //    - GITHUB_PR_BODY
    //    - GITHUB_BASE_REPO
    //    - GITHUB_HEAD_REPO
    // 7. Set source to PR branch
    // 8. Submit build to builds.sr.ht using personal access token (temporary measure.)

    let opt = Opt::from_args();
    let insecure = opt.insecure;
    let gh_secret = opt.github_secret;
    let shim_mode = opt.shim;
    let srchut_secret = opt.srchut_secret;
    let srchut_endpoint = opt.srchut_webhook;

    HttpServer::new(move || {
        App::new()
            .data(AppConfig {
                insecure,
                github_secret: gh_secret.clone(),
                dispatcher: create_dispatcher(shim_mode, &srchut_secret, &srchut_endpoint).unwrap(),
            })
            .service(hello_world)
            .service(github_pull_request_webhook)
    })
    .bind(format!("127.0.0.1:{}", opt.port))?
    .run()
    .await
}
