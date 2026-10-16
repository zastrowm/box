//! Commands that produce workspace policy artifacts.

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use policy::{compose_action_schema, event_schema_source, generate_mcp_schema};

use crate::error::{BoxError, McpSchemaError};
use crate::record::config::egress::EgressSecret;
use crate::record::config::{read_mcp_servers, read_remote_mcp_servers};
use crate::record::layout::operator_home_directory;

const ACTION_SCHEMA_FILE: &str = "actions.cedarschema";
const EVENT_SCHEMA_FILE: &str = "events.dwschema";

pub(crate) async fn generate_schema(
    config: &Path,
    output_dir: &Path,
) -> Result<ExitCode, BoxError> {
    let working =
        std::env::current_dir().map_err(|source| McpSchemaError::WorkingDirectory { source })?;
    let config = working.join(config);
    let servers = read_mcp_servers(&config)?;
    let home = operator_home_directory()?;

    let mut generated = Vec::with_capacity(servers.len());
    for server in &servers {
        let response = crate::run::broker::mcp::list_tools(server, &home, &working)
            .await
            .map_err(|source| McpSchemaError::Discover {
                server: server.name.clone(),
                source,
            })?;
        let schema = generate_mcp_schema(&server.name, &response.to_string())
            .map_err(McpSchemaError::from)?;
        generated.push((server.name.clone(), schema));
    }

    // Remote MCP servers (`[egress.<name>]` speaking `mcp`) are discovered over HTTP by a direct
    // client, not spawned. There is no gateway before `run`, so the credential is resolved and
    // attached here rather than injected as a phantom.
    for server in read_remote_mcp_servers(&config)? {
        let auth = match &server.secret {
            Some(secret) => Some(resolve_auth(&server.name, secret)?),
            None => None,
        };
        let response = crate::run::broker::mcp_remote::list_tools(&server.url, auth)
            .await
            .map_err(|source| McpSchemaError::Discover {
                server: server.name.clone(),
                source,
            })?;
        let schema = generate_mcp_schema(&server.name, &response.to_string())
            .map_err(McpSchemaError::from)?;
        generated.push((server.name.clone(), schema));
    }

    let schemas = generated
        .iter()
        .map(|(server, schema)| (server.as_str(), schema.as_str()))
        .collect::<Vec<_>>();
    let actions = compose_action_schema(&schemas).map_err(McpSchemaError::from)?;
    let directory = working.join(output_dir);
    std::fs::create_dir_all(&directory).map_err(|source| McpSchemaError::Write {
        path: directory.clone(),
        source,
    })?;
    let action_path = directory.join(ACTION_SCHEMA_FILE);
    let event_path = directory.join(EVENT_SCHEMA_FILE);
    write_schema(&directory, &action_path, actions.as_bytes())?;
    write_schema(&directory, &event_path, event_schema_source().as_bytes())?;

    println!("Generated {}", action_path.display());
    println!("Generated {}", event_path.display());
    Ok(ExitCode::SUCCESS)
}

/// Resolve a remote server's credential and build the `(header, value)` to attach to its discovery
/// requests. `env://` reads the operator's variable through the sanctioned resolver; the value is
/// zeroized when it drops and never reaches the generated schema. Only header placement is
/// supported here — the common case, and the one github uses.
fn resolve_auth(server: &str, secret: &EgressSecret) -> Result<(String, String), McpSchemaError> {
    if let Some(placement) = &secret.placement
        && !placement.eq_ignore_ascii_case("header")
    {
        return Err(McpSchemaError::UnsupportedPlacement {
            server: server.to_string(),
            placement: placement.clone(),
        });
    }
    let locator = credentials::Locator::parse_uri(&secret.reference).map_err(|source| {
        McpSchemaError::Credential {
            server: server.to_string(),
            reason: source.to_string(),
        }
    })?;
    let token = credentials::Backend::local()
        .resolve(&locator)
        .map_err(|source| McpSchemaError::Credential {
            server: server.to_string(),
            reason: source.to_string(),
        })?;
    let header = secret
        .header
        .clone()
        .unwrap_or_else(|| "Authorization".to_string());
    let default_prefix = if header.eq_ignore_ascii_case("Authorization") {
        "Bearer "
    } else {
        ""
    };
    let prefix = secret
        .prefix
        .clone()
        .unwrap_or_else(|| default_prefix.to_string());
    Ok((header, format!("{prefix}{}", token.as_str())))
}

/// Ask a running box to re-read its policy file, and report the acknowledgement.
///
/// Connects to the box's control socket in `private/` — the channel the contained agent cannot
/// reach — sends a reload request, and blocks on the reply frame. Exits 0 when the box confirms
/// the reload applied, and non-zero with the box's reason when it refused. This is the
/// acknowledgement the `SIGUSR1` trigger cannot give: there, the outcome reaches only the box's
/// own stderr; here it comes back to the caller.
pub(crate) async fn reload(config: &Path) -> Result<ExitCode, BoxError> {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    let invocation =
        std::env::current_dir().map_err(|source| McpSchemaError::WorkingDirectory { source })?;
    let contract = crate::record::config::RunContract::read(config, &invocation)?;
    let socket = crate::record::layout::control_socket_path(contract.box_directory());

    let stream = match tokio::net::UnixStream::connect(&socket).await {
        Ok(stream) => stream,
        Err(source) => {
            eprintln!(
                "strands-box: cannot reach a running box at {} ({source})",
                socket.display()
            );
            eprintln!(
                "strands-box: the control socket exists only while `strands-box run` is live; is the box running?"
            );
            return Ok(ExitCode::FAILURE);
        }
    };

    let (read_half, mut write_half) = stream.into_split();
    if let Err(source) = write_half.write_all(b"{\"op\":\"reload\"}\n").await {
        eprintln!("strands-box: could not send the reload request: {source}");
        return Ok(ExitCode::FAILURE);
    }
    let _ = write_half.flush().await;

    let mut reply = String::new();
    if let Err(source) = tokio::io::BufReader::new(read_half)
        .read_line(&mut reply)
        .await
    {
        eprintln!("strands-box: no reply from the box: {source}");
        return Ok(ExitCode::FAILURE);
    }

    #[derive(serde::Deserialize)]
    struct Reply {
        ok: bool,
        subject: Option<String>,
        error: Option<String>,
    }
    let reply: Reply = match serde_json::from_str(reply.trim()) {
        Ok(reply) => reply,
        Err(source) => {
            eprintln!("strands-box: unreadable reply from the box: {source}");
            return Ok(ExitCode::FAILURE);
        }
    };

    if reply.ok {
        println!(
            "policy reloaded from {}",
            reply.subject.as_deref().unwrap_or("policy")
        );
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "policy reload refused: {}",
            reply.error.as_deref().unwrap_or("unknown reason")
        );
        eprintln!("the previous policy is still in force");
        Ok(ExitCode::FAILURE)
    }
}

fn write_schema(directory: &Path, path: &Path, schema: &[u8]) -> Result<(), McpSchemaError> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(directory).map_err(|source| McpSchemaError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .write_all(schema)
        .map_err(|source| McpSchemaError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    temporary
        .persist(path)
        .map_err(|error| McpSchemaError::Write {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use super::*;

    #[test]
    fn writing_a_schema_replaces_its_inode() {
        let directory = tempfile::tempdir().expect("schema directory");
        let path = directory.path().join(ACTION_SCHEMA_FILE);
        std::fs::write(&path, "old schema").expect("old schema");
        let old_inode = std::fs::metadata(&path).expect("old metadata").ino();

        write_schema(directory.path(), &path, b"new schema").expect("replace schema");

        let new_inode = std::fs::metadata(&path).expect("new metadata").ino();
        assert_ne!(
            new_inode, old_inode,
            "replacement must rename a separate temporary file over the target"
        );
        assert_eq!(std::fs::read(&path).expect("new schema"), b"new schema");
    }
}
