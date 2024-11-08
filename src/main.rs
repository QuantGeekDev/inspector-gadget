use git2::{Repository};
use std::fs::{self, File};
use std::io::{Write, BufWriter};
use std::process::Command;

async fn download_repo(repo_url: &str, clone_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("git")
        .arg("clone")
        .arg(repo_url)
        .arg(clone_dir)
        .status()?;

    if !status.success() {
        return Err("Git clone failed".into());
    }

    Ok(())
}

fn analyze_git_history(repo_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let repo = Repository::open(repo_path)?;

    let sensitive_files = vec![".env", ".git-credentials", "config.json"];
    let mut findings = Vec::new();

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;

    for oid in revwalk {
        let commit = repo.find_commit(oid?)?;
        let tree = commit.tree()?;

        for entry in tree.iter() {
            let file_name = entry.name().unwrap_or("");

            if sensitive_files.contains(&file_name) {
                findings.push(format!(
                    "Sensitive file detected: '{}' in commit {}",
                    file_name,
                    commit.id()
                ));

                let object = entry.to_object(&repo)?;
                if let Some(git2::ObjectType::Blob) = object.kind() {
                    let content = object.as_blob().unwrap().content();
                    findings.push(format!("Contents of {}: {}", file_name, String::from_utf8_lossy(content)));
                }
            }
        }
    }

    Ok(findings)
}

fn write_results_to_file(results: Vec<String>, output_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);

    for result in results {
        writeln!(writer, "{}", result)?;
    }

    Ok(())
}

fn cleanup_repo(repo_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::remove_dir_all(repo_path)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo_url = "https://github.com/QuantGeekDev/inspector-gadget-ctf";
    let clone_dir = "./temp_repo";
    let output_file = "sensitive_file_report.txt";


    download_repo(repo_url, clone_dir).await?;

    let findings = analyze_git_history(clone_dir)?;

    if !findings.is_empty() {
        write_results_to_file(findings, output_file)?;
        println!("Findings written to {}", output_file);
    } else {
        println!("No sensitive files found.");
    }

    cleanup_repo(clone_dir)?;

    Ok(())
}
