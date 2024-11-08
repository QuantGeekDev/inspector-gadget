use git2::{Repository, ObjectType, Commit, Tree};
use std::fs::{self, File};
use std::io::{Write, BufWriter};
use std::path::{Path, PathBuf};
use std::collections::HashSet;
use std::error::Error;
use walkdir::WalkDir;
use tempfile::TempDir;
use url::Url;

#[derive(Debug)]
enum AnalyzerError {
    GitError(git2::Error),
    IoError(std::io::Error),
    InvalidPath(String),
    InvalidUrl(String),
    CloneError(String),
}

impl std::fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AnalyzerError::GitError(e) => write!(f, "Git error: {}", e),
            AnalyzerError::IoError(e) => write!(f, "IO error: {}", e),
            AnalyzerError::InvalidPath(p) => write!(f, "Invalid path: {}", p),
            AnalyzerError::InvalidUrl(u) => write!(f, "Invalid URL: {}", u),
            AnalyzerError::CloneError(e) => write!(f, "Clone error: {}", e),
        }
    }
}

impl Error for AnalyzerError {}

impl From<git2::Error> for AnalyzerError {
    fn from(err: git2::Error) -> Self {
        AnalyzerError::GitError(err)
    }
}

impl From<std::io::Error> for AnalyzerError {
    fn from(err: std::io::Error) -> Self {
        AnalyzerError::IoError(err)
    }
}

impl From<url::ParseError> for AnalyzerError {
    fn from(err: url::ParseError) -> Self {
        AnalyzerError::InvalidUrl(err.to_string())
    }
}

struct GitAnalyzer {
    sensitive_patterns: HashSet<String>,
    output_dir: PathBuf,
}

impl GitAnalyzer {
    fn new(output_dir: PathBuf) -> Self {
        let mut sensitive_patterns = HashSet::new();
        sensitive_patterns.extend(vec![
            ".env".to_string(),
            ".git-credentials".to_string(),
            "/config.json".to_string(),
            "id_rsa".to_string(),
            "id_ed25519".to_string(),
            "id_ecdsa".to_string(),
            "id_dsa".to_string(),
            ".npmrc".to_string(),
            ".pypirc".to_string(),
            "secrets.yaml".to_string(),
            "secrets.yml".to_string(),
            "secrets.json".to_string(),
            "credentials.json".to_string(),
            ".aws/credentials".to_string(),
            ".aws/config".to_string(),
            ".dockercfg".to_string(),
            ".docker/config.json".to_string(),
            "wp-config.php".to_string(),
            "htpasswd".to_string(),
            ".netrc".to_string(),
            ".bash_history".to_string(),
            ".zsh_history".to_string(),
            ".mysql_history".to_string(),
            ".psql_history".to_string(),
            "authorized_keys".to_string(),
            "known_hosts".to_string(),
            "key.pem".to_string(),
            "private.key".to_string(),
            "cert.pem".to_string(),
            "private.pem".to_string(),
            ".pgpass".to_string(),
            "proftpdpasswd".to_string(),
            "redis.conf".to_string(),
            "mongod.conf".to_string(),
            "master.key".to_string(),
            "settings.py".to_string(),
            "database.yml".to_string(),
            "production.rb".to_string(),
            "settings.json".to_string(),
            ".keystore".to_string(),
            ".jks".to_string(),
            "secret.key".to_string(),
            "oauth.json".to_string(),
            "auth.json".to_string(),
            "authentication.json".to_string(),
            ".ftpconfig".to_string(),
            "sftp-config.json".to_string(),
            "backup.sql".to_string(),
            "dump.sql".to_string(),
            "dump.rdb".to_string(),
        ]);

        GitAnalyzer {
            sensitive_patterns,
            output_dir,
        }
    }

    async fn clone_repository(&self, repo_url: &str) -> Result<TempDir, AnalyzerError> {
        let url = Url::parse(repo_url)?;
        if url.scheme() != "https" {
            return Err(AnalyzerError::InvalidUrl("Only HTTPS URLs are supported".to_string()));
        }

        let temp_dir = TempDir::new().map_err(|e| AnalyzerError::IoError(e))?;

        match Repository::clone(repo_url, temp_dir.path()) {
            Ok(_) => Ok(temp_dir),
            Err(e) => Err(AnalyzerError::CloneError(e.to_string())),
        }
    }

    fn find_local_repos(&self, search_path: &Path) -> Result<Vec<PathBuf>, AnalyzerError> {
        let mut repos = Vec::new();

        for entry in WalkDir::new(search_path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !Self::is_excluded_dir(e.path()))
        {
            let entry = entry.map_err(|e| AnalyzerError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )))?;

            if entry.file_type().is_dir() && entry.path().join(".git").exists() {
                repos.push(entry.path().to_path_buf());
            }
        }

        Ok(repos)
    }

    fn is_excluded_dir(path: &Path) -> bool {
        path.components().any(|c| {
            let s = c.as_os_str().to_string_lossy();
            s == "node_modules" || s == "target" || s == "vendor" || s.starts_with('.')
        })
    }

    async fn analyze_repository(&self, repo_path: &Path) -> Result<Vec<Finding>, AnalyzerError> {
        let repo = Repository::open(repo_path)?;
        let mut findings = Vec::new();
        self.analyze_working_directory(repo_path, &mut findings)?;
        self.analyze_git_history(&repo, &mut findings)?;
        Ok(findings)
    }

    fn analyze_working_directory(&self, repo_path: &Path, findings: &mut Vec<Finding>) -> Result<(), AnalyzerError> {
        for entry in WalkDir::new(repo_path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !Self::is_excluded_dir(e.path()))
        {
            let entry = entry.map_err(|e| AnalyzerError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )))?;

            if entry.file_type().is_file() {
                let file_name = entry.file_name().to_string_lossy();
                let file_path = entry.path().to_string_lossy();
                if self.is_sensitive_file(&file_path) {
                    findings.push(Finding {
                        file_name: file_name.to_string(),
                        location: file_path.to_string(),
                        commit_id: "working_directory".to_string(),
                        content_preview: Self::get_safe_content_preview(entry.path())?,
                    });
                }
            }
        }
        Ok(())
    }

    fn analyze_git_history(&self, repo: &Repository, findings: &mut Vec<Finding>) -> Result<(), AnalyzerError> {
        let mut revwalk = repo.revwalk()?;
        revwalk.push_head()?;
        revwalk.set_sorting(git2::Sort::TIME)?;

        for oid in revwalk {
            let commit = repo.find_commit(oid?)?;
            self.analyze_tree(&commit.tree()?, &commit, repo, findings)?;
        }

        Ok(())
    }

    fn analyze_tree(&self, tree: &Tree, commit: &Commit, repo: &Repository, findings: &mut Vec<Finding>) -> Result<(), AnalyzerError> {
        for entry in tree.iter() {
            if let Some(name) = entry.name() {
                if self.is_sensitive_file(name) {
                    if let Ok(object) = entry.to_object(repo) {
                        if object.kind() == Some(ObjectType::Blob) {
                            let blob = object.as_blob().unwrap();
                            let content_preview = String::from_utf8_lossy(&blob.content()[..])
                                .chars()
                                .take(100)
                                .collect::<String>();

                            findings.push(Finding {
                                file_name: name.to_string(),
                                location: entry.name().unwrap_or("unknown").to_string(),
                                commit_id: commit.id().to_string(),
                                content_preview,
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn is_sensitive_file(&self, filepath: &str) -> bool {
        self.sensitive_patterns.iter().any(|pattern| {
            filepath.ends_with(pattern) ||
                filepath.contains("secret") ||
                filepath.contains("credential") ||
                filepath.contains("password")
        }) && !filepath.ends_with("tsconfig.json")
    }

    fn get_safe_content_preview(path: &Path) -> Result<String, AnalyzerError> {
        let content = fs::read_to_string(path).map_err(AnalyzerError::IoError)?;
        Ok(content.chars().take(100).collect())
    }

    fn write_findings(&self, findings: &[Finding], repo_name: &str) -> Result<PathBuf, AnalyzerError> {
        fs::create_dir_all(&self.output_dir)?;
        let output_file = self.output_dir.join(format!("{}_analysis.txt", repo_name));
        let file = File::create(&output_file)?;
        let mut writer = BufWriter::new(file);

        writeln!(writer, "Security Analysis Report for {}\n", repo_name)?;
        writeln!(writer, "Generated: {}\n", chrono::Local::now())?;

        for finding in findings {
            writeln!(writer, "Found sensitive file: {}", finding.file_name)?;
            writeln!(writer, "Location: {}", finding.location)?;
            writeln!(writer, "Commit: {}", finding.commit_id)?;
            writeln!(writer, "Content Preview: {}\n", finding.content_preview)?;
        }

        Ok(output_file)
    }
}

#[derive(Debug)]
struct Finding {
    file_name: String,
    location: String,
    commit_id: String,
    content_preview: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let output_dir = PathBuf::from("./security_reports");
    let analyzer = GitAnalyzer::new(output_dir);

    let local_path = Path::new("/home/user/Documents");
    println!("\nSearching for local Git repositories...");

    match analyzer.find_local_repos(local_path) {
        Ok(repos) => {
            println!("Found {} repositories", repos.len());
            for repo_path in repos {
                println!("Analyzing repository: {}", repo_path.display());
                match analyzer.analyze_repository(&repo_path).await {
                    Ok(findings) => {
                        if !findings.is_empty() {
                            let repo_name = repo_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown");
                            match analyzer.write_findings(&findings, repo_name) {
                                Ok(output_file) => println!(
                                    "Analysis complete. Report written to: {}",
                                    output_file.display()
                                ),
                                Err(e) => eprintln!("Error writing findings: {}", e),
                            }
                        } else {
                            println!("No sensitive files found in {}", repo_path.display());
                        }
                    }
                    Err(e) => eprintln!("Error analyzing repository {}: {}", repo_path.display(), e),
                }
            }
        }
        Err(e) => eprintln!("Error finding local repositories: {}", e),
    }

    Ok(())
}