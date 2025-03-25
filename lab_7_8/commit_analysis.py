import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def compute_unique_cwe_counts(repo_reports_dir, output_csv):
    
    commit_numbers = []
    unique_cwe_counts = []
    unique_cwe_list = []
    
    try:
        files = sorted(os.listdir(repo_reports_dir))
    except FileNotFoundError as fnf_error:
        print(f"Directory not found: {repo_reports_dir}")
        raise fnf_error
    
    for idx, filename in enumerate(files, start=1):
        if filename.endswith(".csv"):
            commit_numbers.append(idx)
            file_path = os.path.join(repo_reports_dir, filename)
            try:
                df = pd.read_csv(file_path)
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                continue
            if 'issue_cwe' in df.columns:
                unique_cwes = set(df['issue_cwe'].dropna())
                unique_cwe_counts.append(len(unique_cwes))
                unique_cwe_list.append("; ".join(unique_cwes))
            else:
                unique_cwe_counts.append(0)
                unique_cwe_list.append("")
    
    df_output = pd.DataFrame({
        "Commit_Number": commit_numbers,
        "Unique_CWE_Count": unique_cwe_counts,
        "Unique_CWEs": unique_cwe_list
    })
    
    df_output.to_csv(output_csv, index=False)
    print(f"Unique CWE per commit data saved to {output_csv}")
    return df_output

def process_repository(repo_name):
   
    repo_reports_dir = os.path.join("bandit_reports", repo_name, "bandit_results")
    output_csv = os.path.join("bandit_plots", f"{repo_name}_unique_cwes.csv")
    plot_path = os.path.join("bandit_plots", f"{repo_name}_unique_cwe_trend.png")
    
    df_unique_cwe = compute_unique_cwe_counts(repo_reports_dir, output_csv)
    
    sns.set(style="whitegrid", palette="muted", font_scale=1.2)
    plt.figure(figsize=(12, 6))
    sns.lineplot(x="Commit_Number", y="Unique_CWE_Count", data=df_unique_cwe, marker="o", color="blue")
    plt.title(f"Unique CWE Count per Commit - {repo_name.capitalize()}")
    plt.xlabel("Commit Number")
    plt.ylabel("Unique CWE Count")
    plt.tight_layout()
    plt.savefig(plot_path)
    plt.close()
    print(f"Unique CWE trend plot saved to {plot_path}")

os.makedirs("bandit_plots", exist_ok=True)

repositories = ["deeplake", "flower", "cookiecutter"]

for repo in repositories:
    print(f"Processing repository: {repo}")
    process_repository(repo)
