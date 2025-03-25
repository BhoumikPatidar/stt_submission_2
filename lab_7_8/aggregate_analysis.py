import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


repos = {
    "deeplake": os.path.join("deeplake_results", "bandit_plots"),
    "flower": os.path.join("flower_results", "bandit_plots"),
    "cookiecutter": os.path.join("cookiecutter_results", "bandit_plots")
}

def load_severity_data(repo_csv_folder):
    file_path = os.path.join(repo_csv_folder, "severity_issues_data.csv")
    try:
        df = pd.read_csv(file_path)
        if "Commit" not in df.columns and "Commit_Number" in df.columns:
            df.rename(columns={"Commit_Number": "Commit"}, inplace=True)
        return df
    except Exception as e:
        print(f"Error loading severity data from {file_path}: {e}")
        return pd.DataFrame()

def load_cwe_data(repo_csv_folder):
    file_path = os.path.join(repo_csv_folder, "cwe_total_count.csv")
    try:
        df = pd.read_csv(file_path)
        return df
    except Exception as e:
        print(f"Error loading CWE data from {file_path}: {e}")
        return pd.DataFrame()

severity_data_list = []

for repo, folder in repos.items():
    print(f"Loading severity data for {repo} from folder '{folder}'")
    df = load_severity_data(folder)
    if not df.empty:
        df['Repository'] = repo
        severity_data_list.append(df)
    else:
        print(f"No severity data found for {repo}")

if not severity_data_list:
    raise ValueError("No severity data loaded for any repository. Check your CSV files and paths.")

combined_severity = pd.concat(severity_data_list, ignore_index=True)

sns.set(style="whitegrid", palette="muted", font_scale=1.2)


plt.figure(figsize=(12,6))
for repo in repos.keys():
    df_repo = combined_severity[combined_severity['Repository'] == repo]
    if df_repo.empty:
        print(f"No severity data for repository {repo}, skipping high severity plot.")
        continue
    plt.plot(df_repo['Commit'], df_repo['High Severity'], marker='o', label=repo.capitalize())
plt.title("Overall High Severity Trend Across Repositories")
plt.xlabel("Commit Number")
plt.ylabel("High Severity Issue Count")
plt.legend()
plt.tight_layout()
overall_high_severity_trend = os.path.join("bandit_plots", "overall_high_severity_trend.png")
plt.savefig(overall_high_severity_trend)
plt.close()
print(f"Overall high severity trend plot saved to {overall_high_severity_trend}")


plt.figure(figsize=(12,6))
for repo in repos.keys():
    df_repo = combined_severity[combined_severity['Repository'] == repo]
    if df_repo.empty:
        continue
    plt.plot(df_repo['Commit'], df_repo['High Severity'], marker='o', label=f"{repo.capitalize()} High")
    plt.plot(df_repo['Commit'], df_repo['Medium Severity'], marker='s', label=f"{repo.capitalize()} Medium")
    plt.plot(df_repo['Commit'], df_repo['Low Severity'], marker='^', label=f"{repo.capitalize()} Low")
plt.title("Overall Severity Comparison Across Repositories")
plt.xlabel("Commit Number")
plt.ylabel("Issue Count")
plt.legend(ncol=2, fontsize=8)
plt.tight_layout()
overall_severity_comparison = os.path.join("bandit_plots", "overall_severity_comparison.png")
plt.savefig(overall_severity_comparison)
plt.close()
print(f"Overall severity comparison plot saved to {overall_severity_comparison}")


overall_cwe_counts = {}
for repo, folder in repos.items():
    print(f"Aggregating CWE counts for {repo} from folder '{folder}'")
    cwe_df = load_cwe_data(folder)
    if cwe_df.empty:
        continue
    for idx, row in cwe_df.iterrows():
        cwe = row["CWE"]
        count = row["Total_Count"]
        overall_cwe_counts[cwe] = overall_cwe_counts.get(cwe, 0) + count

overall_cwe_df = pd.DataFrame(list(overall_cwe_counts.items()), columns=["CWE", "Total_Count"])
overall_cwe_df = overall_cwe_df.sort_values(by="Total_Count", ascending=False)

plt.figure(figsize=(14,7))
sns.barplot(x="CWE", y="Total_Count", data=overall_cwe_df, palette="Blues_d")
plt.title("Overall CWE Coverage Across Repositories")
plt.xlabel("CWE")
plt.ylabel("Total Occurrences")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
overall_cwe_coverage = os.path.join("bandit_plots", "overall_cwe_coverage.png")
plt.savefig(overall_cwe_coverage)
plt.close()
print(f"Overall CWE coverage plot saved to {overall_cwe_coverage}")

cwe_csv_overall = os.path.join("bandit_plots", "overall_cwe_total_count.csv")
overall_cwe_df.to_csv(cwe_csv_overall, index=False)
print(f"Overall CWE counts saved to {cwe_csv_overall}")
