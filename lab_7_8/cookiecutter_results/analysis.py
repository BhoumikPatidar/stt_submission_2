import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

reports_dir = "bandit_reports"
output_dir = "bandit_plots"
os.makedirs(output_dir, exist_ok=True)

sns.set(style="whitegrid", palette="muted", font_scale=1.2)

commit_numbers = []  
high_conf, med_conf, low_conf = [], [], []
high_sev, med_sev, low_sev = [], [], []

cwe_raw_counts = {}
cwe_commit_counts = {}

files = sorted(os.listdir(reports_dir))
for idx, filename in enumerate(files, start=1):
    if filename.endswith(".csv"):
        commit_numbers.append(idx)
        file_path = os.path.join(reports_dir, filename)
        df = pd.read_csv(file_path)
        
        hc = (df['issue_confidence'].str.upper() == 'HIGH').sum() if 'issue_confidence' in df.columns else 0
        mc = (df['issue_confidence'].str.upper() == 'MEDIUM').sum() if 'issue_confidence' in df.columns else 0
        lc = (df['issue_confidence'].str.upper() == 'LOW').sum() if 'issue_confidence' in df.columns else 0
        
        high_conf.append(hc)
        med_conf.append(mc)
        low_conf.append(lc)
        
        hs = (df['issue_severity'].str.upper() == 'HIGH').sum() if 'issue_severity' in df.columns else 0
        ms = (df['issue_severity'].str.upper() == 'MEDIUM').sum() if 'issue_severity' in df.columns else 0
        ls = (df['issue_severity'].str.upper() == 'LOW').sum() if 'issue_severity' in df.columns else 0
        
        high_sev.append(hs)
        med_sev.append(ms)
        low_sev.append(ls)
        
        if 'issue_cwe' in df.columns:
            for cwe in df['issue_cwe'].dropna():
                cwe_raw_counts[cwe] = cwe_raw_counts.get(cwe, 0) + 1
            unique_cwes = set(df['issue_cwe'].dropna())
            for cwe in unique_cwes:
                cwe_commit_counts[cwe] = cwe_commit_counts.get(cwe, 0) + 1

data_conf = pd.DataFrame({
    "Commit": commit_numbers,
    "High Confidence": high_conf,
    "Medium Confidence": med_conf,
    "Low Confidence": low_conf
})
conf_csv = os.path.join(output_dir, "confidence_issues_data.csv")
data_conf.to_csv(conf_csv, index=False)

data_sev = pd.DataFrame({
    "Commit": commit_numbers,
    "High Severity": high_sev,
    "Medium Severity": med_sev,
    "Low Severity": low_sev
})
sev_csv = os.path.join(output_dir, "severity_issues_data.csv")
data_sev.to_csv(sev_csv, index=False)


plt.figure(figsize=(12, 6))
sns.lineplot(x="Commit", y="High Confidence", data=data_conf, marker="o", label="High Confidence", color="darkred")
sns.lineplot(x="Commit", y="Medium Confidence", data=data_conf, marker="s", label="Medium Confidence", color="darkorange")
sns.lineplot(x="Commit", y="Low Confidence", data=data_conf, marker="^", label="Low Confidence", color="gold")
plt.title("Confidence Level Issues Across Commits")
plt.xlabel("Commit Number")
plt.ylabel("Number of Issues")
plt.legend()
plt.tight_layout()
conf_plot = os.path.join(output_dir, "confidence_issues_seaborn.png")
plt.savefig(conf_plot)
plt.close()


plt.figure(figsize=(12, 6))
sns.lineplot(x="Commit", y="High Severity", data=data_sev, marker="o", label="High Severity", color="darkred")
sns.lineplot(x="Commit", y="Medium Severity", data=data_sev, marker="s", label="Medium Severity", color="darkorange")
sns.lineplot(x="Commit", y="Low Severity", data=data_sev, marker="^", label="Low Severity", color="gold")
plt.title("Severity Level Issues Across Commits")
plt.xlabel("Commit Number")
plt.ylabel("Number of Issues")
plt.legend()
plt.tight_layout()
sev_plot = os.path.join(output_dir, "severity_issues_seaborn.png")
plt.savefig(sev_plot)
plt.close()


cwe_df = pd.DataFrame(list(cwe_raw_counts.items()), columns=["CWE", "Total_Count"])
cwe_df = cwe_df.sort_values(by="Total_Count", ascending=False)
cwe_csv = os.path.join(output_dir, "cwe_total_count.csv")
cwe_df.to_csv(cwe_csv, index=False)


plt.figure(figsize=(14, 7))
sns.barplot(x="CWE", y="Total_Count", data=cwe_df, palette="Blues_d")
plt.title("CWE Raw Total Occurrences Across Commits")
plt.xlabel("CWE")
plt.ylabel("Total Occurrences")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
cwe_plot = os.path.join(output_dir, "cwe_total_count_seaborn.png")
plt.savefig(cwe_plot)
plt.close()


print("Updated analysis complete!")
print(f"Confidence issues data CSV: {conf_csv}")
print(f"Severity issues data CSV: {sev_csv}")
print(f"CWE total count CSV: {cwe_csv}")
print(f"Confidence plot saved at: {conf_plot}")
print(f"Severity plot saved at: {sev_plot}")
print(f"CWE bar chart saved at: {cwe_plot}")
