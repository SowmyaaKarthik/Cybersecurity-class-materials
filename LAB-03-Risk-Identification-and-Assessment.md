# Lab 3 — Identify Threats, Vulnerabilities and Risks

## 1. Lab Overview

**Course:** PECB Cybersecurity Foundation  
**Topic:** Risk Identification, Analysis, Evaluation and Treatment  
**Environment:** Kali Linux or another Linux distribution  
**Tools:** Linux terminal, text editor, Python 3  
**Estimated duration:** 45–60 minutes

## 2. Learning Objectives

By completing this lab, you will be able to:

- Differentiate a threat, a vulnerability and a risk.
- Identify cybersecurity risks affecting a hospital environment.
- Create a simple risk register in CSV format.
- Calculate risk scores using likelihood × impact.
- Categorize risks as High, Medium or Low using the thresholds defined in this exercise.
- Explain why an organization needs documented risk evaluation and treatment criteria.

## 3. Scenario

You are supporting the cybersecurity team at a hospital. The hospital uses an Electronic Health Record (EHR) system, a patient database, staff accounts, connected medical devices and a hospital network.

The security team wants to document possible risks and prioritize them for further review.

For this lab, you will create a basic risk register and use a Python script to calculate a score for each risk. The data is fictional and intended for training only.

## 4. Understand the Key Concepts

| Concept | Meaning | Hospital example |
|---|---|---|
| Threat | A potential cause of harm | Ransomware targeting the patient database |
| Vulnerability | A weakness that could be exploited | Insufficiently tested recovery procedures |
| Risk | The potential effect when a threat exploits a vulnerability, considering likelihood and impact | Patient information or hospital services becoming unavailable following a ransomware incident |

**Remember:** A threat is the potential cause, a vulnerability is the weakness, and risk describes the potential consequences and their significance.

## 5. Prerequisites

Open a terminal and check that Python 3 is installed:

```bash
python3 --version
```

If Python 3 is not installed, install it using your distribution's approved package manager or ask your lab administrator.

## 6. Step 1 — Create the Lab Folders

From your home directory, create the project folders:

```bash
mkdir -p ~/cybersecurity-foundation-lab/risk
cd ~/cybersecurity-foundation-lab
```

Confirm your current location and folders:

```bash
pwd
ls
```

You should be working inside `cybersecurity-foundation-lab`, with a `risk` directory available.

> If you already created a main project folder for Labs 1 and 2, use that existing folder instead. Do not create a separate project unnecessarily.

## 7. Step 2 — Create the Risk Register

A risk register is a structured record of identified risks. It helps an organization document risk scenarios and support prioritization, treatment and follow-up.

Create the CSV file:

```bash
cat > risk/risk-register.csv <<'EOF'
ID,Asset,Threat,Vulnerability,Likelihood,Impact
R1,EHR System,Unauthorized access,Weak authentication,4,5
R2,Patient Database,Ransomware,Insufficient recovery testing,3,5
R3,Staff Accounts,Phishing,Limited awareness,4,4
R4,Medical Devices,Service disruption,Weak network separation,3,5
R5,Hospital Network,Unauthorized connection,Inadequate access restrictions,3,4
EOF
```

Check that the file exists and view its contents:

```bash
ls -l risk/
cat risk/risk-register.csv
```

### Understand the columns

- **ID:** Unique identifier for the risk.
- **Asset:** The system, account or service that could be affected.
- **Threat:** The potential cause of harm.
- **Vulnerability:** The weakness that could make the threat more likely to succeed.
- **Likelihood:** A training score from 1 to 5 indicating how likely the event is considered.
- **Impact:** A training score from 1 to 5 indicating the potential severity of the consequences.

For this exercise, 1 means the lowest level and 5 means the highest level. In a real assessment, the organization must define what each rating means.

## 8. Step 3 — Calculate Risk Scores with Python

For this lab, use the following simple calculation:

**Risk score = Likelihood × Impact**

The exercise uses these illustrative thresholds:

| Score | Classification |
|---:|---|
| 1–8 | Low |
| 9–15 | Medium |
| 16–25 | High |

These thresholds are for this exercise only. They are not a universal cybersecurity risk-scoring standard.

Create the Python script:

```bash
cat > risk/score_risks.py <<'PY'
import csv

with open("risk/risk-register.csv", newline="", encoding="utf-8") as file:
    reader = csv.DictReader(file)

    for risk in reader:
        likelihood = int(risk["Likelihood"])
        impact = int(risk["Impact"])
        score = likelihood * impact

        if score >= 16:
            level = "High"
        elif score >= 9:
            level = "Medium"
        else:
            level = "Low"

        print(
            f'{risk["ID"]}: {risk["Asset"]} | '
            f"Score: {score} | {level}"
        )
PY
```

### Understand the Python code

1. `import csv` loads Python's CSV-handling module.
2. `open(...)` opens the risk register.
3. `csv.DictReader(file)` reads each row using the column names.
4. `int(...)` converts the likelihood and impact values into integers.
5. `likelihood * impact` calculates the score.
6. The `if` and `elif` statements assign a classification using the thresholds above.
7. `print(...)` displays the risk ID, asset, score and classification.

## 9. Step 4 — Run the Risk-Scoring Script

Run the script from the main project folder:

```bash
python3 risk/score_risks.py
```

### Expected Output

```text
R1: EHR System | Score: 20 | High
R2: Patient Database | Score: 15 | Medium
R3: Staff Accounts | Score: 16 | High
R4: Medical Devices | Score: 15 | Medium
R5: Hospital Network | Score: 12 | Medium
```

Your output should match the sample data above.

**Important:** The script calculates scores and assigns labels. It does not determine the hospital's final risk response or replace a full risk assessment.

## 10. Step 5 — Interpret the Results

### R1 — EHR System: High (20)

- Threat: Unauthorized access
- Vulnerability: Weak authentication
- Potential consequence: Unauthorized viewing or alteration of patient records
- Possible treatment options: Strengthen authentication, apply least privilege, review access logs and investigate suspicious activity.

### R2 — Patient Database: Medium (15)

- Threat: Ransomware
- Vulnerability: Insufficient recovery testing
- Potential consequence: Patient data or services may become unavailable
- Possible treatment options: Maintain protected backups, test restoration procedures and develop recovery plans.

### R3 — Staff Accounts: High (16)

- Threat: Phishing
- Vulnerability: Limited awareness
- Potential consequence: An attacker may gain access through compromised staff credentials
- Possible treatment options: Provide awareness training, use multifactor authentication where appropriate and implement phishing reporting procedures.

### R4 — Medical Devices: Medium (15)

- Threat: Service disruption
- Vulnerability: Weak network separation
- Potential consequence: Connected medical services or devices may be disrupted
- Possible treatment options: Review network segmentation, restrict unnecessary communications and coordinate changes with clinical and medical-device teams.

### R5 — Hospital Network: Medium (12)

- Threat: Unauthorized connection
- Vulnerability: Inadequate access restrictions
- Potential consequence: An unauthorized device could connect to internal resources
- Possible treatment options: Strengthen network access controls, maintain an approved device inventory and monitor connections.

These are example treatment ideas, not a completed risk-treatment decision. The hospital should validate each scenario and select controls suitable for its environment.

## 11. Step 6 — Connect the Lab to Risk Management

Risk management involves more than calculating a score:

1. **Identify:** Document assets, threats, vulnerabilities and possible consequences.
2. **Analyze:** Estimate likelihood and impact using defined criteria.
3. **Evaluate:** Compare the results with the organization's risk acceptance criteria and priorities.
4. **Treat:** Decide whether to reduce, avoid, share/transfer or retain the risk, as appropriate.
5. **Monitor and review:** Reassess risks and confirm that selected treatments remain effective.

A high score may require urgent review, but the score alone does not automatically determine the response. For example, a hospital may need to escalate a medical-device risk because of patient-safety implications even when a simple numeric score is not the highest.

## 12. Step 7 — Learner Exercises

Complete these tasks independently:

- **Task 1:** Explain the difference between a threat, a vulnerability and a risk in your own words.
- **Task 2:** Add a sixth risk to `risk/risk-register.csv`, such as unauthorized access to a backup system. Choose a plausible likelihood and impact score from 1 to 5.
- **Task 3:** Run the Python script again and record the new score and classification.
- **Task 4:** Choose one risk and recommend two appropriate security controls.
- **Task 5:** Explain why a risk with a Medium score might still need urgent attention in a hospital.
- **Task 6:** Identify one limitation of using likelihood × impact as the only basis for prioritization.

After editing the CSV, rerun:

```bash
python3 risk/score_risks.py
```

## 13. Troubleshooting

### Error: `python3: command not found`

Python 3 may not be installed or may not be available on the system path. Check with your lab administrator or install it using your Linux distribution's approved package manager.

### Error: `FileNotFoundError: risk/risk-register.csv`

The script expects to be run from the main project folder. Check your location:

```bash
pwd
ls risk/
```

Then navigate to the folder containing the `risk` directory and rerun the script.

### The output does not match the expected output

Check that:

- The CSV column names match the supplied header.
- Likelihood and Impact contain numeric values from 1 to 5.
- You have not accidentally changed the sample rows.
- You are running the correct script from the main project folder.

## 14. Lab Completion Checklist

- [ ] I can explain threat, vulnerability and risk.
- [ ] I created `risk/risk-register.csv`.
- [ ] I created `risk/score_risks.py`.
- [ ] I ran the Python script successfully.
- [ ] I interpreted the sample scores.
- [ ] I identified at least one possible risk treatment.
- [ ] I understand that risk thresholds must be defined by the organization.

## 15. Key Takeaway

A risk register helps a hospital document and prioritize cybersecurity concerns. A simple scoring script is useful for learning and initial sorting, but real risk decisions must consider the organization's criteria, operational context, patient safety, legal and regulatory obligations, existing controls and risk appetite.

**End of Lab 3**
