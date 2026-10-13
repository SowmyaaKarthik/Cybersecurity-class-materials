# PECB Cybersecurity Foundation — Hospital Security Capstone

## Labs 4–8: Governance, Technical Controls, Log Monitoring, Incident Response, and Security Metrics

**Environment:** Kali Linux or another Linux training virtual machine  
**Scenario:** A fictional hospital protecting electronic health records (EHR), clinical applications, infrastructure, and medical-device services  
**Audience:** Cybersecurity Foundation learners

---

# How to Use This Lab Manual

This practical project demonstrates how cybersecurity principles can be applied in a hospital environment.

The labs build on one another:

1. **Lab 4 — Governance:** Define who is responsible for protecting hospital systems and information.
2. **Lab 5 — Technical Controls:** Restrict access to a test file and detect unauthorized changes using file-integrity checking.
3. **Lab 6 — Log Monitoring:** Identify suspicious authentication activity using Linux commands and Python.
4. **Lab 7 — Incident Response:** Practice recording, investigating, and responding to a simulated security incident.
5. **Lab 8 — Security Metrics:** Prepare a report that management can use to measure security performance and prioritize improvements.

Each lab contains:

- Learning objectives
- Hospital scenario
- Detailed theory
- Step-by-step practical instructions
- Command explanations
- Expected results
- Troubleshooting guidance
- Trainer discussion points
- Learner assessment questions

## Safety Requirements

All exercises use synthetic data and local training files.

- Do not use real patient information.
- Do not run these commands against production hospital systems.
- Do not disable real accounts, isolate medical devices, or interrupt clinical services.
- Use authorized systems and follow the instructor's guidance.
- Treat the policy examples as educational templates, not approved compliance documents.

---

# Initial Setup — Prepare the Project Directory

If you have already created the project directory during the earlier labs, continue using it. Otherwise, open a terminal in Kali Linux and run:

```bash
mkdir -p hospital-security/{governance,controls/demo,logs,incidents,reports}
cd hospital-security
```

### Explanation

- `mkdir` creates directories.
- `-p` creates missing parent directories and avoids errors when directories already exist.
- `{governance,controls/demo,logs,incidents,reports}` creates the directory structure.
- `cd hospital-security` moves into the project directory.

Verify the structure:

```bash
find . -maxdepth 2 -type d | sort
```

You should see the following directories:

```text
.
./controls
./controls/demo
./governance
./incidents
./logs
./reports
```

**Important:** Run the following lab commands from the `hospital-security` directory unless otherwise stated. Relative paths such as `logs/auth-demo.log` are interpreted from your current directory.

---

# Lab 4 — Establish Governance, Policies, and Responsibilities

## 1. Course Alignment

- Cybersecurity governance
- Security roles and responsibilities
- Policies, procedures, standards, and records
- Accountability and oversight
- Access control and risk management

## 2. Learning Objectives

By the end of this lab, learners should be able to:

1. Explain the importance of cybersecurity governance.
2. Identify the security responsibilities of different hospital departments.
3. Distinguish between policies, procedures, standards, and records.
4. Create a role-and-responsibility register.
5. Draft a basic access-control policy.
6. Explain why policies need formal approval and periodic review.
7. Connect governance requirements to practical security activities.

## 3. Hospital Scenario

A hospital operates an electronic health record system, a patient database, clinical applications, network infrastructure, backup systems, and connected medical devices.

Several departments participate in security, but their responsibilities are unclear.

Consider the following situation:

A hospital employee leaves the organization. Their network account and access to the EHR remain active because HR assumes IT will remove access, while IT assumes HR will submit a request.

The account remains available after the employee's departure.

This creates several potential risks:

- Unauthorized access to patient information
- Misuse of an active account
- Failure to comply with internal access-control requirements
- Inability to demonstrate that access was revoked appropriately
- Unclear accountability when an incident occurs

The problem is not necessarily a technical failure alone. It is also a governance failure.

The hospital needs clearly assigned responsibilities, documented procedures, approved policies, and evidence that required activities have been completed.

## 4. Detailed Theory

### 4.1 What Is Cybersecurity Governance?

Cybersecurity governance is the framework through which an organization directs, manages, and oversees cybersecurity activities.

It ensures that security decisions support organizational objectives, legal obligations, risk management, and business continuity.

In a hospital, cybersecurity governance must also consider patient safety and continuity of clinical services.

For example, management may need to decide whether to invest in stronger authentication, improve backup capabilities, or replace unsupported clinical systems.

These decisions involve more than technology. They require ownership, risk assessment, resources, and management approval.

Governance answers questions such as:

- Who approves cybersecurity policies?
- Who is responsible for implementing controls?
- Who accepts or treats security risks?
- Who reviews whether controls are working?
- Who receives reports about security incidents?
- Who authorizes exceptions to security requirements?

Without clear governance, departments may assume another team is responsible for an important task.

### 4.2 Policy, Procedure, Standard, and Record

These terms are related but serve different purposes.

| Document type | Purpose | Hospital example |
|---|---|---|
| Policy | States what is required | Every user must have an individual account wherever supported |
| Procedure | Explains how to perform an activity | Steps for requesting, approving, creating, reviewing, and revoking accounts |
| Standard | Defines a mandatory baseline | Approved technical requirements for authentication |
| Record | Provides evidence of an activity | An approved access request or completed access-review report |

**Example:**

A policy may state that departing employees must lose access promptly.

The procedure explains how HR notifies IT, how IT identifies the employee's accounts, how access is removed, and how completion is verified.

The record may be a ticket showing the departure notification, approvals, removal time, and verification.

The record provides evidence that the procedure was followed.

### 4.3 Accountability and Responsibility

A person or team may perform an activity without being the final authority for the decision.

- **Accountable:** Ultimately answerable for the outcome.
- **Responsible:** Performs or coordinates the work.
- **Consulted:** Provides input before the decision.
- **Informed:** Receives relevant updates.

For example, IT may be responsible for disabling an account, while the designated management role is accountable for ensuring that the hospital has an effective employee offboarding process.

The exact assignment depends on the hospital's organizational structure.

### 4.4 Least Privilege

The principle of least privilege means granting users only the permissions required for their assigned responsibilities.

Examples:

- A clinician receives the access needed for their authorized clinical duties.
- An HR employee receives access to relevant personnel systems.
- A facilities employee does not automatically receive access to patient records.
- A database administrator receives privileged access only when required and authorized.

Least privilege reduces the potential damage caused by mistakes, compromised credentials, or misuse of access.

### 4.5 Emergency Access

Hospitals must be able to respond to urgent clinical situations.

An emergency-access or break-glass process may allow authorized personnel to obtain exceptional access when normal access procedures are insufficient.

Such access should be:

- Limited to the emergency need
- Authorized according to the approved process
- Logged
- Reviewed afterward
- Protected against unnecessary or routine use

Security controls must support patient safety rather than introduce unmanaged clinical risks.

## 5. Practical Exercise

### Step 1 — Create the Governance Directory

Run:

```bash
mkdir -p governance
```

Check the directory:

```bash
ls -ld governance
```

The command displays information about the directory.

### Step 2 — Create the Roles Register

Run:

```bash
cat > governance/roles.csv <<'EOF'
Role,Responsibility
Hospital Management,Approve policy and risk appetite
Information Security Manager,Coordinate security program
Clinical IT,Secure EHR and clinical applications
Infrastructure Team,Manage servers and backups
HR,Support joiner and leaver processes
Clinical Engineering,Manage medical-device security
All Staff,Follow policy and report suspicious activity
Incident Response Team,Investigate and coordinate response
EOF
```

Display the file:

```bash
cat governance/roles.csv
```

### Understanding the Command

- `cat` displays file contents and can also create a file when combined with redirection.
- `>` creates a new file or replaces an existing file.
- `<<'EOF'` begins a multiline input block.
- The closing `EOF` marks the end of that block.
- The CSV format stores data in comma-separated fields.

**Important:** Using `>` overwrites an existing file with the same name. Check the target filename before executing commands that use it.

### Step 3 — Understand the Roles

| Role | Responsibility in practice | Example evidence |
|---|---|---|
| Hospital Management | Approves policy, resources, and risk appetite | Approval record or meeting minutes |
| Information Security Manager | Coordinates security activities and risk reviews | Risk register and security report |
| Clinical IT | Secures clinical applications and access | Access-review records and configuration evidence |
| Infrastructure Team | Manages servers, infrastructure, and backups | Backup logs and restore-test results |
| HR | Coordinates employee joiner, mover, and leaver notifications | Approved HR notification |
| Clinical Engineering | Coordinates medical-device security and maintenance | Device inventory and maintenance records |
| All Staff | Follows policy and reports suspicious events | Awareness completion records |
| Incident Response Team | Coordinates investigations and response | Incident timeline and investigation notes |

These are example responsibilities. The hospital should formally define its own role assignments and approval authority.

### Step 4 — Create an Access-Control Policy

Run:

```bash
cat > governance/access-policy.txt <<'EOF'
Hospital Access Control Policy

Purpose:
Protect hospital systems and information while supporting safe and timely patient care.

Scope:
Applies to staff, contractors, approved third parties, accounts, and systems within the hospital's defined scope.

Policy requirements:
1. Every user must have an individual account wherever the system supports individual identities.
2. Access must follow job responsibilities and the principle of least privilege.
3. Multi-factor authentication should be used for supported sensitive and remote access according to approved security requirements.
4. Access must be reviewed periodically and when a person's role changes.
5. Departing staff access must be revoked promptly through the approved leaver process.
6. Emergency access must be limited to the emergency need, logged, and reviewed afterward.
7. Shared and service accounts must have an approved owner and appropriate safeguards.
8. Access requests, approvals, changes, and reviews must be recorded.
9. Suspected unauthorized access must be reported through the incident-reporting process.

Ownership and review:
Policy owner: Information Security Manager
Approver: Hospital Management or the designated policy authority
Review: At the approved review interval and following significant legal, clinical, technical, or organizational changes.

Implementation note:
Applicable legal, regulatory, contractual, privacy, and clinical-safety requirements must be reviewed before formal approval. Exceptions must be documented, risk-assessed, approved by the authorized role, and periodically reviewed.
EOF
```

Display the policy:

```bash
cat governance/access-policy.txt
```

### Step 5 — Trace a Policy Requirement

Consider the requirement:

**“Departing staff access must be revoked promptly.”**

Discuss the following workflow:

1. HR records the approved departure.
2. HR notifies the designated access-management team.
3. The authorized team identifies the employee's accounts and access rights.
4. Access is revoked or disabled according to the approved procedure and timing requirements.
5. The action is documented in a ticket or controlled record.
6. The appropriate owner verifies completion, including remote and privileged access where applicable.
7. Delays or exceptions are escalated and risk-assessed.
8. Evidence is retained according to the organization's requirements.

The hospital must define its own time limits, approval process, and evidence-retention requirements.

### Step 6 — Create a Responsibility Worksheet

Complete the following table as a learner activity.

| Activity | Responsible role | Approver/accountable role | Evidence |
|---|---|---|---|
| Approve access policy |  |  |  |
| Approve a new user's access |  |  |  |
| Notify a staff departure |  |  |  |
| Remove departing user's access |  |  |  |
| Review privileged accounts |  |  |  |
| Review emergency access use |  |  |  |

Answers may vary, provided they reflect a coherent governance process without responsibility gaps.

## 6. Expected Results

The following files should exist:

```text
governance/
├── roles.csv
└── access-policy.txt
```

Verify:

```bash
ls -l governance/
```

## 7. Trainer Explanation

Explain that a policy is not effective simply because a document exists.

An effective governance process requires:

- Approval by an authorized role
- Clear ownership
- Communication to affected personnel
- Supporting procedures
- Evidence that required activities occurred
- Periodic review and improvement

The roles register defines intended responsibilities, while the policy defines expected security behavior.

Neither file alone proves that the hospital is complying with its requirements.

## 8. Learner Assessment Questions

1. Why is cybersecurity governance important in a hospital?
2. What is the difference between a policy and a procedure?
3. Why should HR and IT coordinate during employee offboarding?
4. What does least privilege mean?
5. Why should emergency access be logged and reviewed?
6. Who should approve an exception to a security policy?
7. What evidence can demonstrate that access was revoked?

---

# Lab 5 — Demonstrate Basic Technical Controls

## 1. Course Alignment

- Access control
- Information protection
- Cryptographic hashing
- File integrity
- Technical and administrative controls

## 2. Learning Objectives

By the end of this lab, learners should be able to:

1. Explain the purpose of file permissions.
2. Interpret basic Linux file-permission output.
3. Generate a SHA-256 hash.
4. Create an integrity baseline.
5. Detect a file change by comparing its hash against the baseline.
6. Explain the limitations of file permissions and hash verification.

## 3. Hospital Scenario

The hospital's training team maintains a synthetic record used for security demonstrations.

The team wants to restrict ordinary local access to the file and determine whether its content has changed after a trusted baseline is created.

This exercise demonstrates two controls:

- **File permissions** restrict access according to the local operating system's permission model.
- **Hash verification** detects changes by comparing a file's current digest against a previously recorded digest.

These controls are useful demonstrations but do not independently provide complete EHR or database security.

## 4. Detailed Theory

### 4.1 What Is Access Control?

Access control determines who or what can access a resource and which operations they are permitted to perform.

Examples include:

- Reading a file
- Modifying a record
- Opening an application
- Accessing a database
- Changing a configuration
- Administering a server

Access control may involve user identities, groups, permissions, roles, authentication, authorization, and monitoring.

### 4.2 Linux File Permissions

Linux commonly displays permissions for three categories:

- **User/owner (`u`)**
- **Group (`g`)**
- **Others (`o`)**

Permission symbols include:

- `r` — read
- `w` — write
- `x` — execute for files, or traverse/search for directories

For example:

```text
-rw-------
```

This means the owner can read and write the file, while group members and other users have no permissions through the file's ordinary permission bits.

The command:

```bash
chmod 600 filename
```

sets the owner's read/write permissions and removes group and other permissions.

This does not automatically protect a file against root access, a compromised owner account, insecure backups, or access through a separate application.

### 4.3 What Is a Cryptographic Hash?

A cryptographic hash function calculates a fixed-length digest from input data.

SHA-256 generates a 256-bit digest, normally displayed as 64 hexadecimal characters.

If the file's content changes, the resulting digest will normally change.

A hash can help detect whether content differs from a recorded baseline. However:

- It does not encrypt or hide the content.
- It does not identify who modified the file.
- It does not prove that the original file was trustworthy.
- It is less useful if an attacker can modify both the file and its baseline.

For stronger assurance, organizations may need protected audit logs, signed records, access controls, and trusted storage.

## 5. Practical Exercise

### Step 1 — Create a Synthetic Record

Run:

```bash
mkdir -p controls/demo

printf 'Synthetic patient record - TEST ONLY\n' \
  > controls/demo/patient-test.txt
```

Display the content:

```bash
cat controls/demo/patient-test.txt
```

Expected output:

```text
Synthetic patient record - TEST ONLY
```

Do not store real patient information in the file.

### Step 2 — Apply File Permissions

Run:

```bash
chmod 600 controls/demo/patient-test.txt
```

Display the permissions:

```bash
ls -l controls/demo/patient-test.txt
```

The permission field should resemble:

```text
-rw-------
```

For a more detailed view, run:

```bash
stat -c '%A %a %U %G %n' controls/demo/patient-test.txt
```

The numeric mode should be `600`.

**Interpretation:** The exercise demonstrates local file-permission control. It does not prove that an EHR application enforces the correct authorization rules or that information is encrypted.

### Step 3 — Generate a SHA-256 Hash

Run:

```bash
sha256sum controls/demo/patient-test.txt
```

The output contains a digest and the filename.

The digest depends on the exact file contents. Learners should calculate it themselves rather than copy another person's value.

### Step 4 — Save an Integrity Baseline

Run:

```bash
sha256sum controls/demo/patient-test.txt \
  > controls/baseline.sha256
```

Display the baseline:

```bash
cat controls/baseline.sha256
```

The file stores the expected digest and the path to the file being checked.

For this demonstration, the baseline is stored in the project directory. A production environment should protect baselines from unauthorized modification.

### Step 5 — Verify the File

Run:

```bash
sha256sum -c controls/baseline.sha256
```

Expected output:

```text
controls/demo/patient-test.txt: OK
```

This means the current file digest matches the recorded baseline.

It does not establish that the file is authentic in every possible sense. It establishes a match against the digest stored in the baseline.

### Step 6 — Modify the File

Run:

```bash
echo 'Modified test record' \
  >> controls/demo/patient-test.txt
```

The `>>` operator appends the new line to the file instead of replacing its existing contents.

Display the modified file:

```bash
cat controls/demo/patient-test.txt
```

### Step 7 — Check Integrity Again

Run:

```bash
sha256sum -c controls/baseline.sha256
```

Expected result:

```text
controls/demo/patient-test.txt: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
```

The precise wording may vary by distribution.

The check fails because the current file content no longer matches the original digest.

### Step 8 — Capture Evidence

Run:

```bash
{
  echo '=== File permissions ==='
  stat -c '%A %a %U %G %n' controls/demo/patient-test.txt

  echo
  echo '=== Current SHA-256 ==='
  sha256sum controls/demo/patient-test.txt

  echo
  echo '=== Baseline comparison ==='
  sha256sum -c controls/baseline.sha256
} 2>&1 | tee controls/control-test-results.txt
```

Because the file has already been modified, the baseline comparison should report a mismatch. This is expected.

## 6. Expected Results

```text
controls/
├── baseline.sha256
├── control-test-results.txt
└── demo/
    └── patient-test.txt
```

Verify:

```bash
find controls -maxdepth 2 -type f | sort
```

## 7. Troubleshooting

**Problem: `sha256sum: command not found`**

Check whether the standard core utilities are available in the training VM. Ask the instructor before installing packages.

**Problem: `No such file or directory`**

Confirm that you are working from the `hospital-security` directory.

**Problem: Verification still reports `OK` after modification**

Confirm that the file you modified matches the path stored in `controls/baseline.sha256` and that the baseline was created before the modification.

**Problem: Permission denied**

Check the current user and file ownership. Do not use elevated privileges simply to bypass the issue; understand the permission configuration first.

## 8. Trainer Explanation

This lab demonstrates a control and its limitations.

File permissions help restrict ordinary local access. Hash verification can reveal that content differs from a baseline.

However, a hash is not encryption, and file permissions alone do not provide complete information security.

A real hospital also needs appropriate identity management, application-level authorization, encryption where required, audit logging, backup protection, monitoring, and governance.

## 9. Learner Assessment Questions

1. What does `chmod 600` do?
2. What is the difference between a hash and encryption?
3. Why did the integrity check pass before modification?
4. Why did the integrity check fail afterward?
5. Why should the baseline be protected?
6. Can a hash identify who modified a file?
7. What additional controls would be required for a real EHR?

---

# Lab 6 — Detect Suspicious Activity in Logs

## 1. Course Alignment

- Security monitoring
- Authentication events
- Attack indicators
- Log analysis
- Incident detection and investigation

## 2. Learning Objectives

By the end of this lab, learners should be able to:

1. Explain the importance of authentication logs.
2. Filter log events using `grep`.
3. Count matching events using `wc -l`.
4. Use Python to summarize failed login attempts by account.
5. Distinguish a suspicious indicator from confirmed malicious activity.
6. Identify additional evidence needed during an investigation.

## 3. Hospital Scenario

The hospital monitoring team observes several failed login attempts against a privileged account.

Repeated failures might indicate:

- A user repeatedly entering an incorrect password
- An expired credential used by a service
- A configuration problem
- A forgotten password
- A potential password-guessing attempt

The team needs to examine the events and determine whether further investigation is justified.

A count alone does not prove an attack.

## 4. Detailed Theory

### 4.1 What Are Security Logs?

Logs are records of events that occur within systems, applications, networks, and security tools.

Authentication logs may record:

- Successful logins
- Failed logins
- Account names
- Event timestamps
- Source addresses, where available
- Authentication methods
- Account lockouts
- Session events

Logs help investigators reconstruct events and identify unusual activity.

### 4.2 Why Log Monitoring Matters

Without monitoring, suspicious activity may remain unnoticed.

For example, repeated failed logins may be visible in the authentication logs, but nobody may review them until an account is locked or a user reports a problem.

Monitoring helps organizations detect indicators that require investigation.

Effective logging also requires:

- Accurate timestamps
- Controlled access
- Protection against unauthorized changes
- Appropriate retention
- Correlation across relevant systems
- Defined alert-handling procedures

### 4.3 Suspicious Activity Is Not Proof

Three failed login attempts may justify review, but they do not prove that an attacker is present.

Investigators may need to examine:

- Source addresses
- Timing and frequency
- Successful logins before or after the failures
- Account lockouts
- MFA events
- Approved maintenance
- Known user issues
- Events from other systems

A detection threshold is a rule that helps determine when activity should be reviewed. Thresholds must be appropriate to the environment.

## 5. Practical Exercise

### Step 1 — Create a Synthetic Log

Run:

```bash
cat > logs/auth-demo.log <<'EOF'
2026-10-13 09:00:00 user=doctor01 event=login_success
2026-10-13 09:02:00 user=admin event=login_failure
2026-10-13 09:02:05 user=admin event=login_failure
2026-10-13 09:02:10 user=admin event=login_failure
2026-10-13 09:10:00 user=nurse01 event=login_success
EOF
```

Display the log:

```bash
cat logs/auth-demo.log
```

These are synthetic events created for training, not real hospital records.

### Step 2 — Filter Failed Login Attempts

Run:

```bash
grep 'event=login_failure' logs/auth-demo.log
```

The command prints each line containing the specified event.

Expected output:

```text
2026-10-13 09:02:00 user=admin event=login_failure
2026-10-13 09:02:05 user=admin event=login_failure
2026-10-13 09:02:10 user=admin event=login_failure
```

### Step 3 — Count the Events

Run:

```bash
grep 'event=login_failure' logs/auth-demo.log | wc -l
```

Expected output:

```text
3
```

The pipe (`|`) passes the output of the first command to the second command.

`wc -l` counts the lines it receives.

### Step 4 — Create the Python Analysis Script

Run the following command exactly as shown:

```bash
cat > logs/analyze_logs.py <<'PY'
from collections import Counter

failures = Counter()

with open("logs/auth-demo.log", encoding="utf-8") as file:
    for line in file:
        if "event=login_failure" in line:
            for field in line.split():
                if field.startswith("user="):
                    username = field.split("=", 1)[1]
                    failures[username] += 1

for username, count in failures.items():
    print(f"{username}: {count} failed login attempts")

    if count >= 3:
        print("  REVIEW: investigate this activity")
PY
```

### Understanding the Python Code

**Import the counter**

```python
from collections import Counter
```

`Counter` is a Python utility for counting occurrences of values.

**Initialize the counter**

```python
failures = Counter()
```

This creates an empty counter.

**Open the log**

```python
with open("logs/auth-demo.log", encoding="utf-8") as file:
```

The program opens the synthetic log file for reading. The `with` statement ensures the file is properly closed when the block finishes.

**Read each line**

```python
for line in file:
```

The program processes one log line at a time.

**Identify failed logins**

```python
if "event=login_failure" in line:
```

Only lines containing the failed-login event are processed further.

**Extract the username**

```python
for field in line.split():
    if field.startswith("user="):
        username = field.split("=", 1)[1]
        failures[username] += 1
```

The code splits the line into fields, locates the field beginning with `user=`, extracts the account name, and increments its count.

**Apply a training threshold**

```python
if count >= 3:
```

If an account has three or more failed attempts, the script prints a review message.

This threshold is for the exercise only. It is not a universal security rule.

### Step 5 — Run the Script

Run:

```bash
python3 logs/analyze_logs.py
```

Expected output:

```text
admin: 3 failed login attempts
  REVIEW: investigate this activity
```

### Step 6 — Save the Analysis Output

Run:

```bash
python3 logs/analyze_logs.py | tee logs/analysis-results.txt
```

Display the saved result:

```bash
cat logs/analysis-results.txt
```

The `tee` command displays the output and writes a copy to the specified file.

## 6. Investigation Exercise

Imagine you are the hospital's monitoring analyst.

Answer the following questions:

1. Were the failed attempts close together in time?
2. Was there a successful login to the same account?
3. Is `admin` an approved account name?
4. Could the activity be related to authorized testing or maintenance?
5. Are source addresses or device identifiers available?
6. Was MFA involved?
7. Were any account lockouts recorded?
8. What evidence would justify escalation?
9. Who is authorized to decide whether containment is necessary?

The synthetic log does not provide enough information to answer every question.

Identifying missing information is an important part of the exercise.

## 7. Expected Results

```text
logs/
├── auth-demo.log
├── analyze_logs.py
└── analysis-results.txt
```

Verify:

```bash
find logs -maxdepth 1 -type f | sort
```

## 8. Limitations

This script is a basic educational example, not a production security information and event management system (SIEM).

It does not:

- Validate log integrity
- Correlate events across systems
- Identify source IP addresses
- Interpret every log format
- Normalize time zones
- Determine whether an account was compromised
- Perform containment or incident response

Real monitoring requires reliable log collection, access control, retention, correlation, alert handling, and investigation procedures.

## 9. Trainer Explanation

The purpose of this lab is to move from raw events to an investigation signal.

The script detects three failed logins for one account and recommends review. It does not declare that the account has been compromised.

The learner must understand the difference between a technical observation, a suspicion, and a confirmed finding.

## 10. Learner Assessment Questions

1. What does `grep` do?
2. What does `wc -l` count?
3. Why does the Python script use `Counter`?
4. Why is three failed attempts not proof of an attack?
5. What additional evidence would help determine whether the activity is malicious?
6. Why should logs be protected against modification?
7. What is the difference between log monitoring and incident response?

---

# Lab 7 — Conduct a Hospital Incident-Response Exercise

## 1. Course Alignment

- Incident reporting
- Incident triage
- Containment
- Evidence preservation
- Investigation
- Recovery
- Communication
- Lessons learned

## 2. Learning Objectives

By the end of this lab, learners should be able to:

1. Explain a basic incident-response lifecycle.
2. Record initial facts without making unsupported conclusions.
3. Distinguish detection, triage, containment, investigation, and recovery.
4. Create a basic incident record.
5. Build a response timeline.
6. Explain why clinical safety affects containment decisions.
7. Identify the evidence required to validate recovery.

## 3. Hospital Scenario

The monitoring team detects repeated failed logins to a privileged account.

Shortly afterward, a staff member reports that patient records appear unavailable.

Possible causes include:

- An authentication problem
- An application outage
- A network problem
- An infrastructure failure
- A cybersecurity incident

The actual cause is unknown at the beginning of the exercise.

The objective is to practice a disciplined response instead of assuming the cause or taking disruptive action immediately.

## 4. Detailed Theory

### 4.1 What Is Incident Response?

Incident response is the coordinated process used to identify, assess, handle, and learn from events that may affect information or systems.

A practical sequence includes:

1. Report and record
2. Triage and assess
3. Contain through authorized actions
4. Investigate and preserve evidence
5. Recover and validate services
6. Communicate with authorized stakeholders
7. Review lessons and close the incident

These activities may overlap. The organization should follow its approved incident-response plan.

### 4.2 Incident Triage

Triage determines the urgency, scope, potential impact, and appropriate next steps.

Questions include:

- Which systems are affected?
- How many users are affected?
- Is patient care potentially affected?
- Is there evidence of unauthorized access?
- Is the event still ongoing?
- What evidence needs preservation?
- Who is authorized to make decisions?

Triage should distinguish confirmed facts from unverified reports and hypotheses.

### 4.3 Containment

Containment aims to limit harm while maintaining necessary services.

Possible actions might include restricting an account, isolating an affected endpoint, increasing monitoring, or applying an approved temporary control.

In a hospital, these decisions can affect patient care. Only authorized responders should take action, coordinating with clinical operations and following approved procedures.

**Do not perform containment actions against production systems during this exercise.**

### 4.4 Evidence Preservation

Evidence may include:

- Authentication logs
- Security alerts
- System-health records
- Application logs
- Approved change tickets
- User reports
- Timestamps and investigation notes

Preserve evidence according to approved procedures. Do not edit original logs or record assumptions as confirmed facts.

### 4.5 Recovery

Recovery is not simply restarting a system.

It includes confirming that:

- The service is available.
- The underlying problem has been addressed sufficiently.
- Relevant data and workflows are validated.
- Residual risks are documented.
- Required stakeholders have been informed.

The exact recovery criteria depend on the affected service and the hospital's procedures.

## 5. Practical Exercise

### Step 1 — Review the Incident Facts

Assume the following facts are known:

- Repeated failed logins appear in the synthetic authentication log.
- A staff member reports that patient records appear unavailable.
- The cause and scope are not yet confirmed.
- No production action has been authorized.

Classify the statements below.

| Statement | Classification | Explanation |
|---|---|---|
| Three failed login events are present in the training log | Confirmed within the exercise | The supplied log shows them |
| The privileged account was compromised | Hypothesis | Failed attempts do not prove compromise |
| A staff member reports that patient records are unavailable | Report received | The report has not yet been independently verified |
| A ransomware attack is underway | Hypothesis | No evidence provided confirms ransomware |
| Patient care may be affected | Potential impact to assess | Scope and clinical impact need validation |

### Step 2 — Create the Incident Record

Run:

```bash
cat > incidents/INC-001.txt <<'EOF'
Incident ID: INC-001
System: EHR / privileged account
Detection: Repeated failed login attempts and a report of unavailable patient records
Reported By: Training scenario - monitoring team and staff report
Detection Time: 2026-10-13 09:02 (synthetic exercise time)
Potential Impact: Unauthorized access or service disruption
Severity: To be determined by incident triage
Confirmed Facts: Repeated failed login events are present in the synthetic log; a staff member reports record unavailability
Initial Actions: Preserve relevant logs and notify the authorized response team
Containment: Pending authorized assessment
Investigation: Pending evidence review and scope confirmation
Recovery: Pending investigation and validation
Communication: Follow the approved incident communication plan
Lessons Learned: Pending incident closure
EOF
```

Display the incident record:

```bash
cat incidents/INC-001.txt
```

The timestamps are synthetic scenario data, not actual event times.

### Step 3 — Perform Initial Triage

Complete the table as a learner.

| Triage question | Learner's assessment |
|---|---|
| Which service is reportedly affected? | |
| Has the reported impact been independently verified? | |
| Are multiple users or locations affected? | |
| Could patient care be affected? | |
| Is there evidence of unauthorized successful access? | |
| Is there evidence of data alteration or exfiltration? | |
| Who is the authorized incident lead? | |
| What is the next safe action? | |

If the scenario does not provide sufficient evidence, write **Unknown**.

Recognizing uncertainty is better than making unsupported conclusions.

### Step 4 — Create a Response Timeline

Run:

```bash
cat > incidents/INC-001-timeline.csv <<'EOF'
Time,Event,Source,Confidence,Action or Decision,Owner
09:02,Repeated failed login events observed,Synthetic authentication log,Confirmed within exercise,Preserve log and notify response team,Monitoring team
09:05,Staff reports patient records unavailable,Staff report,Reported not independently verified,Validate scope and clinical impact,Incident lead
09:10,Scope assessment begins,Exercise assumption,Pending,Coordinate with Clinical IT and clinical operations,Incident response team
EOF
```

Display the timeline:

```bash
cat incidents/INC-001-timeline.csv
```

### Understanding the Timeline

- **Time:** When the event occurred or was reported.
- **Event:** What happened.
- **Source:** Where the information came from.
- **Confidence:** Whether the event is confirmed, reported, or uncertain.
- **Action or Decision:** What was done or decided.
- **Owner:** Who is responsible.

The entries are exercise assumptions. In a real incident, use actual times and sources. Never invent timestamps or state that an action occurred when it did not.

### Step 5 — Discuss Containment Options

For each action, discuss the necessary approvals and safety considerations.

| Possible action | Considerations |
|---|---|
| Temporarily restrict a suspected account | Confirm evidence, account criticality, authorized approval, and alternative clinical access |
| Isolate an affected endpoint or network segment | Assess clinical dependencies and coordinate with authorized IT and clinical operations |
| Preserve additional logs | Ensure collection is authorized and evidence is stored securely |
| Restore a service from backup | Validate the recovery approach and obtain the required approval |
| Notify management and clinical leadership | Follow the incident plan, severity criteria, and communication requirements |

Do not execute these actions against real systems as part of this lab.

### Step 6 — Record Investigation Questions

Document the questions an investigator should answer:

- Which authentication events occurred before and after the outage report?
- Was there a successful privileged login?
- Did the EHR or database report a service failure?
- Were there approved changes or maintenance activities?
- Are other systems affected?
- Is there evidence of unauthorized changes, access, or data transfer?
- What evidence must be preserved?
- Who is authorized to access the evidence?
- What criteria must be met before recovery is approved?

### Step 7 — Define Recovery Criteria

A recovery plan should define how authorized personnel will validate the service.

Possible criteria include:

- The system owner confirms service health.
- Authorized clinical users validate the relevant workflow through approved test methods.
- Data integrity checks are completed where appropriate.
- Monitoring indicates that the immediate symptoms have stopped.
- Any remaining risks or workarounds are documented.
- Required stakeholders are informed.

Actual recovery must follow the hospital's approved procedures and be performed by authorized personnel.

### Step 8 — Document Lessons Learned

After the exercise, answer:

1. What worked well?
2. What information was missing?
3. Were responsibilities clear?
4. Were clinical-safety concerns considered?
5. Was the evidence preserved?
6. Was the timeline understandable?
7. Were communications timely?
8. What corrective action is needed?
9. Who should own the corrective action?
10. When should progress be reviewed?

## 6. Expected Results

```text
incidents/
├── INC-001.txt
└── INC-001-timeline.csv
```

Verify:

```bash
find incidents -maxdepth 1 -type f | sort
```

## 7. Trainer Explanation

The incident record provides a structured summary of the event, while the timeline captures the sequence of observations and decisions.

The incident response process should avoid jumping to conclusions. Failed login attempts do not establish that an account was compromised, and a service outage does not automatically prove a cyberattack.

In a hospital, response decisions must also consider clinical safety, continuity of care, and the potential effects of containment actions.

## 8. Learner Assessment Questions

1. What is the purpose of incident triage?
2. Why should confirmed facts be separated from hypotheses?
3. What is the difference between containment and recovery?
4. Why is a timeline useful during an investigation?
5. Why should clinical operations be involved in potentially disruptive response decisions?
6. What evidence is needed before declaring recovery complete?
7. What is the purpose of a lessons-learned review?

---

# Lab 8 — Measure Security Performance and Report to Management

## 1. Course Alignment

- Security metrics
- Management reporting
- Risk treatment
- Corrective actions
- Continual improvement

## 2. Learning Objectives

By the end of this lab, learners should be able to:

1. Explain why cybersecurity performance must be measured.
2. Read and interpret a security-metrics register.
3. Distinguish a target, a current value, and a status.
4. Identify gaps that require corrective action.
5. Assign owners and target dates to improvement activities.
6. Prepare a management summary that supports decisions.

## 3. Hospital Scenario

Hospital management wants to understand whether the cybersecurity program is improving.

A list of policies is not enough. Management needs evidence that controls are operating and risks are being reduced.

The hospital wants to understand:

- Whether critical risks are being treated
- Whether staff complete security awareness activities
- Whether backups can be restored
- Whether privileged access is reviewed
- Whether incident-response exercises are conducted

The learner will prepare a basic metrics register, create a corrective-action plan, and write a management summary.

## 4. Detailed Theory

### 4.1 What Are Security Metrics?

Security metrics measure an aspect of the cybersecurity program.

Examples include:

- Percentage of critical risks with approved treatment
- Percentage of staff completing awareness training
- Number of successful backup restoration tests
- Percentage of privileged accounts reviewed
- Completion of incident-response exercises
- Number of overdue corrective actions

Metrics help management identify gaps, compare progress over time, and decide where resources are needed.

### 4.2 Target, Current Value, and Status

- **Metric:** What is being measured.
- **Target:** The intended result.
- **Current value:** The latest measured result.
- **Status:** Whether the result meets expectations or needs action.
- **Owner:** Who is responsible for measuring or improving the result.
- **Action:** What must happen to address a gap.

A useful metric must have a clear definition, a data source, an owner, and a reporting frequency.

### 4.3 Leading and Lagging Indicators

**Leading indicators** measure activities intended to reduce risk.

Examples:

- Completion of privileged-access reviews
- Completion of backup restoration tests
- Staff awareness completion
- Corrective actions completed on time

**Lagging indicators** measure outcomes that have already occurred.

Examples:

- Confirmed security incidents
- Service disruptions
- Data loss events
- Incident-related recovery time

Both types are useful.

A low number of reported incidents does not necessarily mean security is strong. It could also indicate poor monitoring or under-reporting.

### 4.4 Continual Improvement

Metrics should drive action.

For example, if privileged-access reviews are overdue, management should know:

- Which systems are affected
- Who owns the review
- Why the review is overdue
- What risk the delay creates
- When the review will be completed
- What evidence will demonstrate completion

A report should help management make decisions rather than simply display numbers.

## 5. Practical Exercise

### Step 1 — Create the Security Metrics Register

Run:

```bash
cat > reports/security-metrics.csv <<'EOF'
Metric,Target,Current,Status
Critical risks treated,100%,60%,Needs improvement
Staff awareness completion,95%,80%,Needs improvement
Backup restoration tests,Monthly,Not tested,Action required
Privileged access reviews,Monthly,Pending,Action required
Incident response exercises,Quarterly,Not completed,Action required
EOF
```

Display the file:

```bash
cat reports/security-metrics.csv
```

These values are synthetic training data. They are not measured results from a real hospital.

### Step 2 — Interpret the Metrics

| Metric | Meaning | Example management question |
|---|---|---|
| Critical risks treated | Whether the defined treatment target is being met | Which critical risks remain untreated? |
| Staff awareness completion | Whether staff in scope have completed the required awareness activity | Which departments have outstanding training? |
| Backup restoration tests | Whether backup recovery has been tested | When was the last successful restoration test? |
| Privileged access reviews | Whether powerful accounts are being reviewed | Were unnecessary or unowned privileges identified? |
| Incident-response exercises | Whether the response plan has been exercised | Were gaps identified and corrective actions assigned? |

Notice that the values do not all use the same measurement type.

For example, “Monthly” is a target frequency, while “Not tested” describes a current state.

A mature report should include the measurement period, last completion date, evidence source, and owner.

### Step 3 — Create a Corrective-Action Register

Run:

```bash
cat > reports/security-actions.csv <<'EOF'
Action ID,Gap,Proposed Action,Owner,Target Date,Status,Evidence of Completion
A-001,Critical risks treated is 60%,Review untreated critical risks and document approved treatment or risk acceptance,Information Security Manager,To be assigned,Open,Risk register and approval records
A-002,Awareness completion is 80%,Identify outstanding staff and coordinate completion,HR and Information Security,To be assigned,Open,Training completion report
A-003,Backup restore test not recorded,Schedule an authorized restore test and record validation,Infrastructure Team,To be assigned,Open,Approved restore-test report
A-004,Privileged access review pending,Complete review and document removals or approved exceptions,System Owners,To be assigned,Open,Access-review record
A-005,Incident response exercise not completed,Schedule a tabletop exercise and track lessons learned,Incident Response Team,To be assigned,Open,Exercise report and action tracker
EOF
```

Display the action register:

```bash
cat reports/security-actions.csv
```

### Understanding the Action Register

Each action should identify:

- A unique identifier
- The gap or problem
- The proposed corrective action
- The owner
- The target date
- The current status
- The evidence required to close the action

The target date is deliberately marked **To be assigned**.

Learners should not invent deadlines. The authorized manager should assign realistic dates based on risk, resources, and organizational requirements.

### Step 4 — Define Two Metrics in Detail

Complete the following table for two selected metrics.

| Field | Metric 1 | Metric 2 |
|---|---|---|
| Metric name | | |
| Exact definition | | |
| Target | | |
| Reporting frequency | | |
| Data source | | |
| Accountable owner | | |
| Current result | | |
| Evidence location | | |
| Corrective action if below target | | |

Example definition:

“Percentage of scheduled backup restoration tests completed successfully during the reporting month.”

The hospital must define which systems are in scope and what constitutes a successful restoration test.

### Step 5 — Create the Management Summary

Run:

```bash
cat > reports/management-summary.md <<'EOF'
# Hospital Cybersecurity — Management Summary

## Overall Position

The sample metrics show gaps in critical-risk treatment, staff awareness completion, backup restoration testing, privileged-access reviews, and incident-response exercises.

These values are exercise data and must not be presented as actual hospital performance.

## Key Concerns

1. Critical-risk treatment is below the sample target.
2. Staff awareness completion is below the sample target.
3. Evidence of a recent backup restoration test is not available in the sample register.
4. Privileged-access review is pending.
5. An incident-response exercise has not been recorded as completed.

## Recommended Management Decisions

- Confirm owners and realistic target dates for every corrective action.
- Review remaining critical risks and approve treatment or risk acceptance through the authorized process.
- Schedule an authorized backup restoration test and record its outcome.
- Complete the privileged-access review and document exceptions.
- Schedule an incident-response exercise that includes clinical-safety and communication considerations.

## Follow-up

Review progress at the next agreed governance meeting.

Require evidence of completion rather than verbal confirmation alone. Reassess overdue actions and any residual risk.
EOF
```

Display the report:

```bash
cat reports/management-summary.md
```

### Step 6 — Review the Report

Discuss the following questions:

- Can management understand what is wrong and why it matters?
- Does each action have an owner?
- Are target dates realistic and approved?
- Is there evidence supporting each reported value?
- Are unknown or unmeasured items clearly identified?
- Does the report distinguish activity completion from control effectiveness?
- Is there a process for reviewing overdue actions?

## 6. Expected Results

```text
reports/
├── security-metrics.csv
├── security-actions.csv
└── management-summary.md
```

Verify:

```bash
find reports -maxdepth 1 -type f | sort
```

## 7. Trainer Explanation

A metric can show that an activity occurred without proving that the control is effective.

For example, a successful backup job does not prove that the hospital can restore its data. A restoration test provides stronger evidence of recoverability.

Similarly, a completed access review is not enough if the review identified excessive privileges and no corrective action followed.

Management reporting should make risk understandable and support decisions about priorities, ownership, funding, exceptions, and follow-up.

## 8. Learner Assessment Questions

1. Why is a completed backup different from a successful restoration test?
2. Why does a metric need a clear definition and data source?
3. What is the difference between a target and a current value?
4. Why should each corrective action have an owner and target date?
5. What is the difference between a leading and a lagging indicator?
6. Why might a low incident count be misleading?
7. How can management verify that corrective actions were completed?

---

# 4. Connect the Labs to Hospital Security Decisions

The five labs form one connected security process.

Governance defines responsibilities. Technical controls help protect information. Monitoring identifies potential problems. Incident response coordinates investigation and recovery. Metrics help management assess progress.

| Hospital problem | Security response | Evidence from the project |
|---|---|---|
| Patient records may be accessed improperly | Individual accounts, least privilege, MFA where supported, and access reviews | `governance/access-policy.txt` and `governance/roles.csv` |
| There is no complete view of critical systems | Asset inventory and named ownership | Asset inventory from the earlier lab |
| Weaknesses have not been prioritized | Risk assessment and treatment planning | Risk register and risk scores from the earlier lab |
| Unauthorized changes may go unnoticed | Access restrictions, integrity verification, and audit logging | `controls/baseline.sha256` and `controls/control-test-results.txt` |
| Suspicious sign-ins are not reviewed | Log monitoring and investigation | `logs/analysis-results.txt` |
| Security incidents lack a clear response | Defined escalation, triage, response, recovery, and communication | `incidents/INC-001.txt` and `incidents/INC-001-timeline.csv` |
| Management cannot assess progress | Metrics, action owners, and continual improvement | `reports/security-metrics.csv`, `reports/security-actions.csv`, and `reports/management-summary.md` |

## Discussion Activity

Ask learners:

1. Which hospital problems could be addressed through technology?
2. Which problems require management approval or governance?
3. Why is a technical control not sufficient without ownership and monitoring?
4. How does incident-response evidence support future risk treatment?
5. How can management use metrics to decide which improvements should happen first?

Learners should support their answers with examples from the files created during the labs.

---

# 5. Final Capstone Deliverables

## Completion Checklist

- [ ] Project charter and defined scope from the earlier lab
- [ ] Hospital asset inventory
- [ ] Risk register with likelihood, impact, and treatment recommendations
- [ ] Governance roles and sample access-control policy
- [ ] Technical control demonstration and integrity-check results
- [ ] Log analysis results and investigation notes
- [ ] Incident record and response timeline
- [ ] Security metrics report, corrective-action register, and improvement plan

## Suggested Final Directory Structure

```text
hospital-security/
├── governance/
│   ├── roles.csv
│   └── access-policy.txt
├── controls/
│   ├── baseline.sha256
│   ├── control-test-results.txt
│   └── demo/
│       └── patient-test.txt
├── logs/
│   ├── auth-demo.log
│   ├── analyze_logs.py
│   └── analysis-results.txt
├── incidents/
│   ├── INC-001.txt
│   └── INC-001-timeline.csv
└── reports/
    ├── security-metrics.csv
    ├── security-actions.csv
    └── management-summary.md
```

Add the project charter, asset inventory, and risk register from the earlier labs to the same project directory.

## Final Reflection

Learners should answer the following questions in their own words:

1. Which security risk is most important for the fictional hospital, and why?
2. Which technical control did you demonstrate, and what are its limitations?
3. What additional evidence would you need before calling the failed logins a confirmed attack?
4. How should incident responders balance containment with patient safety?
5. Which management action should be prioritized first, and why?
6. What evidence would convince you that the hospital's security program is improving?
7. How do governance, technical controls, monitoring, incident response, and metrics work together?

## Final Reminder

The objective is not merely to execute commands or create files.

Learners should be able to explain:

- What each activity demonstrates
- What the results do and do not prove
- Who is responsible for the activity
- What evidence should be retained
- What decision should follow

In a real hospital, applicable legal, regulatory, privacy, contractual, and clinical-safety requirements must be reviewed before implementing policies or technical changes. All production activities must follow approved organizational procedures.
