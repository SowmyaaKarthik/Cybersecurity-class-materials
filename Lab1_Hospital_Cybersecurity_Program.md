# Lab 1 — Initiate the Hospital Cybersecurity Program

Course: PECB Cybersecurity Foundation | Topic: Cybersecurity Governance, Program Scope and Objectives

This lab will be conducted as a real-world hospital project. Rather than simply running terminal commands, learners will understand why the hospital needs cybersecurity, who authorizes the work, what systems must be protected, and how the initiative is formally documented.

## Lab overview

Objective

Establish the foundation of a hospital cybersecurity program before implementing technical security controls.

Suggested duration

45–60 minutes, including discussion and the terminal exercise.

Environment

Kali Linux or Ubuntu terminal with a normal user account and Python is not required for this lab.

Expected deliverable

A project folder, an initial cybersecurity project charter, defined scope, objectives and approval responsibilities.

## 1. Understand the hospital scenario

Start by explaining this scenario to the learners.

A hospital manages sensitive patient information and depends on IT systems for appointments, medical records, laboratory results, prescriptions, billing and clinical operations.

Management has identified several concerns:

- Patient records must not be viewed by unauthorized people.
- Medical information must not be altered without authorization.
- Critical systems must remain available to doctors and nurses.
- Backups must be available if systems fail or are affected by ransomware.
- Suspicious access and other security incidents must be detected and investigated.
- Staff must understand their security responsibilities.

The hospital therefore decides to initiate a formal cybersecurity program.

Ask the learners: If you were the hospital's cybersecurity team, would you immediately start installing antivirus software and configuring firewalls?

The correct approach is to establish the program first. The hospital needs authorization, defined objectives, a scope, accountable owners and a plan for making security decisions. Technical controls come later.

## 2. Understand the implementation flow

Step 1

### Identify the business problem

Why does the hospital need cybersecurity?

Step 2

### Obtain management sponsorship

Who authorizes the program and provides resources?

Step 3

### Define security objectives

What outcomes must the program achieve?

Step 4

### Define the scope

Which systems, people and processes are included?

Step 5

### Assign responsibilities

Who approves policies, accepts risks and implements controls?

Step 6

### Create the project charter

How is the initiative formally recorded?

Step 7

### Review and approve

Has management authorized the next stage?

Output: Approved cybersecurity program initiation

The hospital is ready to proceed to asset identification and risk assessment.

## 3. Step 1 — Open the Linux terminal and identify the environment

### What the trainer explains

Before creating the project, we need a working environment. We will use a Linux terminal to create and maintain the hospital's cybersecurity documentation.

The terminal allows us to create folders, store project documents, inspect files and later run basic security checks.

### Practical 1.1 — Open the terminal

In Kali Linux, open Terminal from the applications menu. In Ubuntu, open Terminal from the applications menu or press `Ctrl + Alt + T`.

Run the following commands one at a time.

Command 1: Identify the logged-in user

```
whoami
```

Expected output will be similar to:

```
student
```

Your actual output may be different.

Explanation: This identifies the Linux account being used. In a hospital, individual accounts are important because activities should be attributable to a specific user.

Command 2: Display the current working directory

```
pwd
```

Example output:

```
/home/student
```

Explanation: `pwd` means print working directory. It tells us where the terminal is currently operating. This helps us avoid creating project files in the wrong location.

Command 3: Display the system date and time

```
date
```

Explanation: Security documentation and incident records depend on accurate timestamps. In a real hospital, system clocks should be synchronized with an approved time source.

Command 4: Identify the operating system

```
cat /etc/os-release
```

Look for fields such as `NAME` and `VERSION`.

Explanation: This identifies the Linux distribution. The exact commands and available security tools can differ between systems.

### Learner checkpoint

Ask learners to explain:

- Which user account are you using?
- Where are you working?
- Which operating system is running?

Do not proceed until learners can identify their environment and understand why individual accounts matter.

## 4. Step 2 — Create the hospital cybersecurity project workspace

### What the trainer explains

The hospital needs a central, organized location for its cybersecurity project documents. We will create separate directories for governance, assets, risks, controls, logs, incidents and reports.

These folders represent the workstreams of the larger project. They are not security controls themselves; they are a way to organize the implementation.

### Practical 2.1 — Create the project directories

Run this command:

```
mkdir -p hospital-cybersecurity/{governance,inventory,risk,controls,logs,incidents,reports}
```

What does it mean?

- `mkdir` creates directories.
- `-p` creates any missing parent directories and avoids an error if the directories already exist.
- `hospital-cybersecurity` is the main project directory.
- The items inside `{...}` are the subdirectories to create.

The resulting structure will be:

```
hospital-cybersecurity/
├── governance/
├── inventory/
├── risk/
├── controls/
├── logs/
├── incidents/
└── reports/
```

### Practical 2.2 — Enter the project directory

```
cd hospital-cybersecurity
```

Verify your location:

```
pwd
```

Your output should end with:

```
hospital-cybersecurity
```

### Practical 2.3 — Verify the directories

```
ls -la
```

You should see the seven project directories, along with `.` and `..`.

If the `tree` command is installed, you can also use:

```
tree
```

If `tree` is unavailable, `ls -la` is sufficient for this lab.

Trainer explanation: We are establishing the workspace before creating individual documents. Later, the asset inventory will be stored under `inventory/`, the risk register under `risk/`, and the incident record under `incidents/`.

## 5. Step 3 — Define the hospital's cybersecurity objectives

Before writing the charter, learners need to decide what the hospital wants to achieve.

### What the trainer explains

Cybersecurity objectives should be connected to business and patient-care requirements. The hospital does not implement security merely to install products; it implements security to reduce risk and protect essential services.

Use the CIA triad to explain the first three objectives.

Confidentiality

Only authorized people should access patient records. For example, a billing employee should not automatically receive unrestricted access to clinical notes.

Integrity

Patient information must remain accurate and protected from unauthorized changes. Incorrect medical information can affect clinical decisions.

Availability

Authorized clinical staff must be able to access essential systems when needed. Backups, recovery plans and resilient infrastructure help support availability.

Add two supporting objectives:

- Detection and response: Identify suspicious activity, report incidents and respond according to an approved process.
- Continual improvement: Review risks, test controls, train staff and correct weaknesses.

### Practical 3.1 — Create the objectives document

From inside `hospital-cybersecurity`, run:

```
cat > governance/security-objectives.txt <<'EOF'
Hospital Cybersecurity Program — Objectives

1. Confidentiality
Protect patient information against unauthorized access and disclosure.

2. Integrity
Protect medical records against unauthorized or inappropriate modification.

3. Availability
Maintain access to critical hospital systems and establish recovery capabilities.

4. Detection and Response
Identify suspicious activity, report incidents and coordinate an appropriate response.

5. Continual Improvement
Review risks, assess control effectiveness and improve the cybersecurity program.
EOF
```

Display the file:

```
cat governance/security-objectives.txt
```

What does `cat > filename` do? It creates a file or replaces its existing contents with the text provided. `EOF` marks the beginning and end of the text block.

Important: This command is safe for a new training file, but `>` overwrites an existing file of the same name. Learners should understand this behavior before using redirection on important files.

### Learner checkpoint

Ask the learners to give one example of a confidentiality, integrity and availability failure in a hospital.

For example, unauthorized disclosure of patient records is a confidentiality failure; unauthorized alteration of a prescription is an integrity failure; and an unavailable EHR system is an availability failure.

## 6. Step 4 — Define what is included in the cybersecurity program

### What the trainer explains

The scope defines which systems, users, processes and locations are covered by the program. If scope is unclear, important assets can be overlooked or responsibilities can be disputed.

For this exercise, the hospital will initially include the following systems.

| System or area                         | Why it is in scope                                |
| -------------------------------------- | ------------------------------------------------- |
| Electronic Health Records (EHR)        | Contains sensitive patient information            |
| Patient databases                      | Stores medical history and related records        |
| Servers and supporting infrastructure  | Hosts critical hospital applications              |
| Staff accounts and privileged accounts | Control access to systems and information         |
| Hospital network and remote access     | Connect users, systems and external services      |
| Backup and recovery systems            | Support restoration after disruption              |
| Connected clinical devices             | May affect clinical operations and patient safety |
| Relevant staff and third-party access  | People and suppliers can introduce security risks |

A scope statement should also identify boundaries and exclusions. For example, a third-party cloud service may be included for risk oversight even if the hospital does not directly administer its underlying infrastructure. An exclusion must be documented and approved, not assumed.

### Practical 4.1 — Create the scope document

```
cat > governance/program-scope.txt <<'EOF'
Hospital Cybersecurity Program — Scope

IN SCOPE
- Electronic Health Records (EHR)
- Patient databases
- Hospital servers and supporting infrastructure
- Staff and privileged accounts
- Hospital network and approved remote access
- Backup and recovery systems
- Connected clinical devices
- Relevant staff, contractors and third-party access

BOUNDARIES
The program covers the identification and protection of hospital
information assets, security risks, access, monitoring, incident
response and recovery arrangements.

EXCLUSIONS
No exclusions have been approved at project initiation.
Any proposed exclusion must be documented, assessed for risk
and approved by the authorized hospital decision-maker.

ASSUMPTION
The final inventory and exact technical boundaries will be
confirmed with system owners during the asset-identification phase.
EOF
```

Display the document:

```
cat governance/program-scope.txt
```

### Trainer discussion

Ask: “If the hospital uses an external provider to host its EHR, can we exclude the provider from all cybersecurity discussions?”

No. The hospital still needs to understand relevant provider risks, contractual responsibilities, access arrangements, incident notification and recovery obligations. Responsibility for operating individual controls may be shared, but risks must not disappear simply because a service is outsourced.

## 7. Step 5 — Establish who is responsible for security decisions

### What the trainer explains

A cybersecurity program needs clear accountability. Technical teams can implement controls, but they do not automatically have the authority to accept business risks, approve hospital-wide policies or decide which clinical services may be interrupted.

Use the following fictional responsibility structure for the exercise.

Hospital Management

Sponsors the program, approves its direction and authorizes resources.


Information Security Manager (or CISO)

Coordinates the cybersecurity program, maintains the documentation, reports progress and risks to management and works with technical and business teams. This role manages the program; it does not own every risk.

IT Operations

Implements and operates technical controls such as account management, backups, patching, logging and network configuration, following approved policies and requirements.

System and Data Owners

Business or clinical owners of systems and information, for example the head of medical records for the EHR. They help define access needs, understand the impact of loss, and accept or reject residual risk for their systems.

Clinical Leadership

Advises on patient-safety impact and clinical availability needs. For example, they help decide which systems cannot be interrupted and what downtime procedures are acceptable.

Legal, Compliance and Privacy

Identify applicable legal, regulatory and contractual obligations, including privacy requirements for patient data, and advise on breach and incident notification duties.

All Staff and Third Parties

Follow security policies, protect their credentials, report suspicious activity and meet contractual security obligations.

### Decision responsibility table

| Decision or activity                          | Who is accountable (A)       | Who carries it out (R)                |
| --------------------------------------------- | ---------------------------- | ------------------------------------- |
| Approve the cybersecurity program and budget  | Hospital Management          | Information Security Manager          |
| Approve the cybersecurity policy              | Hospital Management          | Information Security Manager          |
| Accept residual risk for a clinical system    | System/Data Owner            | Information Security Manager (advises)|
| Configure and operate technical controls      | IT Operations manager        | IT Operations                         |
| Decide acceptable downtime for patient care   | Clinical Leadership          | System/Data Owner, IT Operations      |
| Confirm legal and privacy obligations         | Legal, Compliance and Privacy| Legal, Compliance and Privacy         |

Trainer note: this is a simplified example. A real hospital may use different titles, and the table should be agreed with management. The key idea is that the person who runs a control is not automatically the person who accepts the risk.

### Practical 5.1 — Create the roles and responsibilities document

From inside `hospital-cybersecurity`, run:

```
cat > governance/roles-responsibilities.txt <<'EOF'
Hospital Cybersecurity Program — Roles and Responsibilities

1. Hospital Management
Sponsors the program, approves its direction, approves the cybersecurity
policy and authorizes resources.

2. Information Security Manager (or CISO)
Coordinates the program, maintains documentation, reports progress and
risks to management and works with technical and business teams.

3. IT Operations
Implements and operates technical controls under approved policies.

4. System and Data Owners
Define access needs and impact of loss for their systems and accept or
reject residual risk for those systems.

5. Clinical Leadership
Advises on patient-safety impact and acceptable downtime.

6. Legal, Compliance and Privacy
Identify legal, regulatory and contractual obligations, including
privacy and notification requirements.

7. All Staff and Third Parties
Follow security policies, protect credentials, report suspicious
activity and meet contractual security obligations.

KEY PRINCIPLE
The person who operates a control is not automatically the person who
accepts the risk. Risk acceptance belongs to an authorized owner.
EOF
```

Display the file:

```
cat governance/roles-responsibilities.txt
```

### Learner checkpoint

Ask learners:

- Who should approve the cybersecurity policy?
- Can the IT administrator alone decide to accept the risk of an unpatched EHR server? Why not?
- Why does clinical leadership need to be involved in decisions about downtime?

Expected answers: Hospital Management approves the policy. The IT administrator can report the risk and recommend a fix, but the system owner (with management as needed) accepts the risk, because the decision affects patient care and the business, not only IT. Clinical leadership understands the patient-safety impact of interruptions.

## 8. Step 6 — Create the cybersecurity project charter

### What the trainer explains

A project charter is the formal record that starts the initiative. It states why the program exists, what it will cover, who sponsors it and what success looks like. It gives the team the authority to proceed and gives management something concrete to approve.

The charter brings together the work done in earlier steps: the business problem, the objectives, the scope and the responsibilities.

A basic charter should contain:

- Project name and purpose
- Business background and justification
- Sponsor and program manager
- Objectives (from Step 3)
- Scope summary (from Step 4)
- Roles and responsibilities (from Step 5)
- Assumptions and constraints
- Success criteria
- Next steps
- Approval section

### Practical 6.1 — Create the charter

From inside `hospital-cybersecurity`, run:

```
cat > governance/project-charter.txt <<'EOF'
HOSPITAL CYBERSECURITY PROGRAM — PROJECT CHARTER

1. PROJECT NAME
Hospital Cybersecurity Program

2. PURPOSE
To establish a formal, managed cybersecurity program that protects
patient information and critical hospital services.

3. BUSINESS BACKGROUND
The hospital depends on IT systems for appointments, medical records,
laboratory results, prescriptions, billing and clinical operations.
Management has identified concerns about unauthorized access to patient
records, unauthorized changes to medical information, availability of
critical systems, ransomware and backup readiness, detection of
suspicious activity, and staff awareness.

4. SPONSOR AND PROGRAM MANAGER
Sponsor: Hospital Management
Program Manager: Information Security Manager

5. OBJECTIVES
See governance/security-objectives.txt
- Confidentiality
- Integrity
- Availability
- Detection and Response
- Continual Improvement

6. SCOPE
See governance/program-scope.txt
Includes EHR, patient databases, servers, staff and privileged accounts,
network and remote access, backup and recovery, connected clinical
devices, and relevant staff and third-party access.

7. ROLES AND RESPONSIBILITIES
See governance/roles-responsibilities.txt

8. ASSUMPTIONS
- Management will provide the resources needed for the next phase.
- System owners will support the asset-identification activities.
- The detailed asset inventory will be completed in the next phase.

9. CONSTRAINTS
- Patient care must not be interrupted by program activities.
- Applicable legal, regulatory and contractual obligations must be met.

10. SUCCESS CRITERIA FOR THIS PHASE
- Objectives, scope and responsibilities are documented.
- The charter is reviewed and approved by management.
- The program is authorized to proceed to asset identification
  and risk assessment.

11. NEXT STEPS
- Identify and classify information assets.
- Assess cybersecurity risks.
- Select and plan controls based on risk.
EOF
```

Now add a creation date to the end of the file:

```
echo "Charter created on: $(date +%F)" >> governance/project-charter.txt
```

Display the charter:

```
cat governance/project-charter.txt
```

What is the difference between `>` and `>>`?

- `>` creates the file or replaces its existing contents.
- `>>` appends text to the end of the file and keeps what is already there.
- `$(date +%F)` inserts the current date in year-month-day format.

Using `>>` here is important. If we had used `>` the whole charter would have been replaced by a single date line.

### Learner checkpoint

Ask learners to find, in their charter, the sponsor, one objective, one in-scope system and one success criterion. If a learner cannot find them, the charter is not clear enough for management to approve.

## 9. Step 7 — Review and approve the charter

### What the trainer explains

A charter has no authority until the right people have reviewed and approved it. Approval shows that management understands the scope, objectives and responsibilities and is committing to the program. Approval also gives the program a baseline: later changes to scope or objectives should be recorded and approved, not made silently.

In this lab we will simulate approval by creating an approval record and then protecting the approved documents against accidental change. In a real hospital, approval would normally follow the organization's own signature or document-management process.

### Practical 7.1 — Review the documents

From inside `hospital-cybersecurity`, run:

```
ls -l governance/
```

You should see these four files:

```
program-scope.txt
project-charter.txt
roles-responsibilities.txt
security-objectives.txt
```

Count the lines in each document:

```
wc -l governance/*.txt
```

Check that the charter refers to the other documents:

```
grep -n "governance/" governance/project-charter.txt
```

Explanation: `ls -l` lists files with their permissions, owner and size. `wc -l` counts lines. `grep -n` searches for text and shows line numbers. Together they let us confirm that each document exists, is not empty and is referenced by the charter.

### Practical 7.2 — Create the approval record

```
cat > governance/approval-record.txt <<'EOF'
Hospital Cybersecurity Program — Approval Record

Document reviewed: Project Charter, Objectives, Scope, Roles
Decision: Approved to proceed to asset identification and risk assessment

Approved by (Hospital Management): ______________________
Role: ______________________
Date: ______________________

Reviewed by (Information Security Manager): ______________________
Date: ______________________

Conditions or comments:
______________________________________________________________
EOF
```

In the lab, learners fill in a fictional name or their own name for the exercise. In a real organization, only the authorized person can approve.

Display the file:

```
cat governance/approval-record.txt
```

### Practical 7.3 — Protect the approved documents

Make the approved governance documents read-only:

```
chmod a-w governance/*.txt
```

Check the permissions:

```
ls -l governance/
```

The permission column should no longer contain a `w` for the files. For example:

```
-r--r--r-- 1 student student 1234 Jan  1 10:00 project-charter.txt
```

Test the protection by trying to append text:

```
echo "unauthorized change" >> governance/project-charter.txt
```

Expected result:

```
bash: governance/project-charter.txt: Permission denied
```

Explanation: `chmod a-w` removes write permission for all users. This is a simple example of protecting integrity: approved documents should not be changed casually. A real approval process would also record who changed what and when, and would use a controlled document system.

If a document legitimately needs to change later, the change should go through the approval process, and a new version should be approved.

### Practical 7.4 — Record a checksum of the approved documents (optional)

```
sha256sum governance/*.txt > reports/approved-documents.sha256
```

Verify that the files are unchanged:

```
sha256sum -c reports/approved-documents.sha256
```

Each file should show `OK`.

Explanation: a checksum is a fingerprint of the file's content. If even one character changes, the fingerprint changes, so a mismatch shows that the file was modified. This links directly to integrity in the CIA triad. In a real environment, the checksum would be stored separately from the documents, because someone who can change both could hide the change.

## 10. Verify the lab result

Run:

```
find . -type f | sort
```

Expected files (the checksum file appears only if you completed Practical 7.4):

```
./governance/approval-record.txt
./governance/program-scope.txt
./governance/project-charter.txt
./governance/roles-responsibilities.txt
./governance/security-objectives.txt
./reports/approved-documents.sha256
```

Learner checklist

| Item                                          | Done |
| --------------------------------------------- | ---- |
| Identified user, directory, date and OS       |      |
| Created the project workspace (7 directories) |      |
| Created the objectives document               |      |
| Created the scope document                    |      |
| Created the roles and responsibilities file   |      |
| Created the project charter                   |      |
| Created the approval record                   |      |
| Made approved documents read-only             |      |
| Verified the result with find                 |      |

Output: Approved cybersecurity program initiation. The hospital is ready to proceed to asset identification and risk assessment.

## 11. Debrief and discussion

Ask learners:

1. Why did we create the objectives, scope and responsibilities before installing any security tools?
2. What could go wrong if the scope is unclear?
3. Who should approve the charter, and why not the IT team alone?
4. What is the difference between the person who operates a control and the person who accepts a risk?
5. Which CIA property did the read-only protection and checksum support?

Suggested answers

1. Controls should be chosen to meet defined objectives and protect defined assets. Without objectives and scope, effort can be wasted or important assets missed.
2. Assets and responsibilities can be overlooked, disputes can arise and controls may protect the wrong things.
3. Management provides authority and resources and is accountable for the business. The IT team can advise and implement but does not own business risk.
4. The operator runs the control day to day. The risk owner decides whether the remaining risk is acceptable for the business.
5. Integrity.

## 12. Common mistakes and troubleshooting

| Problem                                      | Likely cause and fix                                                                                           |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `No such file or directory`                  | You are in the wrong directory. Run `pwd` and `cd` to `hospital-cybersecurity`.                               |
| `tree: command not found`                    | `tree` is not installed. Use `ls -la` instead.                                                                |
| A document contains only one line            | `>` was used instead of `>>`, which replaced the contents. Recreate the file.                                 |
| `Permission denied` when editing a document  | The file is read-only after Practical 7.3. Use `chmod u+w <file>` only if the change is authorized.          |
| `mkdir: cannot create directory`             | The folder already exists or you lack permission. Check with `ls -la` and confirm you are in your home area. |
| Heredoc does not finish                      | The closing `EOF` must be on its own line with no spaces before it.                                          |

## 13. Lab summary

In this lab learners:

- Understood why a hospital must establish a cybersecurity program before technical controls.
- Created a documented workspace for the program.
- Defined objectives using the CIA triad plus detection and response, and continual improvement.
- Defined scope, boundaries, exclusions and assumptions.
- Assigned accountability and responsibilities for security decisions.
- Created a project charter and an approval record.
- Protected the approved documents and checked their integrity.

Course connections: this lab applies Section 4 (Cybersecurity program), Section 5 (Cybersecurity governance) and Section 6 (Roles and responsibilities), and uses the CIA concepts from Section 3.

Next lab: identify and classify the hospital's information assets and begin the risk assessment, using the `inventory/` and `risk/` directories created in this lab.
