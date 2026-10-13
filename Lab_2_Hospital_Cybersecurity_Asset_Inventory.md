# Lab 2 --- Create the Hospital Cybersecurity Asset Inventory

**Course:** PECB Cybersecurity Foundation\
**Course alignment:** Assets, threats, vulnerabilities, and the CIA
triad\
**Environment:** Kali Linux or Ubuntu\
**Suggested duration:** 45--60 minutes\
**Level:** Beginner

------------------------------------------------------------------------

## 1. Lab objective

In this lab, you will create an initial inventory of the hospital's
information assets and supporting systems. You will record each asset's
owner, function, criticality, and basic security requirements.

By the end of the lab, you should be able to:

-   Explain what an asset is and why it needs protection.
-   Identify important hospital information assets and supporting
    systems.
-   Record asset ownership and business function.
-   Classify asset criticality using a simple training scale.
-   Apply the Confidentiality, Integrity, and Availability (CIA) triad.
-   Validate an inventory and identify missing information.
-   Explain how an asset inventory supports cybersecurity risk
    assessment.

## 2. Hospital scenario

The hospital management team has approved the cybersecurity initiative
described in Lab 1. The Information Security Manager now asks:

> Before we decide which security controls to implement, do we know the
> important systems, who is responsible for them, what information they
> handle, and what would happen if they were compromised?

The hospital identifies these initial assets:

-   Electronic Health Records (EHR)
-   Patient database
-   Backup server
-   Staff accounts
-   Medical devices
-   Hospital network

The hospital has not yet documented these assets in a consistent format.
Your task is to create and review the initial inventory.

**Important:** Use fictional training data only. Do not enter real
patient information, credentials, or confidential hospital details.

## 3. Implementation flow

1.  Review the approved scope from Lab 1.
2.  Identify the hospital's assets.
3.  Assign an owner to each asset.
4.  Record each asset's function.
5.  Classify its criticality.
6.  Define confidentiality, integrity, and availability requirements.
7.  Identify missing assets and dependencies.
8.  Validate the inventory.
9.  Explain how the inventory will be used in the next risk-assessment
    lab.

## 4. Step 1 --- Open the terminal and locate the project

Open a terminal in Kali Linux or Ubuntu.

``` bash
cd ~/hospital-cybersecurity
```

Verify the current directory:

``` bash
pwd
```

Expected output will resemble:

``` text
/home/student/hospital-cybersecurity
```

Your username and path may differ.

Inspect the project directories:

``` bash
ls -la
```

Check the inventory directory:

``` bash
ls -la inventory
```

If the inventory files do not exist yet, that is expected.

**Why this step matters:** Lab 1 established the project's scope and
folder structure. All subsequent labs will use the same project
directory.

## 5. Step 2 --- Identify the hospital's assets

An **asset** is something the hospital values and needs to protect.
Assets can include information, applications, hardware, identities,
services, and business processes.

  -----------------------------------------------------------------------
  Asset                   Example owner           Function
  ----------------------- ----------------------- -----------------------
  EHR System              Clinical IT             Provides access to
                                                  patient records

  Patient Database        Database Team           Stores medical history
                                                  and related information

  Backup Server           Infrastructure Team     Holds recovery copies
                                                  of important data

  Staff Accounts          HR and IT               Manage user identities
                                                  and access

  Medical Devices         Clinical Engineering    Support patient
                                                  monitoring and clinical
                                                  activities

  Hospital Network        Network Team            Connects systems,
                                                  devices, and users
  -----------------------------------------------------------------------

An owner is accountable for defining an asset's business needs and
security requirements. The owner may not be the person who technically
administers it.

**Discussion question:** Is a staff account an asset even though it is
not a physical device?

**Expected learning point:** Yes. An identity can provide access to
sensitive information and critical systems. A compromised or
over-privileged account can create significant risk.

## 6. Step 3 --- Create the initial asset inventory

A CSV file is a simple, spreadsheet-compatible format. Each row
represents an asset, and each column records a property of that asset.

From the `hospital-cybersecurity` directory, run:

``` bash
cat > inventory/assets.csv <<'EOF'
Asset,Owner,Data_or_Function,Criticality
EHR System,Clinical IT,Patient records,Critical
Patient Database,Database Team,Medical history,Critical
Backup Server,Infrastructure Team,Recovery copies,High
Staff Accounts,HR and IT,Identity and access,High
Medical Devices,Clinical Engineering,Patient monitoring,Critical
Hospital Network,Network Team,Connectivity,Critical
EOF
```

### Understanding the command

-   `cat` displays text or reads content.
-   `>` creates the file or replaces its existing contents.
-   `inventory/assets.csv` is the destination file.
-   `<<'EOF'` begins a multiline text block.
-   The final `EOF` marks the end of the text block.

> **Warning:** `>` overwrites an existing file with the same name. Do
> not rerun the command after adding learner data unless you intend to
> replace the file.

Display the inventory:

``` bash
cat inventory/assets.csv
```

Expected output:

``` text
Asset,Owner,Data_or_Function,Criticality
EHR System,Clinical IT,Patient records,Critical
Patient Database,Database Team,Medical history,Critical
Backup Server,Infrastructure Team,Recovery copies,High
Staff Accounts,HR and IT,Identity and access,High
Medical Devices,Clinical Engineering,Patient monitoring,Critical
Hospital Network,Network Team,Connectivity,Critical
```

Count the lines, including the header:

``` bash
wc -l inventory/assets.csv
```

Expected output:

``` text
7 inventory/assets.csv
```

Count only the asset records:

``` bash
tail -n +2 inventory/assets.csv | wc -l
```

Expected output:

``` text
6
```

There are six asset records and one header row.

## 7. Step 4 --- Understand ownership and criticality

**Criticality** describes the consequences of losing or compromising an
asset. The following categories are illustrative for this exercise; a
real hospital should define and approve its own classification criteria.

  -----------------------------------------------------------------------
  Classification          Meaning                 Example
  ----------------------- ----------------------- -----------------------
  Critical                Severe business or      Failure of a critical
                          patient-care impact     EHR service may disrupt
                                                  clinical work

  High                    Significant operational Loss of backup
                          or recovery impact      infrastructure may make
                                                  recovery harder

  Medium                  More limited or         A non-critical internal
                          manageable impact       resource may have a
                                                  practical workaround
  -----------------------------------------------------------------------

Discuss these questions with your trainer:

1.  Why is the EHR system classified as Critical?
2.  Why can the backup server be important even though it does not
    directly treat patients?
3.  What could happen if a staff account with administrative access is
    compromised?
4.  Could a hospital network outage affect several systems at once?
5.  Should all medical devices automatically receive the same
    criticality rating?

### Suggested discussion points

-   The EHR supports clinical workflows and contains sensitive patient
    data.
-   Backups support restoration and continuity after disruption.
-   A compromised privileged account may expose or alter multiple
    systems.
-   The network can be a shared dependency, so its failure may affect
    many services.
-   Device criticality depends on clinical function, connectivity,
    available alternatives, and the consequences of failure.

## 8. Step 5 --- Apply the CIA triad

The CIA triad consists of:

-   **Confidentiality:** Information is accessible only to authorized
    people.
-   **Integrity:** Information remains accurate and protected from
    unauthorized or inappropriate modification.
-   **Availability:** Information and systems are accessible when
    authorized users need them.

For example, a patient database needs confidentiality because the
information is sensitive, integrity because medical records must remain
accurate, and availability because clinical staff may need the records
to provide care.

Create a more detailed inventory:

``` bash
cat > inventory/assets-detailed.csv <<'EOF'
Asset,Owner,Function,Criticality,Confidentiality,Integrity,Availability
EHR System,Clinical IT,Access to patient records,Critical,High,High,High
Patient Database,Database Team,Stores medical history,Critical,High,High,High
Backup Server,Infrastructure Team,Recovery copies,High,High,High,High
Staff Accounts,HR and IT,Identity and access,High,High,High,High
Medical Devices,Clinical Engineering,Patient monitoring,Critical,Medium,High,High
Hospital Network,Network Team,Connectivity,Critical,Medium,High,High
EOF
```

Display the detailed inventory:

``` bash
cat inventory/assets-detailed.csv
```

These CIA ratings are initial classroom assumptions, not the result of a
completed assessment. In a real hospital, system owners and clinical
stakeholders should validate them. Medical-device confidentiality
requirements depend on the data handled, while availability requirements
depend on clinical use.

### Discussion: compare the CIA requirements

  -----------------------------------------------------------------------
  Asset                               Discussion point
  ----------------------------------- -----------------------------------
  EHR System                          Unauthorized disclosure and
                                      incorrect records could both cause
                                      harm

  Patient Database                    Changes should be authorized,
                                      traceable, and recoverable

  Backup Server                       Recovery copies need protection
                                      from unauthorized access and
                                      modification, and must be available
                                      when needed

  Staff Accounts                      Compromised identities can enable
                                      unauthorized access to other assets

  Medical Devices                     Availability and integrity may be
                                      especially important for patient
                                      safety

  Hospital Network                    A network failure can disrupt
                                      multiple connected systems
  -----------------------------------------------------------------------

CIA ratings help define security requirements. They do not, by
themselves, establish the likelihood of an attack or the final risk
level.

## 9. Step 6 --- Identify missing assets and dependencies

An initial inventory is rarely complete. The team should consider
systems that support the listed assets.

Possible additional assets include:

-   Staff laptops and workstations
-   Email and collaboration systems
-   Identity and authentication services
-   Laboratory information systems
-   Pharmacy and prescription systems
-   Network equipment and Wi-Fi
-   Cloud and third-party services
-   Security logs and monitoring systems
-   Paper records and removable media, where applicable

For practice, append two fictional assets to the detailed inventory:

``` bash
cat >> inventory/assets-detailed.csv <<'EOF'
Staff Workstations,IT Support,Access to hospital applications,High,High,High,High
Identity Service,Infrastructure Team,Authentication and access,High,High,High,High
EOF
```

Verify the final three lines:

``` bash
tail -n 3 inventory/assets-detailed.csv
```

### Why use `>>`?

-   `>` replaces the existing contents of a file.
-   `>>` appends new content to the end of a file.

These additional assets are fictional examples. In a real inventory,
confirm each asset's actual owner, function, and classification rather
than assigning values based only on assumptions.

### Consider dependencies

The EHR may depend on the patient database, network connectivity,
authentication services, DNS, storage, and backup infrastructure. If
only the EHR application is inventoried, the risk assessment may
overlook failures in these supporting systems.

## 10. Step 7 --- Validate the inventory

Before using the inventory for risk assessment, check whether:

-   Every asset has an owner.
-   Each asset's function is understandable.
-   Criticality is documented.
-   CIA requirements have been considered.
-   Important systems and dependencies have not been overlooked.
-   Classification assumptions can be reviewed by the appropriate owner.

List the inventory files:

``` bash
ls -l inventory/
```

Count lines in both files:

``` bash
wc -l inventory/assets.csv inventory/assets-detailed.csv
```

Expected counts for the files created in this lab:

-   `assets.csv`: 7 lines, including the header.
-   `assets-detailed.csv`: 9 lines, including the header, after adding
    the two extra assets.

### Check the basic inventory's column count

``` bash
awk -F, 'NF != 4 {print "Check basic inventory line:", NR}' inventory/assets.csv
```

If there is no output, each line has four comma-separated fields.

### Check the detailed inventory's column count

``` bash
awk -F, 'NF != 7 {print "Check detailed inventory line:", NR}' inventory/assets-detailed.csv
```

If there is no output, each line has seven comma-separated fields.

**Limitation:** These simple checks are appropriate for this sample
data. They are not complete CSV validators; a CSV-aware parser is needed
when fields contain quoted commas or more complex formatting.

Review the results and discuss:

1.  Does every asset have an owner?
2.  Are the CIA ratings reasonable?
3.  Which assets are shared dependencies?
4.  Which classifications need confirmation from clinical or system
    owners?
5.  What other assets could be missing?

## 11. Step 8 --- Connect the inventory to risk assessment

The inventory provides the starting point for the next lab.

Example: Patient database

-   **Asset:** Patient database
-   **Threat:** Ransomware or unauthorized access
-   **Possible vulnerability:** Inadequate access restrictions or
    untested recovery arrangements
-   **Potential impact:** Exposure, alteration, or unavailability of
    patient records
-   **Security requirements:** Confidentiality, integrity, and
    availability
-   **Potential controls:** Least privilege, strong authentication,
    monitoring, protected backups, and tested recovery procedures

This illustrates the difference between an asset, a threat, a
vulnerability, and a risk:

-   An **asset** is something the hospital needs to protect.
-   A **threat** is a potential cause of harm.
-   A **vulnerability** is a weakness that could be exploited or
    contribute to harm.
-   A **risk** describes the potential consequences and likelihood of an
    event affecting the asset.

The risk assessment in Lab 3 will build on the assets identified here.

## 12. Lab completion checklist

Before completing the lab, confirm that you can:

-   [ ] Create and inspect `inventory/assets.csv`.
-   [ ] Explain what an asset is and why ownership matters.
-   [ ] Assign and justify asset criticality.
-   [ ] Create `inventory/assets-detailed.csv` with CIA ratings.
-   [ ] Identify additional assets and system dependencies.
-   [ ] Validate the sample inventory and identify assumptions that need
    confirmation.
-   [ ] Explain how the inventory supports risk assessment.

## 13. Deliverables

Save the following files in your project directory:

``` text
hospital-cybersecurity/
└── inventory/
    ├── assets.csv
    └── assets-detailed.csv
```

Your trainer may ask you to explain the owner, criticality, and CIA
ratings of any asset in your inventory.

## 14. Key takeaway

The purpose of asset inventory is not just to produce a spreadsheet. It
is to create a reliable, reviewable record of what the hospital needs to
protect, who is responsible for it, and what security requirements
apply.

**Next lab:** Lab 3 --- Assess Hospital Cybersecurity Risks. You will
use the inventory to identify threats and vulnerabilities, estimate
likelihood and impact, prioritize risks, and recommend treatments.

------------------------------------------------------------------------

**Training note:** This is a trainer-designed practical aligned with
cybersecurity foundation concepts. It is not an official PECB-mandated
lab or a certification of regulatory compliance.
