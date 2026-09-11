# Dictionaries — generated from the pack; predefined Zscaler dictionaries are looked up by name.

data "zia_dlp_dictionaries" "social_security_numbers_us" {
  # Social Security Numbers (US)
  name = "SSN"
}

data "zia_dlp_dictionaries" "treatments_information" {
  name = "Treatments Information"
}

data "zia_dlp_dictionaries" "diseases_information" {
  # Diseases Information
  name = "DISEASES_LEAKAGE"
}

data "zia_dlp_dictionaries" "ndc_number_package" {
  name = "NDC Number (Package)"
}

data "zia_dlp_dictionaries" "ndc_number_product" {
  name = "NDC Number (Product)"
}

data "zia_dlp_dictionaries" "medical_information" {
  # Medical Information
  name = "MEDICAL"
}

data "zia_dlp_dictionaries" "drugs_information" {
  # Drugs Information
  name = "DRUGS_LEAKAGE"
}

data "zia_dlp_dictionaries" "medical_document" {
  # Medical Document
  name = "ML_MEDICAL_DOC_LEAKAGE"
}

data "zia_dlp_dictionaries" "medical_imaging" {
  name = "Medical Imaging"
}

data "zia_dlp_dictionaries" "names_us" {
  name = "Names (US)"
}

data "zia_dlp_dictionaries" "enhanced_driver_s_license_united_states" {
  name = "Enhanced Driver's License (United States)"
}

data "zia_dlp_dictionaries" "driver_s_license_united_states" {
  # Driver's License (United States)
  name = "USDL_LEAKAGE"
}

data "zia_dlp_dictionaries" "tax_identification_number_us" {
  # Tax Identification Number (US)
  name = "USITIN_LEAKAGE"
}

data "zia_dlp_dictionaries" "self_harm_cyberbullying" {
  name = "Self-Harm & Cyberbullying"
}

data "zia_dlp_dictionaries" "illegal_drugs" {
  name = "Illegal Drugs"
}

data "zia_dlp_dictionaries" "national_provider_identifier" {
  name = "National Provider Identifier"
}

data "zia_dlp_dictionaries" "insurance_document" {
  name = "Insurance Document"
}

data "zia_dlp_dictionaries" "credit_cards" {
  # Credit Cards
  name = "CREDIT_CARD"
}

resource "zia_dlp_dictionaries" "custom_medical_record_number" {
  name                         = "Custom-Medical-Record-Number"
  description                  = "HIPAA identifier 8: an MRN, chart, encounter, visit, account or EMPI label within 50 bytes of a 6-10 digit number (optional 1-3 letter prefix). Both the phrase and the pattern must ma... [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 50
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[A-Z]{0,3}[-]?\\d{6,10}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Medical Record Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Medical Record"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Patient Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Patient Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Chart"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Chart Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Hospital Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Health Record Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Encounter Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Visit Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Account Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Enterprise Master Patient Index"
  }
}

resource "zia_dlp_dictionaries" "custom_date_of_birth" {
  name                         = "Custom-Date-of-Birth"
  description                  = "HIPAA identifier 3: a birth-date label within 50 bytes of a date in US, ISO or long form (years 1920-2026). Both the phrase and the pattern must match. [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 50
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:0[1-9]|1[0-2])[/\\-.](?:0[1-9]|[12][0-9]|3[01])[/\\-.](?:19[2-9][0-9]|20[01][0-9]|202[0-6])\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:19[2-9][0-9]|20[01][0-9]|202[0-6])-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\\s+(?:0?[1-9]|[12][0-9]|3[01]),?\\s+(?:19[2-9][0-9]|20[01][0-9]|202[0-6])\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Date of Birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Birth Date"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Birthdate"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Born"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Born on"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Patient Date of Birth"
  }
}

resource "zia_dlp_dictionaries" "custom_sensitive_condition_markers" {
  name                         = "Custom-Sensitive-Condition-Markers"
  description                  = "Elevated-protection PHI (42 CFR Part 2, GINA, state HIV / mental-health / reproductive statutes): SUD and MAT terms, mental-health markers, HIV markers, genetic-testing terms and gene... [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(?:BRCA[12]|APOE|MTHFR|CFTR|HLA-[A-Z][0-9]?|MLH1|MSH[26]|PMS2|TP53|PTEN|APC|VHL|RET|JAK2|FLT3|EGFR|ALK|KRAS|NRAS|BRAF|HER2)\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Substance Use Disorder"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Alcohol Use Disorder"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Opioid Use Disorder"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Detox"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Rehabilitation"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Methadone"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Suboxone"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Buprenorphine"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Naloxone"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Medication Assisted Treatment"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Code of Federal Regulations Title 42 Part 2"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Withdrawal"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Overdose"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Suicidal Ideation"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Self-Harm"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Major Depressive Disorder"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Generalized Anxiety Disorder"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Post-Traumatic Stress Disorder"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Human Immunodeficiency Virus Positive"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Antiretroviral"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Pre-Exposure Prophylaxis"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Cluster of Differentiation 4 Count"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Viral Load"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Seropositive"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Genetic Testing"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Carrier Status"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Pathogenic Variant"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Variant of Uncertain Significance"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Hereditary"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Twenty-Three and Me"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Invitae"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Myriad"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Genetic Counselor"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Genetic Information Nondiscrimination Act"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Last Menstrual Period"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Estimated Date of Delivery"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Termination of Pregnancy"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Abortion"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Miscarriage"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Intrauterine Device"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Tubal Ligation"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "In Vitro Fertilization"
  }
}

resource "zia_dlp_dictionaries" "custom_health_plan_member_identifier" {
  name                         = "Custom-Health-Plan-Member-Identifier"
  description                  = "HIPAA identifier 9: a member, subscriber, policy, group, plan, beneficiary, Medicare/Medicaid or pharmacy-benefit label within 50 bytes of a Medicare Beneficiary Identifier or a 2-3 l... [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 50
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[1-9][AC-HJKMNP-RT-Y][0-9AC-HJKMNP-RT-Y][0-9]-?[A-Z][AC-HJKMNP-RT-Y][0-9]-?[A-Z]{2}[0-9]{2}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b[A-Z]{2,3}[0-9]{6,12}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Member Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Member Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Subscriber Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Subscriber Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Policy Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Policy Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Insurance Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Insurance Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Group Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Plan Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Plan Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Beneficiary Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Beneficiary Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Medicare Beneficiary Identifier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Health Insurance Claim Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Medicare Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Medicaid Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Prescription Bank Identification Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Prescription Processor Control Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Cardholder Identifier"
  }
}

resource "zia_dlp_dictionaries" "custom_insurance_billing" {
  name                         = "Custom-Insurance-Billing"
  description                  = "Payer names, EDI transaction and billing vocabulary (EOB, remittance, claim, copay, prior authorization). Phrases only; counted per phrase so the claims pathway can require density (>... [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Aetna"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Anthem"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Blue Cross"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Blue Shield"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Blue Cross Blue Shield"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Cigna"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Humana"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Kaiser Permanente"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "UnitedHealthcare"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Medicare"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Medicaid"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Tricare"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "WellCare"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Centene"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Molina"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Optum"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Caremark"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Express Scripts"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "OptumRx"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Health Care Claim Professional"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Health Care Claim Institutional"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Health Care Claim Payment Advice"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Eligibility Inquiry"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Health Level Seven"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Fast Healthcare Interoperability Resources"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Electronic Data Interchange"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Accredited Standards Committee X12"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Explanation of Benefits"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Remittance Advice"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Claim Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Copay"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Deductible"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Coinsurance"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Prior Authorization"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Authorization Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Reimbursement"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Adjudication"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Allowed Amount"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Billed Amount"
  }
}

resource "zia_dlp_dictionaries" "custom_clinical_narrative" {
  name                         = "Custom-Clinical-Narrative"
  description                  = "Structural markers of clinical documents (chief complaint, history, review of systems, discharge, progress and operative notes, provider roles, admission and discharge dates, medicati... [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Chief Complaint"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "History of Present Illness"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Past Medical History"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Past Surgical History"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Family History"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Social History"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Review of Systems"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Physical Examination"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Differential Diagnosis"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Discharge Summary"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Discharge Disposition"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Progress Note"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Consultation Note"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Operative Report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Pathology Report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Radiology Report"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Patient presents"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Patient denies"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Patient reports"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Admitting Provider"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Attending Physician"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Primary Care Physician"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Date of Admission"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Date of Discharge"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Length of Stay"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No Known Drug Allergies"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Current Medications"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Medication Reconciliation"
  }
}

resource "zia_dlp_dictionaries" "custom_address_zip" {
  name                         = "Custom-Address-ZIP"
  description                  = "HIPAA identifier 2: an address label within 50 bytes of a ZIP+4 or a street address. ZIP alone is very noisy; this dictionary is only used beside insurance and billing context. [DLP-Check baseline healthcare_phi_baseline v3.0] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  proximity                    = 50
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b\\d{5}(?:-\\d{4})?\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b\\d{1,6}\\s+[A-Za-z0-9\\s]{2,40}\\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Circle|Cir|Way|Place|Pl|Parkway|Pkwy|Highway|Hwy)\\b\\.?"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Patient Address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Home Address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Mailing Address"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Street"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "City"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "State"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Zone Improvement Plan Code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Postal Code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Apartment"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Suite"
  }
}

