# Dictionaries — generated from the pack; predefined Zscaler dictionaries are looked up by name.

data "zia_dlp_dictionaries" "ssn" {
  name = "SSN"
}

data "zia_dlp_dictionaries" "usitin_leakage" {
  name = "USITIN_LEAKAGE"
}

data "zia_dlp_dictionaries" "usdl_leakage" {
  name = "USDL_LEAKAGE"
}

data "zia_dlp_dictionaries" "aba_leakage" {
  name = "ABA_LEAKAGE"
}

data "zia_dlp_dictionaries" "credit_card" {
  name = "CREDIT_CARD"
}

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

data "zia_dlp_dictionaries" "ml_corporate_finance_leakage" {
  name = "ML_CORPORATE_FINANCE_LEAKAGE"
}

data "zia_dlp_dictionaries" "ml_tax_leakage" {
  name = "ML_TAX_LEAKAGE"
}

data "zia_dlp_dictionaries" "financial" {
  name = "FINANCIAL"
}

resource "zia_dlp_dictionaries" "custom_medical_record_number" {
  name                         = "Custom-Medical-Record-Number"
  description                  = "HIPAA identifier 8: an MRN, chart, encounter, visit, account or EMPI label within 50 bytes of a 6-10 digit number (optional 1-3 letter prefix). Both the phrase and the pattern must ma... [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
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
  description                  = "HIPAA identifier 3: a birth-date label within 50 bytes of a date in US, ISO or long form (years 1920-2026). Both the phrase and the pattern must match. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
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
  description                  = "Elevated-protection PHI (42 CFR Part 2, GINA, state HIV / mental-health / reproductive statutes): SUD and MAT terms, mental-health markers, HIV markers, genetic-testing terms and gene... [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
  description                  = "HIPAA identifier 9: a member, subscriber, policy, group, plan, beneficiary, Medicare/Medicaid or pharmacy-benefit label within 50 bytes of a Medicare Beneficiary Identifier or a 2-3 l... [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
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
  description                  = "Payer names, EDI transaction and billing vocabulary (EOB, remittance, claim, copay, prior authorization). Phrases only; counted per phrase so the claims pathway can require density (>... [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
  description                  = "Structural markers of clinical documents (chief complaint, history, review of systems, discharge, progress and operative notes, provider roles, admission and discharge dates, medicati... [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
  description                  = "HIPAA identifier 2: an address label within 50 bytes of a ZIP+4 or a street address. ZIP alone is very noisy; this dictionary is only used beside insurance and billing context. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
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

resource "zia_dlp_dictionaries" "hc_social_security_numbers_us_high" {
  name                         = "HC-Social Security Numbers (US) - High"
  description                  = "Detect leakage of United States Social Security Numbers [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.ssn.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ssn"
  }
}

resource "zia_dlp_dictionaries" "hc_social_security_numbers_us_prox_500" {
  name                         = "HC-Social Security Numbers (US) - Prox 500"
  description                  = "Detect leakage of United States Social Security Numbers [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.ssn.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ssn"
  }
}

resource "zia_dlp_dictionaries" "hc_tax_identification_number_us_high" {
  name                         = "HC-Tax Identification Number (US) - High"
  description                  = "Detect Leakage of US Tax Identification Numbers [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.usitin_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
}

resource "zia_dlp_dictionaries" "hc_tax_identification_number_us_prox_500" {
  name                         = "HC-Tax Identification Number (US) - Prox 500"
  description                  = "Detect Leakage of US Tax Identification Numbers [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.usitin_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
}

resource "zia_dlp_dictionaries" "hc_drivers_license_united_states_high" {
  name                         = "HC-Drivers License (United States) - High"
  description                  = "Detect leakage of United States Driver’s Licenses [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.usdl_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_HIGH"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
  hierarchical_identifiers     = ["USDL_AL", "USDL_AK", "USDL_AZ", "USDL_AR", "USDL_CA", "USDL_CO", "USDL_CT", "USDL_DE", "USDL_DC", "USDL_FL", "USDL_GA", "USDL_HI", "USDL_ID", "USDL_IL", "USDL_IN", "USDL_IA", "USDL_KS", "USDL_KY", "USDL_LA", "USDL_ME", "USDL_MD", "USDL_MA", "USDL_MI", "USDL_MN", "USDL_MS", "USDL_MO", "USDL_MT", "USDL_NE", "USDL_NV", "USDL_NH", "USDL_NJ", "USDL_NM", "USDL_NY", "USDL_NC", "USDL_ND", "USDL_OH", "USDL_OK", "USDL_OR", "USDL_PA", "USDL_RI", "USDL_SC", "USDL_SD", "USDL_TN", "USDL_TX", "USDL_VT", "USDL_VA", "USDL_WV", "USDL_WI", "USDL_WY", "USDL_GU"]
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Driver License"
  }
}

resource "zia_dlp_dictionaries" "hc_drivers_license_united_states_prox_500" {
  name                         = "HC-Drivers License (United States) - Prox 500"
  description                  = "Detect leakage of United States Driver’s Licenses [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.usdl_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_HIGH"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
  hierarchical_identifiers     = ["USDL_AL", "USDL_AK", "USDL_AZ", "USDL_AR", "USDL_CA", "USDL_CO", "USDL_CT", "USDL_DE", "USDL_DC", "USDL_FL", "USDL_GA", "USDL_HI", "USDL_ID", "USDL_IL", "USDL_IN", "USDL_IA", "USDL_KS", "USDL_KY", "USDL_LA", "USDL_ME", "USDL_MD", "USDL_MA", "USDL_MI", "USDL_MN", "USDL_MS", "USDL_MO", "USDL_MT", "USDL_NE", "USDL_NV", "USDL_NH", "USDL_NJ", "USDL_NM", "USDL_NY", "USDL_NC", "USDL_ND", "USDL_OH", "USDL_OK", "USDL_OR", "USDL_PA", "USDL_RI", "USDL_SC", "USDL_SD", "USDL_TN", "USDL_TX", "USDL_VT", "USDL_VA", "USDL_WV", "USDL_WI", "USDL_WY", "USDL_GU"]
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Driver License"
  }
}

resource "zia_dlp_dictionaries" "hc_alien_registration_number_high_confidence" {
  name                         = "HC-Alien Registration Number - High Confidence"
  description                  = "From the Fed pack's US PII set: USCIS alien registration / A-number beside an immigration label [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?i)\\bA?[\\-#]?\\d{3}-?\\d{3}-?\\d{1,3}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ARN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Alien Registration"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Alien Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "'A-Number'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Immigrant data"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "USCIS Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Employment Authorization"
  }
}

resource "zia_dlp_dictionaries" "hc_alien_registration_number_prox_500" {
  name                         = "HC-Alien Registration Number - Prox 500"
  description                  = "From the Fed pack's US PII set: USCIS alien registration / A-number beside an immigration label (any pattern within 500 bytes of any phrase) [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?i)\\bA?[\\-#]?\\d{3}-?\\d{3}-?\\d{1,3}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "ARN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Alien Registration"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Alien Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "'A-Number'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Immigrant data"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "USCIS Number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Employment Authorization"
  }
}

resource "zia_dlp_dictionaries" "hc_date_of_birth_high_confidence" {
  name                         = "HC-Date of Birth - High Confidence"
  description                  = "From the Fed pack's US PII set: US, ISO or dotted dates beside a birth-date label [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b([0-1]?\\d)[\\/.-]([0-3]?\\d)[\\/.-](19|20)?\\d{2}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(19|20)?\\d{2}[\\/.-]([0-1]?\\d)[\\/.-]([0-3]?\\d)\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Date of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "year of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "month of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "day of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "birthday"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "birth year"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "birth month"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "dob"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "d.o.b"
  }
}

resource "zia_dlp_dictionaries" "hc_date_of_birth_prox_500" {
  name                         = "HC-Date of Birth - Prox 500"
  description                  = "From the Fed pack's US PII set: US, ISO or dotted dates beside a birth-date label (any pattern within 500 bytes of any phrase) [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b([0-1]?\\d)[\\/.-]([0-3]?\\d)[\\/.-](19|20)?\\d{2}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b(19|20)?\\d{2}[\\/.-]([0-1]?\\d)[\\/.-]([0-3]?\\d)\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Date of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "year of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "month of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "day of birth"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "birthday"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "birth year"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "birth month"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "dob"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "d.o.b"
  }
}

resource "zia_dlp_dictionaries" "hc_us_passport_high_confidence" {
  name                         = "HC-US Passport - High Confidence"
  description                  = "From the Fed pack's US PII set: 8-9 digit or letter+8 digit passport numbers beside a passport label [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b\\d{8,9}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?i)\\b[A-Z]\\d{8}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport Number "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport No"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport#"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PassportID"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passportno"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passportnumber "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No. du Passeport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No. de Pasaporte"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passeport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Pasaporte"
  }
}

resource "zia_dlp_dictionaries" "hc_us_passport_prox_500" {
  name                         = "HC-US Passport - Prox 500"
  description                  = "From the Fed pack's US PII set: 8-9 digit or letter+8 digit passport numbers beside a passport label (any pattern within 500 bytes of any phrase) [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
  proximity                    = 500
  proximity_enabled_for_custom_dictionary = true
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "\\b\\d{8,9}\\b"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "(?i)\\b[A-Z]\\d{8}\\b"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport Number "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport No"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport#"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "PassportID"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passportno"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passportnumber "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No. du Passeport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "No. de Pasaporte"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Passeport"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_ALL"
    phrase = "Pasaporte"
  }
}

resource "zia_dlp_dictionaries" "hc_aba_bank_routing_number_prox_500" {
  name                         = "HC-ABA Bank Routing Number - Prox 500"
  description                  = "Detect leakage of ABA Bank Routing Numbers [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.aba_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
}

resource "zia_dlp_dictionaries" "hc_form_1040_and_related_schedules" {
  name                         = "HC-Form 1040 and related schedules"
  description                  = "From the Fed pack (Form 1040 and related schedules). [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form 1040"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0074"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = " or other tax year beginning"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Was born before January 2, 1959"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "If you checked the HOH or QSS box"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "I have examined this return and accompanying schedules and statements, and to the best of my knowledge"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Do you want to allow another person to discuss this return"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Cat. No. 11320B"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "'Schedule 1 (Form 1040)'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Additional Income and Adjustments to Income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Foreign earned income exclusion"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Activity not engaged in for profit income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Nontaxable amount of Medicaid "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Cat. No. 71479F"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "'Schedule 2 (Form 1040)'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Alternative minimum tax. Attach Form"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Social security and Medicare tax on unreported tip income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Additional Medicare Tax. Attach Form 8959"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = " tax due on installment income from the sale of certain residential lots"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = " Cat. No. 71478U"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Recapture of federal mortgage subsidy"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Compensation you received from a nonqualified deferred"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Tax on non-effectively connected income for any part of"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Section 965 net tax liability installment from Form 965-A"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "'Schedule 3 (Form 1040)'"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Foreign tax credit. Attach Form 1116 if required"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "General business credit. Attach Form 3800"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Mortgage interest credit. Attach Form 8396"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Credit to holders of tax credit bonds. Attach Form 8912"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Attach to Form 1040, 1040-SR, or 1040-NR"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Excess social security and tier 1 RRTA tax withheld"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Credit for repayment of amounts included in income from earlier"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Deferred amount of net 965 tax liability"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Add lines 9 through 12 and 14. Enter here and on Form 1040, 1040-SR, or 1040-NR"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form 1040-ES"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Disclosure, Privacy Act, and Paperwork Reduction Act Notice"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "File only if you are making a payment of estimated tax by check"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Amount of estimated tax you are paying"
  }
}

resource "zia_dlp_dictionaries" "hc_aba_bank_routing_number_high" {
  name                         = "HC-ABA Bank Routing Number - High"
  description                  = "Detect leakage of ABA Bank Routing Numbers [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.aba_leakage.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
}

resource "zia_dlp_dictionaries" "hc_credit_card_magnetic_tracks" {
  name                         = "HC-Credit Card Magnetic Tracks"
  description                  = "Focuses on track 1 and 2 data, without targeting track 3. As track 3 is less commonly used, and would still be accompanied by track 1 and 2 [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "[%][B]\\d{12,19}[\\^][a-zA-Z\\/\\s.]{2,26}[\\^](\\d{7})([a-zA-Z\\d*]{1,24})[?][a-zA-Z\\d*]?"
  }
  patterns {
    action  = "PATTERN_COUNT_TYPE_UNIQUE"
    pattern = "[;]\\d{12,19}[=]([\\dxX])([a-zA-Z\\d*]{1,24})[?][a-zA-Z\\d*]?"
  }
}

resource "zia_dlp_dictionaries" "hc_form_1099_misc_and_1099_nec" {
  name                         = "HC-Form 1099-MISC and 1099-NEC"
  description                  = "From the Fed pack (Form 1099-MISC and 1099-NEC). [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "PAYER’S name, street address, city or town, state or province, country, ZIP"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form 1099-MISC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form 1099-NEC"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Payer made direct sales totaling $5,000 or more of"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Nonqualified deferred compensation"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0115"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Excess golden parachute"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Gross proceeds paid to an"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "PAYER’S TIN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "RECIPIENT’S TIN"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "File with Form 1096."
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0116"
  }
}

resource "zia_dlp_dictionaries" "hc_credit_cards_prox_500" {
  name                         = "HC-Credit Cards - Prox 500"
  description                  = "Detect leakage of credit card information [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.credit_card.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  proximity                    = 500
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
}

resource "zia_dlp_dictionaries" "hc_w2_or_w4_or_w9_forms" {
  name                         = "HC-W2 or W4 or W9 Forms"
  description                  = "From the Fed pack (W2 or W4 or W9 Forms). [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "a Employee’s social security number"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0008 "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form W-2"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Wage and Tax Statement"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "c Employer’s name, address, and ZIP code"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "e Employee’s first name and initial"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "3 Social security wages"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form W-9"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Identification Number and Certification"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Name of entity/individual. An entry is required"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "LLC. Enter the tax classification "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Exemptions (codes apply only to"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Cat. No. 10231X"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "List account number(s) here (optional)"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Form W-4"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0074"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Single or Married filing separately"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Other income (not from jobs)."
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "If your total income will be $200,000 or less"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Deductions. If you expect to claim deductions other than the standard deduction "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Cat. No. 10220Q"
  }
}

resource "zia_dlp_dictionaries" "hc_credit_cards_high" {
  name                         = "HC-Credit Cards - High"
  description                  = "Detect leakage of credit card information [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dict_template_id             = data.zia_dlp_dictionaries.credit_card.id
  confidence_level_for_predefined_dict = "CONFIDENCE_LEVEL_MEDIUM"
  confidence_threshold         = "CONFIDENCE_LEVEL_HIGH"
  include_bin_numbers          = true
  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)
}

resource "zia_dlp_dictionaries" "hc_form_k_1" {
  name                         = "HC-Form K-1"
  description                  = "From the Fed pack (Form K-1). [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  dictionary_type              = "PATTERNS_AND_PHRASES"
  custom                       = true
  custom_phrase_match_type     = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Schedule K-1 "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "OMB No. 1545-0123"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "A Partnership’s employer identification number "
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "F Name, address, city, state, and ZIP code for partner entered in"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Partner’s share of liabilities"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "Partner’s Share of Current Year Income"
  }
  phrases {
    action = "PHRASE_COUNT_TYPE_UNIQUE"
    phrase = "More than one activity for passive activity purposes"
  }
}

