#!/usr/bin/env python3
"""
ZIA DLP Configuration Importer (reference script, not used by the app)
----------------------------------------------------------------------
This is the original stand-alone importer the Fed pack was first deployed
with. Its flow — dictionaries, then engines, then rules; one rule per
engine; every rule created off — is the pattern the app now applies to
EVERY pack through one shared execution path (pack_ops.py, used by
pack_deploy.py and pack_removal.py; see docs/SHARED_EXECUTION_PATH.md).
Deploy Policy Packs never runs this file. It is kept as the reference the
shared path is measured against.

ZIA DLP Configuration Importer
------------------------------
Imports DLP dictionaries (including clones), engines, and policies from 
clean JSON definition files.

Supports two types of dictionaries:
1. Regular custom dictionaries (with patterns/phrases)
2. Cloned dictionaries (predefined_clone=True, uses dictTemplateId)

Input Files (from ./configs/ directory):
- dlp_dictionaries.json
- dlp_engines.json  
- dlp_policies.json

Requirements:
- zscaler-sdk-python (Legacy client)

Credentials are entered interactively - no files stored on disk.
"""
import json
import os
import sys
import re
import getpass
from zscaler.oneapi_client import LegacyZIAClient

def _nx(ret):
    """Normalize SDK return tuple (obj, error)."""
    if not isinstance(ret, tuple): return ret, None
    if len(ret) == 1: return ret[0], None
    return ret[0], ret[-1]

def obj_to_dict(obj):
    """Convert SDK object to dictionary."""
    if hasattr(obj, "to_dict"): return obj.to_dict()
    if hasattr(obj, "as_dict"): return obj.as_dict()
    if hasattr(obj, "__dict__"): return vars(obj)
    return obj

# ------------------------------------------------------------------------------
# Post-Import Configuration: Dictionary Adjustments
# ------------------------------------------------------------------------------
def set_medical_low_confidence(zia):
    """Optionally set the 'MEDICAL' dictionary to low confidence."""
    print("\n" + "="*60, flush=True)
    print("PHASE 4: POST-IMPORT CONFIGURATION", flush=True)
    print("="*60, flush=True)

    print("[INFO] Checking for 'MEDICAL' dictionary...", flush=True)
    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    
    if err:
        print(f"[ERROR] Could not fetch dictionaries: {err}", flush=True)
        return

    medical_obj = next((d for d in all_dicts if obj_to_dict(d).get('name') == "MEDICAL"), None)

    if not medical_obj:
        print("[WARN] 'MEDICAL' dictionary not found. Skipping configuration.", flush=True)
        return

    m_dict = obj_to_dict(medical_obj)
    medical_id = m_dict.get('id')
    current_conf = m_dict.get('confidence_threshold')

    print(f"[INFO] Found 'MEDICAL' dictionary (ID: {medical_id})", flush=True)
    print(f"[INFO] Current confidence level: {current_conf}", flush=True)

    choice = input("\nFor best results, the Medical Information dictionary should be set to low confidence.\nDo you want to do this now? (y/n): ").strip().lower()

    if choice == 'y':
        print("[INFO] Applying Low Confidence setting to dictionary 'MEDICAL'...", flush=True)
        response, _, err = zia.dlp_dictionary.update_dict(
            medical_id,
            name='MEDICAL',
            dictionary_type='PATTERNS_AND_PHRASES',
            custom_phrase_match_type='MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY',
            confidence_threshold='CONFIDENCE_LEVEL_LOW'
        )

        if err:
            print(f"[FAIL] Failed to update dictionary: {err}", flush=True)
        else:
            print("[OK] 'MEDICAL' dictionary updated to Low Confidence.", flush=True)
    else:
        print("[INFO] Skipping 'MEDICAL' dictionary update.", flush=True)  

def set_financial_high_confidence(zia):
    """Optionally set the 'Financial Document' dictionary to high confidence."""
    print("\n[INFO] Checking for 'Financial Document' dictionary...", flush=True)
    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    
    if err:
        print(f"[ERROR] Could not fetch dictionaries: {err}", flush=True)
        return

    target_names = ["Financial Document", "Financial Documents", "FINANCIAL_DOCUMENT", "FINANCIAL_DOCUMENTS", "FINANCIAL"]
    fin_obj = next((d for d in all_dicts if obj_to_dict(d).get('name') in target_names), None)

    if not fin_obj:
        print("[WARN] 'Financial Document' dictionary not found. Skipping configuration.", flush=True)
        return

    f_dict = obj_to_dict(fin_obj)
    fin_id = f_dict.get('id')
    actual_name = f_dict.get('name')
    current_conf = f_dict.get('confidence_threshold')
    dict_type = f_dict.get('dictionary_type', 'PATTERNS_AND_PHRASES')
    match_type = f_dict.get('custom_phrase_match_type', 'MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY')

    print(f"[INFO] Found '{actual_name}' dictionary (ID: {fin_id})", flush=True)
    print(f"[INFO] Current confidence level: {current_conf}", flush=True)

    choice = input(f"\nFor best results, the {actual_name} dictionary should be set to HIGH confidence.\nDo you want to do this now? (y/n): ").strip().lower()

    if choice == 'y':
        print(f"[INFO] Applying High Confidence setting to dictionary '{actual_name}'...", flush=True)
        response, _, err = zia.dlp_dictionary.update_dict(
            fin_id,
            name=actual_name,
            dictionary_type=dict_type,
            custom_phrase_match_type=match_type,
            confidence_threshold='CONFIDENCE_LEVEL_HIGH'
        )

        if err:
            print(f"[FAIL] Failed to update dictionary: {err}", flush=True)
        else:
            print(f"[OK] '{actual_name}' dictionary updated to High Confidence.", flush=True)
    else:
        print(f"[INFO] Skipping '{actual_name}' dictionary update.", flush=True)

# ------------------------------------------------------------------------------
# Post-Import Configuration: Deployment Verification
# ------------------------------------------------------------------------------
def verify_deployment(zia):
    """Compares the deployed dictionaries and engines against the JSON files."""
    print("\n" + "="*60, flush=True)
    print("PHASE 5: DEPLOYMENT VERIFICATION", flush=True)
    print("="*60, flush=True)
    
    choice = input("Would you like to verify the deployment against the JSON files? (y/n): ").strip().lower()
    if choice != 'y':
        print("[INFO] Skipping verification.", flush=True)
        return

    print("\n[INFO] Fetching deployed configuration from ZIA...", flush=True)
    
    # Map the deployed dictionaries by their name for easy lookup
    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    deployed_dicts_map = {obj_to_dict(d).get('name', '').strip(): obj_to_dict(d) for d in all_dicts} if not err else {}
    
    all_engines, err = _nx(zia.dlp_engine.list_dlp_engines_lite())
    deployed_engine_names = {e.name.strip() for e in all_engines if e.name} if not err else set()
    
    dict_file = 'configs/dlp_dictionaries.json'
    engine_file = 'configs/dlp_engines.json'
    
    missing_dicts = []
    mismatched_dicts = {}
    
    if os.path.exists(dict_file):
        with open(dict_file, 'r') as f:
            desired_dicts = json.load(f)
        
        for d_json in desired_dicts:
            d_name = d_json['name'].strip()
            
            # Check 1: Does it exist at all?
            if d_name not in deployed_dicts_map:
                missing_dicts.append(d_name)
            else:
                # Check 2: Content Verification
                d_deployed = deployed_dicts_map[d_name]
                mismatches = []
                
                # --- VERIFY PROXIMITY LOGIC ---
                expected_prox = d_json.get('proximity') or 0
                actual_prox = d_deployed.get('proximity') or 0
                
                if expected_prox != actual_prox:
                    mismatches.append(f"Proximity Value Mismatch (JSON: {expected_prox} vs PROD: {actual_prox})")
                
                # If proximity is expected to be enabled, verify the required flags are True in production
                if expected_prox > 0:
                    # length enabled is required for both custom and clones
                    prod_len_enabled = d_deployed.get('proximity_length_enabled', d_deployed.get('proximityLengthEnabled', False))
                    if not prod_len_enabled:
                        mismatches.append("Proximity Length Enabled flag is missing or False in production.")
                        
                    # custom dictionary flag is required ONLY for custom dictionaries
                    is_clone = d_json.get('predefined_clone', False)
                    if not is_clone:
                        prod_custom_flag = d_deployed.get('proximity_enabled_for_custom_dictionary', d_deployed.get('proximityEnabledForCustomDictionary', False))
                        if not prod_custom_flag:
                            mismatches.append("Custom Dictionary Proximity flag is missing or False in production.")
                # ------------------------------
                    
                # Helper function to extract patterns/phrases into comparable sets
                def extract_items(item_list, key_name):
                    res = set()
                    if not item_list: return res
                    for item in item_list:
                        item_dict = item if isinstance(item, dict) else obj_to_dict(item)
                        res.add((item_dict.get('action', ''), item_dict.get(key_name, '')))
                    return res

                # Verify Patterns
                expected_patterns = extract_items(d_json.get('patterns', []), 'pattern')
                actual_patterns = extract_items(d_deployed.get('patterns', []), 'pattern')
                
                if expected_patterns != actual_patterns:
                    mismatches.append(f"Pattern mismatch (JSON has {len(expected_patterns)}, Tenant has {len(actual_patterns)})")
                    
                # Verify Phrases
                expected_phrases = extract_items(d_json.get('phrases', []), 'phrase')
                actual_phrases = extract_items(d_deployed.get('phrases', []), 'phrase')
                
                if expected_phrases != actual_phrases:
                    mismatches.append(f"Phrase mismatch (JSON has {len(expected_phrases)}, Tenant has {len(actual_phrases)})")
                    
                if mismatches:
                    mismatched_dicts[d_name] = mismatches
    else:
        print(f"[WARN] {dict_file} not found. Skipping dictionary verification.")

    missing_engines = []
    if os.path.exists(engine_file):
        with open(engine_file, 'r') as f:
            desired_engines = json.load(f)
        desired_engine_names = {e['name'].strip() for e in desired_engines}
        missing_engines = list(desired_engine_names - deployed_engine_names)
    else:
        print(f"[WARN] {engine_file} not found. Skipping engine verification.")

    # --- Print the Verification Report ---
    print("\n--- Verification Results ---")
    all_good = True
    
    if os.path.exists(dict_file):
        if missing_dicts:
            print(f"[FAIL] Missing {len(missing_dicts)} Dictionaries:")
            for md in missing_dicts:
                print(f"       - {md}")
            all_good = False
        else:
            print("[OK] All desired Dictionaries are present in the tenant.")
            
        if mismatched_dicts:
            print(f"\n[FAIL] Found Content Mismatches in {len(mismatched_dicts)} Dictionaries:")
            for d_name, m_list in mismatched_dicts.items():
                print(f"       - {d_name}:")
                for m in m_list:
                    print(f"           > {m}")
            all_good = False
        elif not missing_dicts:
            print("[OK] All Dictionary contents (proximity, patterns, phrases) match.")

    if os.path.exists(engine_file):
        if missing_engines:
            print(f"\n[FAIL] Missing {len(missing_engines)} Engines:")
            for me in missing_engines:
                print(f"       - {me}")
            all_good = False
        else:
            print("[OK] All desired Engines are present in the tenant.")

    if all_good:
        print("\n[SUCCESS] Validation Passed: Deployed items and their contents match the JSON definitions.")
    else:
        print("\n[WARNING] Validation Failed: See mismatches above.")

# ------------------------------------------------------------------------------
# Import Dictionaries (with Clone Support & Snake_Case Fixes)
# ------------------------------------------------------------------------------
def import_dictionaries(zia):
    """Import DLP dictionaries from JSON definition file, including clones."""
    print("\n" + "="*60, flush=True)
    print("PHASE 1: IMPORTING DICTIONARIES", flush=True)
    print("="*60, flush=True)
    
    dict_file = 'configs/dlp_dictionaries.json'
    if not os.path.exists(dict_file):
        print(f"[INFO] {dict_file} not found, skipping dictionaries", flush=True)
        return
    
    with open(dict_file, 'r') as f:
        desired_dictionaries = json.load(f)
        print(f"[INFO] Loaded {len(desired_dictionaries)} dictionary definitions", flush=True)
    
    clone_count = sum(1 for d in desired_dictionaries if d.get('predefined_clone'))
    custom_count = len(desired_dictionaries) - clone_count
    print(f"[INFO] Dictionary types: {custom_count} custom, {clone_count} clones", flush=True)
    
    print("[INFO] Checking existing dictionaries...", flush=True)
    existing_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    if err:
        print(f"[ERROR] Failed to list existing dictionaries: {err}", flush=True)
        return
    
    existing_dict_names = {}
    predefined_name_to_id = {}
    for d in existing_dicts:
        d_dict = obj_to_dict(d)
        name = d_dict.get('name', '').strip()
        existing_dict_names[name] = d_dict.get('id')
        if not d_dict.get('custom', False):
            predefined_name_to_id[name] = d_dict.get('id')
    
    print(f"[INFO] Found {len(existing_dict_names)} existing dictionaries ({len(predefined_name_to_id)} predefined)", flush=True)
    
    missing_dictionaries = [
        d for d in desired_dictionaries 
        if d['name'].strip() not in existing_dict_names
    ]
    
    if not missing_dictionaries:
        print("\n[INFO] [OK] All dictionaries already exist, nothing to create", flush=True)
        return
    
    missing_clone_count = sum(1 for d in missing_dictionaries if d.get('predefined_clone'))
    missing_custom_count = len(missing_dictionaries) - missing_clone_count
    print(f"\n[INFO] Creating {len(missing_dictionaries)} missing dictionaries ({missing_custom_count} custom, {missing_clone_count} clones)...", flush=True)
    
    created_count = 0
    failed_count = 0
    skipped_count = 0
    
    for idx, d in enumerate(missing_dictionaries, 1):
        is_clone = d.get('predefined_clone', False)
        
        try:
            if is_clone:
                print(f"  [{idx}/{len(missing_dictionaries)}] Cloning: {d['name']}...", flush=True)
                
                template_id = d.get('dict_template_id')
                template_name = d.get('dict_template_name')
                
                if not template_id and template_name:
                    template_id = predefined_name_to_id.get(template_name)
                    if template_id:
                        print(f"    [INFO] Resolved template '{template_name}' -> ID {template_id}", flush=True)
                
                if not template_id:
                    print(f"    [FAIL] Cannot clone: No template ID and template '{template_name}' not found in destination", flush=True)
                    failed_count += 1
                    continue
                
                kwargs = {
                    'description': d.get('description', ''),
                    'dict_template_id': int(template_id),
                    'custom': True,
                }
                
                conf_threshold = d.get('confidence_threshold')
                if conf_threshold:
                    kwargs['confidence_threshold'] = conf_threshold
                
                conf_predef = d.get('confidence_level_for_predefined_dict')
                if conf_predef:
                    kwargs['confidence_level_for_predefined_dict'] = conf_predef
                
                hier_ids = d.get('hierarchical_identifiers')
                if hier_ids:
                    kwargs['hierarchical_identifiers'] = hier_ids
                
                if d.get('include_bin_numbers'):
                    kwargs['include_bin_numbers'] = True
                if d.get('include_ssn_numbers'):
                    kwargs['include_ssn_numbers'] = True
                
                # --- PROXIMITY DEBUG & LOGIC FOR CLONES ---
                proximity = d.get('proximity')
                if proximity and proximity > 0:
                    print(f"    [DEBUG] Proximity > 0 detected ({proximity}) for clone. Injecting 'proximity' and 'proximity_length_enabled'.", flush=True)
                    kwargs['proximity'] = proximity
                    kwargs['proximity_length_enabled'] = True
                else:
                    print("    [DEBUG] No proximity detected (or set to 0).", flush=True)
                
                if 'patterns' in d and d['patterns']:
                    kwargs['patterns'] = [(p['action'], p['pattern']) for p in d['patterns']]
                
                if 'phrases' in d and d['phrases']:
                    kwargs['phrases'] = [(p['action'], p['phrase']) for p in d['phrases']]
                
                response = zia.dlp_dictionary.add_dict(
                    d['name'],
                    d['custom_phrase_match_type'],
                    'PATTERNS_AND_PHRASES',
                    **kwargs
                )
                
            else:
                print(f"  [{idx}/{len(missing_dictionaries)}] Creating Custom: {d['name']}...", flush=True)
                
                has_patterns = 'patterns' in d and d['patterns']
                has_phrases = 'phrases' in d and d['phrases']
                
                if not has_patterns and not has_phrases:
                    print("    [FAIL] Skipped: No patterns or phrases defined (may be an unexported clone)", flush=True)
                    skipped_count += 1
                    continue
                
                kwargs = {'description': d.get('description', '')}
                
                # --- PROXIMITY DEBUG & LOGIC FOR CUSTOM DICTIONARIES ---
                proximity = d.get('proximity')
                if proximity and proximity > 0:
                    print(f"    [DEBUG] Proximity > 0 detected ({proximity}) for custom dictionary. Injecting all required proximity flags.", flush=True)
                    kwargs['proximity'] = proximity
                    kwargs['proximity_length_enabled'] = True
                    kwargs['proximity_enabled_for_custom_dictionary'] = True
                else:
                    print("    [DEBUG] No proximity detected (or set to 0).", flush=True)

                conf_threshold = d.get('confidence_threshold')
                if conf_threshold:
                    kwargs['confidence_threshold'] = conf_threshold
                
                if d.get('include_bin_numbers'):
                    kwargs['include_bin_numbers'] = True
                if d.get('include_ssn_numbers'):
                    kwargs['include_ssn_numbers'] = True

                if has_patterns:
                    kwargs['patterns'] = [(p['action'], p['pattern']) for p in d['patterns']]
                
                if has_phrases:
                    kwargs['phrases'] = [(p['action'], p['phrase']) for p in d['phrases']]
                
                response = zia.dlp_dictionary.add_dict(
                    d['name'], 
                    d['custom_phrase_match_type'], 
                    'PATTERNS_AND_PHRASES', 
                    **kwargs
                )
            
            if response and response[0] is not None:
                new_id = response[0].id if hasattr(response[0], 'id') else obj_to_dict(response[0]).get('id')
                clone_marker = " (clone)" if is_clone else ""
                print(f"    [OK] Created{clone_marker} (ID: {new_id})", flush=True)
                created_count += 1
            else:
                error_msg = "Unknown error"
                if len(response) > 2 and response[2]:
                    if isinstance(response[2], dict):
                        error_msg = response[2].get('message', str(response[2]))
                    else:
                        error_msg = str(response[2])
                print(f"    [FAIL] Failed: {error_msg}", flush=True)
                failed_count += 1
                
        except Exception as e:
            print(f"    [FAIL] Exception: {str(e)[:150]}", flush=True)
            failed_count += 1
    
    print(f"\n[SUMMARY] Dictionaries: {created_count} created, {skipped_count} skipped, {failed_count} failed", flush=True)

# ------------------------------------------------------------------------------
# Import Engines
# ------------------------------------------------------------------------------
def import_engines(zia):
    """Import DLP engines from JSON definition file."""
    print("\n" + "="*60, flush=True)
    print("PHASE 2: IMPORTING ENGINES", flush=True)
    print("="*60, flush=True)
    
    engine_file = 'configs/dlp_engines.json'
    if not os.path.exists(engine_file):
        print(f"[INFO] {engine_file} not found, skipping engines", flush=True)
        return
    
    with open(engine_file, 'r') as f:
        desired_engines = json.load(f)
        print(f"[INFO] Loaded {len(desired_engines)} engine definitions", flush=True)
    
    print("[INFO] Checking existing engines...", flush=True)
    existing_engines, err = _nx(zia.dlp_engine.list_dlp_engines_lite())
    if err:
        print(f"[ERROR] Failed to list existing engines: {err}", flush=True)
        return
    
    existing_engine_names = {e.name.strip() for e in existing_engines if e.name}
    print(f"[INFO] Found {len(existing_engine_names)} existing engines in tenant", flush=True)
    
    missing_engines = [
        e for e in desired_engines 
        if e['name'].strip() not in existing_engine_names
    ]
    
    if not missing_engines:
        print("\n[INFO] [OK] All engines already exist, nothing to create", flush=True)
        return
    
    print("\n[INFO] Building dictionary name-to-ID mapping...", flush=True)
    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    if err:
        print(f"[ERROR] Could not fetch dictionaries: {err}", flush=True)
        return
    
    dict_name_to_id = {}
    for d in all_dicts:
        d_dict = obj_to_dict(d)
        name = d_dict.get('name', '').strip()
        dict_name_to_id[name] = d_dict.get('id')
    print(f"[INFO] [OK] Mapped {len(dict_name_to_id)} dictionaries", flush=True)
    
    print(f"\n[INFO] Creating {len(missing_engines)} missing engines...", flush=True)
    
    created_count = 0
    failed_count = 0
    
    for idx, engine_def in enumerate(missing_engines, 1):
        try:
            print(f"  [{idx}/{len(missing_engines)}] Creating: {engine_def['name']}...", flush=True)
            
            final_expression = engine_def['expression']
            sorted_dict_names = sorted(dict_name_to_id.keys(), key=len, reverse=True)
            
            unresolved_refs = []
            for dict_name in sorted_dict_names:
                placeholder = f"D:{dict_name}"
                if placeholder in final_expression:
                    dict_id = dict_name_to_id[dict_name]
                    api_format = f"D{dict_id}.S"
                    final_expression = final_expression.replace(placeholder, api_format)
            
            remaining_matches = re.findall(r'D:([^&|>\s]+(?:\s+[^&|>\s]+)*?)(?=\s*[&|>)]|\s*$)', final_expression)
            for ref in remaining_matches:
                ref = ref.strip()
                if ref and not ref.startswith('D') and not ref[0].isdigit():
                    print(f"    [WARN] Dictionary not found: '{ref}'", flush=True)
                    unresolved_refs.append(ref)
            
            remaining = re.findall(r'D:[^D\d][^&|>)]*', final_expression)
            if remaining:
                print(f"    [WARN] Unresolved dictionary references: {remaining}", flush=True)
            
            response = zia.dlp_engine.add_dlp_engine(
                name=engine_def['name'],
                engine_expression=final_expression,
                custom_dlp_engine=True,
                description=engine_def.get('description', 'Imported engine')
            )
            
            if response and isinstance(response, tuple) and response[0] is not None:
                new_id = response[0].id if hasattr(response[0], 'id') else obj_to_dict(response[0]).get('id')
                print(f"    [OK] Created (ID: {new_id})", flush=True)
                created_count += 1
            else:
                error_msg = "Unknown error"
                if len(response) > 2 and response[2]:
                    if isinstance(response[2], dict):
                        error_msg = response[2].get('message', str(response[2]))
                    else:
                        error_msg = str(response[2])
                print(f"    [FAIL] Failed: {error_msg}", flush=True)
                failed_count += 1
                
        except Exception as e:
            error_str = str(e)
            print(f"    [FAIL] Exception: {error_str[:200]}", flush=True)
            failed_count += 1
    
    print(f"\n[SUMMARY] Engines: {created_count} created, {failed_count} failed", flush=True)

# ------------------------------------------------------------------------------
# Import Policies
# ------------------------------------------------------------------------------
def import_policies(client, use_rank_0=False): 
    """Import DLP policies from JSON definition file."""
    print("\n" + "="*60, flush=True)
    print("PHASE 3: IMPORTING POLICIES", flush=True)
    if use_rank_0:
        print("MODE: Admin Rank 0 (Conflict Resolution)", flush=True)
    else:
        print("MODE: Normal (Standard Ranking)", flush=True)
    print("="*60, flush=True)
    
    policy_file = 'configs/dlp_policies.json'
    if not os.path.exists(policy_file):
        print(f"[INFO] {policy_file} not found, skipping policies", flush=True)
        return
    
    with open(policy_file, 'r') as f:
        desired_policies = json.load(f)
        print(f"[INFO] Loaded {len(desired_policies)} policy definitions", flush=True)
    
    print("[INFO] Checking existing policies...", flush=True)
    existing_rules, err = _nx(client.zia.dlp_web_rules.list_rules())
    if err:
        print(f"[ERROR] Failed to list existing policies: {err}", flush=True)
        return
    
    existing_policy_names = {r.name.strip() for r in existing_rules if r.name}
    print(f"[INFO] Found {len(existing_policy_names)} existing policies in tenant", flush=True)
    
    missing_policies = [
        p for p in desired_policies 
        if p['name'].strip() not in existing_policy_names
    ]
    
    if not missing_policies:
        print("\n[INFO] [OK] All policies already exist, nothing to create", flush=True)
        return
    
    print("\n[INFO] Building engine name-to-ID mapping...", flush=True)
    all_engines, err = _nx(client.zia.dlp_engine.list_dlp_engines_lite())
    if err:
        print(f"[ERROR] Could not fetch engines: {err}", flush=True)
        return
    
    engine_name_to_id = {e.name.strip(): e.id for e in all_engines if e.name}
    print(f"[INFO] [OK] Mapped {len(engine_name_to_id)} engines", flush=True)
    
    print(f"\n[INFO] Creating {len(missing_policies)} missing policies...", flush=True)
    
    created_count = 0
    failed_count = 0
    
    for idx, policy_def in enumerate(missing_policies, 1):
        try:
            print(f"  [{idx}/{len(missing_policies)}] Creating: {policy_def['name']}...", flush=True)
            
            engine_names = policy_def.get('engines', [])
            engine_ids = []
            missing_engines = []
            
            for engine_name in engine_names:
                if engine_name in engine_name_to_id:
                    engine_ids.append(engine_name_to_id[engine_name])
                else:
                    missing_engines.append(engine_name)
            
            if missing_engines:
                print(f"    [WARN] Could not find engines: {missing_engines}", flush=True)
            
            if not engine_ids:
                print("    [FAIL] No valid engines found, skipping policy", flush=True)
                failed_count += 1
                continue
            
            payload = {
                'name': policy_def['name'],
                'order': '1',
                'state': policy_def.get('state', 'ENABLED'),
                'action': policy_def.get('action', 'ALLOW'),
                'dlp_engines': engine_ids,
                'protocols': policy_def.get('protocols', ['ANY_RULE'])
            }
            
            if use_rank_0:
                payload['rank'] = 0
            else:
                payload['rank'] = policy_def.get('rank', 7)
            
            if policy_def.get('description'):
                payload['description'] = policy_def['description']
            
            if policy_def.get('severity'):
                payload['severity'] = policy_def['severity']
            
            if policy_def.get('min_size'):
                payload['min_size'] = policy_def['min_size']
            
            if policy_def.get('file_types'):
                payload['file_types'] = policy_def['file_types']
            
            if policy_def.get('cloud_applications'):
                payload['cloud_applications'] = policy_def['cloud_applications']
            
            optional_fields = [
                'locations', 'location_groups', 'groups', 'departments',
                'users', 'url_categories', 'labels'
            ]
            for field in optional_fields:
                if policy_def.get(field):
                    payload[field] = policy_def[field]
            
            if policy_def.get('match_only'):
                payload['match_only'] = True
            if policy_def.get('without_content_inspection'):
                payload['without_content_inspection'] = True
            
            response = client.zia.dlp_web_rules.add_rule(**payload)
            
            if response and isinstance(response, tuple) and response[0] is not None:
                new_id = response[0].id if hasattr(response[0], 'id') else obj_to_dict(response[0]).get('id')
                print(f"    [OK] Created (ID: {new_id})", flush=True)
                created_count += 1
            else:
                error_msg = "Unknown error"
                if len(response) > 2 and response[2]:
                    if isinstance(response[2], dict):
                        error_msg = response[2].get('message', str(response[2]))
                    else:
                        error_msg = str(response[2])
                print(f"    [FAIL] Failed: {error_msg}", flush=True)
                failed_count += 1
                
        except Exception as e:
            error_str = str(e)
            print(f"    [FAIL] Exception: {error_str[:200]}", flush=True)
            failed_count += 1
    
    print(f"\n[SUMMARY] Policies: {created_count} created, {failed_count} failed", flush=True)

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
def get_credentials():
    """Prompt user for ZIA credentials interactively."""
    print("\n" + "-"*60, flush=True)
    print("Enter your ZIA credentials", flush=True)
    print("-"*60, flush=True)
    print("(Credentials are stored in memory only - not saved to disk)\n", flush=True)
    
    username = input("ZIA Username (email): ").strip()
    password = getpass.getpass("ZIA Password: ")
    api_key = getpass.getpass("ZIA API Key: ")
    
    print("\nZIA Cloud options: zscaler, zscalerone, zscalertwo, zscalerthree,")
    print("                   zscloud, zscalerbeta, zscalergov, zscalerten")
    cloud = input("ZIA Cloud: ").strip().lower()
    
    return {
        "username": username,
        "password": password,
        "api_key": api_key,
        "cloud": cloud,
    }

def main():
    print("\n" + "="*60, flush=True)
    print("ZIA DLP Configuration Importer", flush=True)
    print("="*60, flush=True)
    print("\n" + "="*60)
    print("DEPLOYMENT MODE SELECTION")
    print("="*60)
    print("[0] Admin Rank 0 Mode (Resolves conflicts, highest priority)")
    print("[1] Normal Mode (Uses default rank from API Admin)")
    
    mode_choice = input("\nSelect deployment mode (0 or 1): ").strip()
    use_rank_0 = (mode_choice == '0')
    
    if use_rank_0:
        print("[INFO] Mode Enabled: ALL policies will be set to Admin Rank 0.")
    else:
        print("[INFO] Mode Enabled: Policies will use standard/default ranking.")
    
    config = get_credentials()
    
    missing = [k for k, v in config.items() if not v]
    if missing:
        print(f"\n[ERROR] Missing credentials: {', '.join(missing)}", flush=True)
        sys.exit(1)
    
    try:
        print("\n[INFO] Connecting to ZIA...", flush=True)
        with LegacyZIAClient(config) as client:
            print("[INFO] [OK] Connected successfully", flush=True)
            
            # Phase 1, 2, 3: Import Operations
            import_dictionaries(client.zia)
            import_engines(client.zia)
            import_policies(client, use_rank_0=use_rank_0)
            
            print("\n" + "="*60, flush=True)
            print("Import Complete!", flush=True)
            print("="*60 + "\n", flush=True)
            
            # Phase 4: Post-Import Tweaks
            set_medical_low_confidence(client.zia)            
            set_financial_high_confidence(client.zia)

            # Phase 5: Verification
            verify_deployment(client.zia)
            
    except Exception as e:
        print(f"\n[CRITICAL ERROR] {e}", flush=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()