import Levenshtein
import json

try:
    with open("known_slopsquats.json", "r", encoding='utf-8') as file:
        KNOWN_SLOPSQUATS = json.load(file)
except FileNotFoundError:
    KNOWN_SLOPSQUATS = {}

def get_min_edit_distance(scanned_package_name, top_packages_list):
    min_distance = float('inf')
    
    for safe_package in top_packages_list:
        
        dist = Levenshtein.distance(scanned_package_name, safe_package)
        
        if dist < min_distance:
            min_distance = dist
            
            if min_distance == 1:
                break
                
    return min_distance




def char_substitution_detected(scanned_package_name, top_packages_list):
    HOMOGLYPH_DICT = {
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '5': 's',
        'rn': 'm',
    }
    
    de_obfuscated_word = scanned_package_name
    
    for fake_char, real_char in HOMOGLYPH_DICT.items():
        de_obfuscated_word = de_obfuscated_word.replace(fake_char, real_char)
        
    return 1 if de_obfuscated_word in top_packages_list else 0


def underscore_substition_detected(scanned_package_name, top_packages_list):

    underscore_subbed_name = scanned_package_name
    
    if "_" in scanned_package_name:
        underscore_subbed_name = underscore_subbed_name.replace("_", "-")
    elif "-" in scanned_package_name:
        underscore_subbed_name = underscore_subbed_name.replace("-", "_")
        
    return 1 if underscore_subbed_name in top_packages_list else 0

def prefix_or_suffix_trickery(scanned_package_name:str, top_packages_list):

    if scanned_package_name in top_packages_list:
        return 0
        
    for package in top_packages_list:
        if scanned_package_name.startswith(package+"_") or scanned_package_name.startswith(package+"-"):
            return 1
        if scanned_package_name.endswith("_"+package) or scanned_package_name.endswith("-"+package):
            return 1
    
    return 0


def conflation_pattern_detection(scanned_package_name:str, top_packages_list:list[str]):

    if scanned_package_name in top_packages_list:
        return 0
    
    if "_" in scanned_package_name:
        package_names_seperated = scanned_package_name.split("_")
        if all(names in top_packages_list for names in package_names_seperated):
            return 1
    elif "-" in scanned_package_name:
        package_names_seperated = scanned_package_name.split("-")
        if all(names in top_packages_list for names in package_names_seperated):
            return 1            
    
    return 0 

def known_slopsquat_detection(scanned_package_name):
    if scanned_package_name in KNOWN_SLOPSQUATS:
        return 1
    else:
        return 0