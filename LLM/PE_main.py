

import pefile
import os
import array
import math
import pickle
import joblib
import sys


# Function to calculate entropy
def get_entropy(data):
    if not data:
        return 0.0
    occurrences = array.array('L', [0] * 256)
    
    for byte in data:
        occurrences[byte] += 1

    return -sum((count / len(data)) * math.log2(count / len(data)) for count in occurrences if count)


# Extract resources information
def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                resources.append([get_entropy(data), resource_lang.data.struct.Size])
        except Exception:
            return resources
    return resources


# Extract version information
def get_version_info(pe):
    res = {}
    if hasattr(pe, 'FileInfo'):
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    res.update(st.entries)
            elif fileinfo.Key == 'VarFileInfo':
                for var in fileinfo.Var:
                    res.update(var.entry.items())  # ✅ Correct indentations())

    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        fixed_info = pe.VS_FIXEDFILEINFO
        res.update({
            'flags': fixed_info.FileFlags,
            'os': fixed_info.FileOS,
            'type': fixed_info.FileType,
            'file_version': fixed_info.FileVersionLS,
            'product_version': fixed_info.ProductVersionLS,
            'signature': fixed_info.Signature,
            'struct_version': fixed_info.StrucVersion,
        })
    return res


# Extract PE features
def extract_infos(fpath):
    try:
        pe = pefile.PE(fpath)
    except pefile.PEFormatError:
        print(f"❌ Error: Unable to parse {fpath} as a valid PE file.")
        sys.exit(1)

    res = {
        'Machine': pe.FILE_HEADER.Machine,
        'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
        'Characteristics': pe.FILE_HEADER.Characteristics,
        'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
        'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
        'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
        'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
        'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
        'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
        'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
        'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
        'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
        'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
        'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
        'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
        'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
        'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
        'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
        'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
        'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
        'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
    }

    # Sections Analysis
    res['SectionsNb'] = len(pe.sections)
    entropies = [section.get_entropy() for section in pe.sections]
    res['SectionsMeanEntropy'] = sum(entropies) / len(entropies) if entropies else 0
    res['SectionsMinEntropy'] = min(entropies) if entropies else 0
    res['SectionsMaxEntropy'] = max(entropies) if entropies else 0

    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    res['SectionsMeanRawsize'] = sum(raw_sizes) / len(raw_sizes) if raw_sizes else 0
    res['SectionsMinRawsize'] = min(raw_sizes, default=0)
    res['SectionsMaxRawsize'] = max(raw_sizes, default=0)

    # Imports
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        res['ImportsNb'] = sum(len(x.imports) for x in pe.DIRECTORY_ENTRY_IMPORT)
    except AttributeError:
        res['ImportsNbDLL'] = res['ImportsNb'] = 0

    # Exports
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        res['ExportNb'] = 0

    # Resources
    resources = get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if resources:
        entropies = [r[0] for r in resources]
        sizes = [r[1] for r in resources]
        res['ResourcesMeanEntropy'] = sum(entropies) / len(entropies)
        res['ResourcesMinEntropy'] = min(entropies)
        res['ResourcesMaxEntropy'] = max(entropies)
        res['ResourcesMeanSize'] = sum(sizes) / len(sizes)
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res.update({k: 0 for k in ['ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy',
                                   'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize']})

    # Version Information
    res['VersionInformationSize'] = len(get_version_info(pe))
    
    return res


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python pe_main.py <path_to_pe_file>")
        sys.exit(1)

    # Load classifier and feature list
    try:
        clf = joblib.load('Classifier/classifier.pkl')
        if not hasattr(clf, "predict"):
            raise ValueError("Invalid model format. Ensure the classifier is trained correctly.")

    except Exception as e:
        print(f"❌ Error loading model: {e}")
        sys.exit(1)

    with open('Classifier/features.pkl', 'rb') as f:
        features = pickle.load(f)

    # Extract features
    data = extract_infos(sys.argv[1])
    pe_features = [data.get(feat, 0) for feat in features]

    # Predict
    prediction = clf.predict([pe_features])[0]
    print(f"🔍 {os.path.basename(sys.argv[1])} is {'malicious' if prediction == 0 else 'legitimate'}.")
