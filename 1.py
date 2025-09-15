import os
import hashlib
import pandas as pd
import argparse
from datetime import datetime


BASELINE_FILENAME = 'baseline.csv'
REPORT_FILENAME = 'integrity_report.xlsx'


def calculate_sha256(filepath):

    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:

            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError:

        return None


def generate_baseline(folder_path):

    print(f"Generating baseline for '{folder_path}'...")
    file_hashes = {}

    if not os.path.isdir(folder_path):
        print(f"Error: Folder '{folder_path}' not found.")
        return

    for root, _, files in os.walk(folder_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_hash = calculate_sha256(filepath)
            if file_hash:
                relative_path = os.path.relpath(filepath, folder_path)
                file_hashes[relative_path] = file_hash

    if not file_hashes:
        print("No files found to generate a baseline.")
        return


    baseline_df = pd.DataFrame(list(file_hashes.items()), columns=['file_path', 'hash'])
    baseline_df.to_csv(BASELINE_FILENAME, index=False)
    print(f"Baseline generated successfully and saved to '{BASELINE_FILENAME}'.")


def verify_integrity(folder_path):

    print(f"Starting integrity verification for '{folder_path}'...")


    try:
        baseline_df = pd.read_csv(BASELINE_FILENAME)
        baseline_hashes = dict(zip(baseline_df['file_path'], baseline_df['hash']))
    except FileNotFoundError:
        print(f"Error: Baseline file '{BASELINE_FILENAME}' not found.")
        print("Please generate a baseline first using '--mode baseline'.")
        return


    current_hashes = {}
    if not os.path.isdir(folder_path):
        print(f"Error: Verification folder '{folder_path}' not found.")
        return

    for root, _, files in os.walk(folder_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_hash = calculate_sha256(filepath)
            if file_hash:
                relative_path = os.path.relpath(filepath, folder_path)
                current_hashes[relative_path] = file_hash


    report_data = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    all_files = set(baseline_hashes.keys()) | set(current_hashes.keys())

    for file_rel_path in sorted(all_files):
        status = ''
        last_hash = baseline_hashes.get(file_rel_path, '—')
        current_hash = current_hashes.get(file_rel_path, '—')

        if file_rel_path not in current_hashes:
            status = 'Missing'
        elif file_rel_path not in baseline_hashes:
            status = 'New'
        elif baseline_hashes[file_rel_path] != current_hashes[file_rel_path]:
            status = 'Modified'
        else:
            status = 'Unchanged'

        report_data.append({
            'File Path': file_rel_path,
            'Status': status,
            'Last Hash': last_hash,
            'Current Hash': current_hash,
            'Timestamp': timestamp
        })

    if not report_data:
        print("No files to verify.")
        return

    # --- 4. Export to Excel ---
    report_df = pd.DataFrame(report_data)
    report_df.to_excel(REPORT_FILENAME, index=False)
    print(f"Verification complete. Report saved to '{REPORT_FILENAME}'.")


def main():
    """Main function to parse arguments and run the selected mode."""
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument(
        '--mode',
        required=True,
        choices=['baseline', 'verify'],
        help="Operation mode: 'baseline' to create a new hash baseline, 'verify' to check against it."
    )
    parser.add_argument(
        '--folder',
        required=True,
        help="The target folder to scan."
    )

    args = parser.parse_args()

    folder = args.folder

    if args.mode == 'baseline':
        generate_baseline(folder)
    elif args.mode == 'verify':
        verify_integrity(folder)


if __name__ == "__main__":
    main()
