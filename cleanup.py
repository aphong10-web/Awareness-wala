from pathlib import Path
import shutil


# === ADDED: cleanup saved lab output folders ===
def ask_cleanup_saved_folders():
    project_root = Path(__file__).resolve().parent

    # Only generated folders should be deleted.
    # Do NOT delete wordlist/, because rockyou.txt may be large and useful later.
    saved_folders = [
        "scans",
        "captures",
        "pmkid_captures",
        "hashes",
    ]

    existing_folders = []

    for folder_name in saved_folders:
        folder_path = project_root / folder_name

        if folder_path.exists() and folder_path.is_dir():
            existing_folders.append(folder_path)

    if not existing_folders:
        return

    print("\nSaved output folders found:")

    for folder in existing_folders:
        print(f"- {folder.name}/")

    choice = input("\nDo you want to keep these saved folders? (y/n): ").strip().lower()

    if choice in ("y", "yes"):
        print("[+] Saved folders kept.")
        return

    if choice in ("n", "no"):
        for folder in existing_folders:
            shutil.rmtree(folder)
            print(f"[+] Deleted {folder.name}/")

        print("[+] Cleanup complete.")
        return

    print("[!] Invalid choice. Saved folders were kept for safety.")
