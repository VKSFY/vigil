# Vigil — User Guide

This is the friendly version of the docs. If you want the deep technical write-up, that's the [README](README.md). If you just want to use the thing, you're in the right place.

## What is Vigil?

Vigil is a small antivirus tool for Windows that you run yourself. It looks at programs, scripts, Word/Excel documents, and PDFs, and tells you whether each one looks dangerous. It can also watch a folder of your choice — like Downloads — and check every new file the moment it arrives. When something looks bad, Vigil moves it out of the way into a quarantine folder so you can decide what to do with it.

## What it can and can't do

**It can:**

- Scan a single file you point it at and give you a verdict in a second or two.
- Watch a folder in the background and scan anything new that lands in it.
- Watch the programs running on your computer for suspicious patterns (like a Word document spawning PowerShell, which legitimate Office files basically never do).
- Move flagged files into a quarantine folder and remember the original location so you can restore them.
- Show you everything it has done in a small local dashboard in your browser.

**It can't:**

- Replace Windows Defender. Defender ships with Windows, has a kernel driver, signed definition updates, cloud lookups, and a security team behind it. Vigil is a personal-project antivirus, not a commercial product. Run them both — Defender as your real protection, Vigil as an extra opinion.
- Scan every file on your computer all the time. By default it only scans files you point it at, or files that appear in the folder you asked it to watch.
- Catch every threat. No tool does, and Vigil's PowerShell detection in particular is experimental — it was trained on a synthetic dataset, so it works well on test files but will miss things that look very different from what it was trained on.
- Stop malware once it has already started running. The behavior monitor will *alert* you to suspicious process activity, but it doesn't kill the process. That's a different category of tool.

## Installing Vigil

You'll need Python 3.10 or newer. If you don't have it, grab it from [python.org](https://www.python.org/downloads/) — during the installer, tick the box that says **"Add Python to PATH"**. That one step saves a lot of grief later.

Once Python is installed, open PowerShell (press the Windows key, type "powershell", hit Enter) and run:

```powershell
git clone https://github.com/VKSFY/vigil
cd vigil
pip install -r requirements.txt
```

That clones the repo and installs the Python libraries it needs. It takes a minute or two the first time.

If you want the full Windows experience — a Start Menu shortcut and auto-start when you log in — run `installer\install.bat` from inside the `vigil` folder. That's optional. You can also just run Vigil manually whenever you want.

## Scanning a single file

The simplest thing Vigil can do is scan one file. From the `vigil` folder, run:

```powershell
python scan.py path\to\suspicious.exe
```

Replace the path with whatever you actually want to scan — an EXE, a PowerShell script, a Word document, a PDF. Vigil prints a verdict (`CLEAN` or `MALICIOUS`), a confidence number, and a few reasons for the call. The whole thing takes a couple of seconds.

You can also point it at a folder and it will walk through every file inside.

## Starting the real-time monitor

If you want Vigil to watch a folder in the background — say, your Downloads folder — start it like this:

```powershell
python -m antivirus --watch C:\Users\YourName\Downloads
```

What you'll see:

- A small shield icon appears in your system tray (the area near the clock). Grey means idle, green means actively watching.
- Your browser opens to `http://127.0.0.1:7331/` — that's the dashboard. It's a local page, only you can see it.
- Right-click the tray icon for Start/Stop/Open Log/Exit.

From now on, every new file that lands in the watched folder gets scanned automatically. If something looks bad, you'll see it on the dashboard within a few seconds.

The monitor keeps running until you exit it (right-click tray → Exit, or close the terminal window). If you installed via `installer\install.bat`, it also starts on login.

## Optional: VirusTotal second opinion

If you want Vigil to also check flagged files against [VirusTotal](https://www.virustotal.com) — the big community database of malware hashes used by basically every security vendor — you can plug in a free API key. Get one at [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us), then set it in your terminal before running Vigil:

```powershell
$env:VIGIL_VT_API_KEY = "your_key_here"
```

That's it. From then on, whenever Vigil flags something as malicious, it will also show you what VirusTotal thinks — something like "39 / 72 engines flagged this file" with a link to the full report. If the file isn't in VirusTotal's database yet, you'll see "hash not in database yet" — that's not a failure, it just means nobody's submitted it before. Vigil only sends the file's hash, never the file itself.

The free VirusTotal tier limits you to 4 lookups per minute, so if you trigger more than that, some scans will skip the VT check. That's fine — Vigil still works without it.

If you don't set the key, Vigil silently skips the VirusTotal step and works exactly like before.

## What happens when something is flagged

When Vigil decides a file is malicious, it doesn't ask first — it moves the file into the `quarantine` folder inside the Vigil directory. The file gets renamed with a `.quar` extension so it can't accidentally be opened or run. Alongside it, Vigil writes a small `.json` file that remembers the original location, the verdict, the confidence, and the reasons.

The dashboard's **Quarantine** panel shows everything currently quarantined, with a Restore button next to each entry.

You won't get a popup or a scary banner — Vigil quietly handles it and shows it in the dashboard. If you want a notification, the tray icon is the source of truth: it goes green when monitoring, and any new quarantine entry shows up in the dashboard within 10 seconds.

## Restoring a false positive

Sometimes Vigil will quarantine a file that's actually fine. To restore it:

1. Open the dashboard at `http://127.0.0.1:7331/`.
2. Find the file in the **Quarantine** panel.
3. Click **Restore**.

The file is moved back to where it came from, the `.quar` and sidecar JSON are removed, and you're done. If the original location no longer exists (you deleted the folder, say), the restore lands in your Documents folder with a clear name so you can find it.

If you want to permanently delete it instead of restoring, the same panel has a **Delete** button.

## Submitting feedback on a wrong detection

If Vigil flagged something it shouldn't have — or missed something it should have caught — you can tell it so it learns. From the `vigil` folder:

```powershell
python scan.py feedback path\to\the\file.ps1 clean
```

or:

```powershell
python scan.py feedback path\to\the\file.ps1 malicious
```

That's it. Vigil writes the file and the correct label to a feedback log. Once you've submitted 50 or so corrections, you can retrain the PowerShell model:

```powershell
python -m src.retrain --type ps1
```

The retrain only replaces the model if the new one is actually better on a held-out test split — so it's safe to run. If the retrain didn't improve anything, the old model stays.

(The PE model — the one for .exe files — is large and trained on a 200 GB dataset, so it doesn't retrain locally. Feedback is still recorded though; it just isn't fed back automatically.)

---

## FAQ

**Will this slow my computer down?**

Almost certainly not in a way you'd notice. The realtime monitor only does work when a new file lands in the watched folder — the rest of the time it sits idle waiting for filesystem events. Each scan takes about 2 ms for the model itself, plus however long it takes to read the file off disk. The behavior monitor polls running processes a few times a second but only fetches details for new ones, so it stays cheap. If you start watching a folder where thousands of files appear per minute, you'd see CPU use go up — but for normal Downloads-folder traffic it's invisible.

**What happens to quarantined files — are they deleted?**

No. They're moved into the `quarantine` folder inside the Vigil directory, renamed with a `.quar` extension so they can't be run by accident, and a small JSON file records where they came from. They stay there until you either restore them or click Delete in the dashboard. Vigil never deletes anything on its own.

**How do I know it's actually working?**

A few ways. The tray icon goes green when it's monitoring — if it's grey, it isn't. The dashboard at `http://127.0.0.1:7331/` shows the most recent scans, with timestamps. If you want to verify end-to-end, drop a known-clean file into the watched folder and you should see a scan entry appear within a couple of seconds. There's also a `logs/scan_log.jsonl` file that records every scan, which you can open in any text editor.

**Is this a replacement for Windows Defender?**

No. Run them both. Defender is your real protection — it has a kernel driver, signed updates, cloud lookups, and a security team. Vigil is a personal-project tool that catches a different class of things (especially Office macros, suspicious PowerShell, and process behavior) and gives you visibility into what's happening on your machine. They complement each other and don't conflict.

**The dashboard shows "no changelog yet" — is something broken?**

No, that's expected. The changelog only fills in once you've retrained a model. If you haven't run `python -m src.retrain` yet, there's nothing for it to show. Once you do a retrain — even one that gets rejected because the new model wasn't better — an entry shows up.

**A file I know is safe got flagged — what do I do?**

Two steps. First, restore it from the dashboard's Quarantine panel — that gets the file back to where it was. Second, submit feedback so Vigil learns from the mistake:

```powershell
python scan.py feedback path\to\that\file.ext clean
```

If it's a PowerShell script and you've collected 50+ corrections, you can retrain to bake the fix into the model. For Office and PDF files, the rules are weighted heuristics rather than a learned model, so the feedback is logged but doesn't change behavior automatically.

**How do I uninstall this?**

If you ran `installer\install.bat`, undo the autostart entry by running this in PowerShell:

```powershell
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AVMonitor /f
```

(The registry entry is named `AVMonitor` internally — that's not a typo. It's a holdover from before the project was renamed to Vigil, and changing it would orphan existing autostart entries on machines that installed under the old name.)

Then delete the Start Menu shortcut at `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Vigil.lnk`. After that, just delete the `vigil` folder. There's no installer to uninstall — everything Vigil does lives inside that folder, including the quarantine and logs. (If you want to keep your quarantine and logs as evidence, copy them out before deleting.)
