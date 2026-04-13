import { useState, useCallback, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { Landing, type RecentDrive } from "@/components/Landing";
import { UnlockView } from "@/components/UnlockView";
import { VolumeView } from "@/components/VolumeView";
import { LockScreen } from "@/components/LockScreen";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";
import { Shield, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { UpdateNotification } from "@/components/UpdateNotification";

export type AppStep = "landing" | "file_selected" | "unlocking" | "unlocked" | "mounting" | "mounted";

export interface VolumeInfo {
  encryption: string;
  hash: string;
  header_version: number;
  volume_size: number;
  encrypted_area_start: number;
  encrypted_area_length: number;
  sector_size: number;
  is_hidden: boolean;
}

export interface FileEntry {
  name: string;
  path: string;
  size: number;
  is_dir: boolean;
}

const RECENT_DRIVES_KEY = "safedrive_recent_drives";
const MAX_RECENT = 10;

function loadRecentDrives(): RecentDrive[] {
  try {
    const raw = localStorage.getItem(RECENT_DRIVES_KEY);
    if (raw) return JSON.parse(raw);
  } catch {
    // ignore
  }
  return [];
}

function saveRecentDrives(drives: RecentDrive[]) {
  localStorage.setItem(RECENT_DRIVES_KEY, JSON.stringify(drives));
}

function addRecentDrive(path: string, drives: RecentDrive[]): RecentDrive[] {
  const name = path.split("\\").pop() || path;
  const filtered = drives.filter((d) => d.path !== path);
  const updated = [
    { path, name, lastOpened: new Date().toISOString() },
    ...filtered,
  ].slice(0, MAX_RECENT);
  saveRecentDrives(updated);
  return updated;
}

function removeRecentDrive(path: string, drives: RecentDrive[]): RecentDrive[] {
  const updated = drives.filter((d) => d.path !== path);
  saveRecentDrives(updated);
  return updated;
}

function App() {
  const [step, setStep] = useState<AppStep>("landing");
  const [filePath, setFilePath] = useState<string>("");
  const [volumeInfo, setVolumeInfo] = useState<VolumeInfo | null>(null);
  const [fsType, setFsType] = useState<string>("");
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [driveLetter, setDriveLetter] = useState<string | null>(null);
  const [extractProgress, setExtractProgress] = useState<number>(0);
  const [isExtracting, setIsExtracting] = useState(false);
  const [isMounting, setIsMounting] = useState(false);
  const [isUnmounting, setIsUnmounting] = useState(false);
  const [mountProgress, setMountProgress] = useState<number>(0);
  const [mountStage, setMountStage] = useState<string>("");
  const [recentDrives, setRecentDrives] = useState<RecentDrive[]>(loadRecentDrives);
  const [isLocked, setIsLocked] = useState(false);
  const isDialogOpen = useRef(false);

  // Lock screen when window loses focus and a volume is open
  useEffect(() => {
    const handleBlur = () => {
      if (isDialogOpen.current) return;
      setStep((currentStep) => {
        if (currentStep === "unlocked" || currentStep === "mounting" || currentStep === "mounted") {
          setIsLocked(true);
        }
        return currentStep;
      });
    };
    window.addEventListener("blur", handleBlur);
    return () => window.removeEventListener("blur", handleBlur);
  }, []);

  // Open file dialog
  const handleSelectFile = useCallback(async () => {
    isDialogOpen.current = true;
    try {
      const selected = await openDialog({
        multiple: false,
        filters: [
          { name: "TrueCrypt Volume", extensions: ["tc", "hc"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });
      if (selected) {
        setFilePath(selected as string);
        setStep("file_selected");
      }
    } finally {
      isDialogOpen.current = false;
    }
  }, []);

  // File dropped
  const handleFileDrop = useCallback((path: string) => {
    setFilePath(path);
    setStep("file_selected");
  }, []);

  // Open from recent list
  const handleOpenRecent = useCallback((path: string) => {
    setFilePath(path);
    setStep("file_selected");
  }, []);

  // Remove from recent
  const handleRemoveRecent = useCallback(
    (path: string) => {
      setRecentDrives((prev) => removeRecentDrive(path, prev));
    },
    []
  );

  // Unlock volume
  const handleUnlock = useCallback(
    async (password: string) => {
      setStep("unlocking");
      try {
        const result = await invoke<{ info: VolumeInfo; fs_type: string }>(
          "open_volume",
          { path: filePath, password }
        );
        setVolumeInfo(result.info);
        setFsType(result.fs_type);

        // Load file listing
        try {
          const fileList = await invoke<FileEntry[]>("list_files", {
            path: "\\",
          });
          setFiles(fileList);
        } catch (e) {
          console.warn("Could not list files:", e);
          setFiles([]);
        }

        // Add to recent drives
        setRecentDrives((prev) => addRecentDrive(filePath, prev));

        setStep("unlocked");
      } catch (e) {
        setStep("file_selected");
        toast.error("Failed to unlock volume", {
          description: String(e),
        });
      }
    },
    [filePath]
  );

  // Extract all files
  const handleExtractAll = useCallback(async () => {
    isDialogOpen.current = true;
    let dest: string | null = null;
    try {
      dest = await openDialog({
        directory: true,
        title: "Select extraction destination",
      }) as string | null;
    } finally {
      isDialogOpen.current = false;
    }
    if (!dest) return;

    setIsExtracting(true);
    setExtractProgress(0);

    const unlisten = await listen<number>("extract-progress", (event) => {
      setExtractProgress(event.payload);
    });

    try {
      const count = await invoke<number>("extract_all", { dest });
      toast.success(`Extracted ${count} files successfully`);
    } catch (e) {
      toast.error("Extraction failed", { description: String(e) });
    } finally {
      unlisten();
      setIsExtracting(false);
      setExtractProgress(0);
    }
  }, []);

  // Extract selected files
  const handleExtractSelected = useCallback(async (paths: string[]) => {
    isDialogOpen.current = true;
    let dest: string | null = null;
    try {
      dest = await openDialog({
        directory: true,
        title: "Select extraction destination",
      }) as string | null;
    } finally {
      isDialogOpen.current = false;
    }
    if (!dest) return;

    setIsExtracting(true);
    setExtractProgress(0);

    const unlisten = await listen<number>("extract-progress", (event) => {
      setExtractProgress(event.payload);
    });

    try {
      const count = await invoke<number>("extract_files", {
        dest,
        paths,
      });
      toast.success(`Extracted ${count} files successfully`);
    } catch (e) {
      toast.error("Extraction failed", { description: String(e) });
    } finally {
      unlisten();
      setIsExtracting(false);
      setExtractProgress(0);
    }
  }, []);

  // Mount volume
  const handleMount = useCallback(async () => {
    setIsMounting(true);
    setMountProgress(0);
    setMountStage("");

    const unlisten = await listen<{ stage: string; progress: number }>(
      "mount-progress",
      (event) => {
        setMountStage(event.payload.stage);
        setMountProgress(event.payload.progress);
      }
    );

    try {
      const result = await invoke<{ drive_letter: string | null }>(
        "mount_volume"
      );
      setDriveLetter(result.drive_letter);
      setStep("mounted");
      if (result.drive_letter) {
        toast.success(`Volume mounted as ${result.drive_letter}`);
      } else {
        toast.info(
          "VHD mounted but no drive letter assigned. Check Disk Management."
        );
      }
    } catch (e) {
      toast.error("Mount failed", { description: String(e) });
    } finally {
      unlisten();
      setIsMounting(false);
      setMountProgress(0);
      setMountStage("");
    }
  }, []);

  // Unmount volume
  const handleUnmount = useCallback(async () => {
    setIsUnmounting(true);

    try {
      await invoke("unmount_volume");
      setDriveLetter(null);
      setStep("unlocked");
      toast.success("Volume unmounted and changes saved");
    } catch (e) {
      toast.error("Unmount failed", { description: String(e) });
    } finally {
      setIsUnmounting(false);
    }
  }, []);

  // Close volume and go back
  const handleClose = useCallback(async () => {
    try {
      await invoke("close_volume");
    } catch {
      // Ignore errors on close
    }
    setStep("landing");
    setFilePath("");
    setVolumeInfo(null);
    setFsType("");
    setFiles([]);
    setDriveLetter(null);
    setIsMounting(false);
    setIsUnmounting(false);
    setMountProgress(0);
    setMountStage("");
  }, []);

  // Go back to landing (without close, for pre-unlock steps)
  const handleBack = useCallback(() => {
    setStep("landing");
    setFilePath("");
  }, []);

  const isVolumeOpen =
    step === "unlocked" || step === "mounted" || step === "mounting";

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="border-b px-5 py-3 flex items-center justify-between bg-card">
        <div className="flex items-center gap-2.5">
          {isVolumeOpen && (
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0 mr-1"
              onClick={handleClose}
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <Shield className="h-5 w-5 text-primary" />
          <h1 className="text-base font-semibold text-foreground tracking-tight">
            SafeDrive
          </h1>
        </div>
        {isVolumeOpen && (
          <button
            onClick={handleClose}
            className="text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Close Volume
          </button>
        )}
      </div>

      {/* Content */}
      {step === "landing" && (
        <Landing
          recentDrives={recentDrives}
          onOpenDrive={handleSelectFile}
          onOpenRecent={handleOpenRecent}
          onRemoveRecent={handleRemoveRecent}
          onFileDrop={handleFileDrop}
        />
      )}

      {(step === "file_selected" || step === "unlocking") && (
        <UnlockView
          filePath={filePath}
          onBack={handleBack}
          onSelectFile={handleSelectFile}
          onUnlock={handleUnlock}
          isUnlocking={step === "unlocking"}
          onFileDrop={handleFileDrop}
        />
      )}

      {isVolumeOpen && volumeInfo && (
        <VolumeView
          volumeInfo={volumeInfo}
          fsType={fsType}
          filePath={filePath}
          files={files}
          onExtractAll={handleExtractAll}
          onExtractSelected={handleExtractSelected}
          isExtracting={isExtracting}
          extractProgress={extractProgress}
          isMounted={step === "mounted"}
          isMounting={isMounting}
          isUnmounting={isUnmounting}
          mountProgress={mountProgress}
          mountStage={mountStage}
          driveLetter={driveLetter}
          onMount={handleMount}
          onUnmount={handleUnmount}
          isLocked={isLocked}
        />
      )}

      <Toaster position="bottom-right" />
      <UpdateNotification />

      {/* Lock screen overlay */}
      {isLocked && <LockScreen onUnlock={() => setIsLocked(false)} />}
    </div>
  );
}

export default App;
