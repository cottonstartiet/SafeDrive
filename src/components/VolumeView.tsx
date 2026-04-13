import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { FolderOpen, Info } from "lucide-react";
import { FileBrowser } from "@/components/FileBrowser";
import { VolumeInfoPanel } from "@/components/VolumeInfoPanel";
import { MountPanel } from "@/components/MountPanel";
import type { VolumeInfo, FileEntry } from "@/App";

interface VolumeViewProps {
  volumeInfo: VolumeInfo;
  fsType: string;
  filePath: string;
  files: FileEntry[];
  // Extract
  onExtractAll: () => void;
  onExtractSelected: (paths: string[]) => void;
  isExtracting: boolean;
  extractProgress: number;
  // Mount
  isMounted: boolean;
  isMounting: boolean;
  isUnmounting: boolean;
  mountProgress: number;
  mountStage: string;
  driveLetter: string | null;
  onMount: () => void;
  onUnmount: () => void;
  // Lock
  isLocked: boolean;
}

export function VolumeView({
  volumeInfo,
  fsType,
  filePath,
  files,
  onExtractAll,
  onExtractSelected,
  isExtracting,
  extractProgress,
  isMounted,
  isMounting,
  isUnmounting,
  mountProgress,
  mountStage,
  driveLetter,
  onMount,
  onUnmount,
  isLocked,
}: VolumeViewProps) {
  const fileName = filePath.split("\\").pop() || filePath;
  const fileCount = files.filter((f) => !f.is_dir).length;
  const dirCount = files.filter((f) => f.is_dir).length;

  return (
    <div className="h-[calc(100vh-57px)] flex flex-col">
      <div className="mx-auto max-w-5xl w-full px-6 py-6 flex flex-col gap-5 flex-1 min-h-0">
        {/* Header bar with file name and mount */}
        <div className="flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <div>
              <h2 className="text-lg font-semibold truncate">{fileName}</h2>
              <p className="text-xs text-muted-foreground truncate max-w-lg">
                {filePath}
              </p>
            </div>
            {volumeInfo.is_hidden && (
              <Badge variant="outline" className="shrink-0 text-amber-600 border-amber-300">
                Hidden
              </Badge>
            )}
          </div>
        </div>

        {/* Mount Panel */}
        <div className="shrink-0">
          <MountPanel
            isMounted={isMounted}
            isMounting={isMounting}
            isUnmounting={isUnmounting}
            mountProgress={mountProgress}
            mountStage={mountStage}
            driveLetter={driveLetter}
            onMount={onMount}
            onUnmount={onUnmount}
          />
        </div>

        {/* Tabbed content */}
        <Tabs defaultValue="contents" className="w-full flex-1 min-h-0 flex flex-col">
          <TabsList className="shrink-0">
            <TabsTrigger value="contents" className="gap-1.5">
              <FolderOpen className="h-3.5 w-3.5" />
              Contents
              <Badge variant="secondary" className="ml-1 text-xs px-1.5 py-0">
                {fileCount} files, {dirCount} folders
              </Badge>
            </TabsTrigger>
            <TabsTrigger value="details" className="gap-1.5">
              <Info className="h-3.5 w-3.5" />
              Volume Details
            </TabsTrigger>
          </TabsList>

          <TabsContent value="contents" className="mt-4 flex-1 min-h-0 flex flex-col overflow-hidden">
            <FileBrowser
              files={files}
              onExtractAll={onExtractAll}
              onExtractSelected={onExtractSelected}
              isExtracting={isExtracting}
              progress={extractProgress}
              isLocked={isLocked}
            />
          </TabsContent>

          <TabsContent value="details" className="mt-4">
            <VolumeInfoPanel
              info={volumeInfo}
              fsType={fsType}
              filePath={filePath}
            />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
