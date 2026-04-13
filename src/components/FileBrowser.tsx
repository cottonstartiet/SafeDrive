import { useState, useMemo, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  FolderOpen, File, Download, CheckSquare, Square, Eye,
  Image, FileText, Film, Music, Archive, ListFilter,
  ChevronRight, HardDrive,
} from "lucide-react";
import { ImagePreviewModal } from "@/components/ImagePreviewModal";
import type { FileEntry } from "@/App";

const IMAGE_EXTENSIONS = new Set([
  "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "ico", "tiff", "tif",
]);

const DOC_EXTENSIONS = new Set([
  "pdf", "doc", "docx", "txt", "rtf", "odt", "xls", "xlsx", "csv", "ppt", "pptx", "md",
]);

const VIDEO_EXTENSIONS = new Set([
  "mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "m4v",
]);

const AUDIO_EXTENSIONS = new Set([
  "mp3", "wav", "flac", "aac", "ogg", "wma", "m4a",
]);

const ARCHIVE_EXTENSIONS = new Set([
  "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab",
]);

function getExt(name: string): string {
  return name.split(".").pop()?.toLowerCase() ?? "";
}

type FilterKey = "all" | "folders" | "images" | "documents" | "videos" | "audio" | "archives";

const FILE_FILTERS: { key: FilterKey; label: string; icon: React.ReactNode; match: (f: FileEntry) => boolean }[] = [
  { key: "all",       label: "All",       icon: <ListFilter className="h-3.5 w-3.5" />, match: () => true },
  { key: "folders",   label: "Folders",   icon: <FolderOpen className="h-3.5 w-3.5" />, match: (f) => f.is_dir },
  { key: "images",    label: "Images",    icon: <Image className="h-3.5 w-3.5" />,      match: (f) => !f.is_dir && IMAGE_EXTENSIONS.has(getExt(f.name)) },
  { key: "documents", label: "Docs",      icon: <FileText className="h-3.5 w-3.5" />,   match: (f) => !f.is_dir && DOC_EXTENSIONS.has(getExt(f.name)) },
  { key: "videos",    label: "Videos",    icon: <Film className="h-3.5 w-3.5" />,        match: (f) => !f.is_dir && VIDEO_EXTENSIONS.has(getExt(f.name)) },
  { key: "audio",     label: "Audio",     icon: <Music className="h-3.5 w-3.5" />,       match: (f) => !f.is_dir && AUDIO_EXTENSIONS.has(getExt(f.name)) },
  { key: "archives",  label: "Archives",  icon: <Archive className="h-3.5 w-3.5" />,     match: (f) => !f.is_dir && ARCHIVE_EXTENSIONS.has(getExt(f.name)) },
];

function isImageFile(name: string): boolean {
  const ext = name.split(".").pop()?.toLowerCase() ?? "";
  return IMAGE_EXTENSIONS.has(ext);
}

function getParentPath(filePath: string): string {
  const lastSep = filePath.lastIndexOf("\\");
  if (lastSep <= 0) return "\\";
  return filePath.substring(0, lastSep);
}

interface BreadcrumbSegment {
  label: string;
  path: string;
}

function buildBreadcrumbs(currentPath: string): BreadcrumbSegment[] {
  const segments: BreadcrumbSegment[] = [{ label: "Root", path: "\\" }];
  if (currentPath === "\\") return segments;
  const parts = currentPath.substring(1).split("\\");
  let accumulated = "";
  for (const part of parts) {
    accumulated += "\\" + part;
    segments.push({ label: part, path: accumulated });
  }
  return segments;
}

interface FileBrowserProps {
  files: FileEntry[];
  onExtractAll: () => void;
  onExtractSelected: (paths: string[]) => void;
  isExtracting: boolean;
  progress: number;
  isLocked: boolean;
}

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024)
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024)
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function FileBrowser({
  files,
  onExtractAll,
  onExtractSelected,
  isExtracting,
  progress,
  isLocked,
}: FileBrowserProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [previewIndex, setPreviewIndex] = useState<number>(-1);
  const [activeFilter, setActiveFilter] = useState<FilterKey>("all");
  const [currentPath, setCurrentPath] = useState<string>("\\");

  // Close image preview when screen locks
  useEffect(() => {
    if (isLocked) setPreviewIndex(-1);
  }, [isLocked]);

  const sortedFiles = useMemo(() => {
    return [...files].sort((a, b) => {
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  }, [files]);

  // Direct children of the current directory
  const directChildren = useMemo(() => {
    return sortedFiles.filter((f) => getParentPath(f.path) === currentPath);
  }, [sortedFiles, currentPath]);

  // Filter counts scoped to direct children
  const filterCounts = useMemo(() => {
    const counts: Record<FilterKey, number> = { all: 0, folders: 0, images: 0, documents: 0, videos: 0, audio: 0, archives: 0 };
    for (const f of directChildren) {
      counts.all++;
      for (const filter of FILE_FILTERS) {
        if (filter.key !== "all" && filter.match(f)) counts[filter.key]++;
      }
    }
    return counts;
  }, [directChildren]);

  // Apply active filter to direct children
  const filteredFiles = useMemo(() => {
    const filter = FILE_FILTERS.find((f) => f.key === activeFilter);
    if (!filter || filter.key === "all") return directChildren;
    return directChildren.filter(filter.match);
  }, [directChildren, activeFilter]);

  // Image files in current directory for preview navigation
  const imageFiles = useMemo(() => {
    return directChildren
      .filter((f) => !f.is_dir && isImageFile(f.name))
      .map((f) => ({ path: f.path, name: f.name }));
  }, [directChildren]);

  // Count of items inside each subfolder (for display)
  const folderItemCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const f of files) {
      const parent = getParentPath(f.path);
      counts.set(parent, (counts.get(parent) || 0) + 1);
    }
    return counts;
  }, [files]);

  const breadcrumbs = useMemo(() => buildBreadcrumbs(currentPath), [currentPath]);

  const fileCount = directChildren.filter((f) => !f.is_dir).length;

  const toggleSelect = (path: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  const selectAll = () => {
    const filePaths = directChildren.filter((f) => !f.is_dir).map((f) => f.path);
    setSelected(new Set(filePaths));
  };

  const selectNone = () => setSelected(new Set());

  const handleExtractSelected = () => {
    onExtractSelected(Array.from(selected));
  };

  const navigateToFolder = (path: string) => {
    setCurrentPath(path);
    setActiveFilter("all");
  };

  const openPreview = (filePath: string) => {
    const idx = imageFiles.findIndex((f) => f.path === filePath);
    if (idx >= 0) setPreviewIndex(idx);
  };

  return (
    <>
    <Card className="flex-1 min-h-0 flex flex-col overflow-hidden">
      <CardHeader className="pb-3 shrink-0">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <FolderOpen className="h-4 w-4" />
            Volume Contents
          </CardTitle>
          <div className="flex gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={selected.size > 0 ? selectNone : selectAll}
            >
              {selected.size > 0 ? "Deselect All" : "Select All"}
            </Button>
            {selected.size > 0 && (
              <Button
                size="sm"
                variant="outline"
                onClick={handleExtractSelected}
                disabled={isExtracting}
              >
                <Download className="h-3.5 w-3.5 mr-1" />
                Extract Selected ({selected.size})
              </Button>
            )}
            <Button
              size="sm"
              onClick={onExtractAll}
              disabled={isExtracting || fileCount === 0}
            >
              <Download className="h-3.5 w-3.5 mr-1" />
              Extract All
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-0 flex-1 min-h-0 flex flex-col overflow-hidden">
        {/* Filter pills */}
        <div className="flex flex-wrap gap-1.5 mb-3 shrink-0">
          {FILE_FILTERS.map((filter) => {
            const count = filterCounts[filter.key];
            const isActive = activeFilter === filter.key;
            if (filter.key !== "all" && count === 0) return null;
            return (
              <button
                key={filter.key}
                onClick={() => setActiveFilter(isActive && filter.key !== "all" ? "all" : filter.key)}
                className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors border ${
                  isActive
                    ? "bg-primary text-primary-foreground border-primary shadow-sm"
                    : "bg-muted/50 text-muted-foreground border-transparent hover:bg-muted hover:text-foreground"
                }`}
              >
                {filter.icon}
                {filter.label}
                <span className={`ml-0.5 tabular-nums ${isActive ? "text-primary-foreground/70" : "text-muted-foreground/60"}`}>
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Breadcrumb navigation */}
        <nav className="flex items-center gap-1 mb-3 shrink-0 text-sm min-h-[28px]">
          {breadcrumbs.map((seg, i) => {
            const isLast = i === breadcrumbs.length - 1;
            return (
              <span key={seg.path} className="flex items-center gap-1">
                {i > 0 && <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/50 shrink-0" />}
                {isLast ? (
                  <span className="flex items-center gap-1.5 font-medium text-foreground">
                    {i === 0 && <HardDrive className="h-3.5 w-3.5" />}
                    {seg.label}
                  </span>
                ) : (
                  <button
                    onClick={() => navigateToFolder(seg.path)}
                    className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {i === 0 && <HardDrive className="h-3.5 w-3.5" />}
                    {seg.label}
                  </button>
                )}
              </span>
            );
          })}
        </nav>

        {isExtracting && (
          <div className="mb-3 space-y-1">
            <Progress value={progress * 100} className="h-2" />
            <p className="text-xs text-muted-foreground">
              Extracting… {Math.round(progress * 100)}%
            </p>
          </div>
        )}

        {files.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            No files found in volume, or filesystem not supported.
          </p>
        ) : filteredFiles.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <p className="text-sm text-muted-foreground">
              No matching files for this filter.
            </p>
          </div>
        ) : (
          <ScrollArea className="flex-1 min-h-0 rounded-md border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8"></TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead className="w-24 text-right">Size</TableHead>
                  <TableHead className="w-32 text-right">Info</TableHead>
                  <TableHead className="w-10"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredFiles.map((file) => (
                  <TableRow
                    key={file.path}
                    className={file.is_dir ? "cursor-pointer hover:bg-muted/50" : "cursor-pointer"}
                    onClick={() => {
                      if (file.is_dir) {
                        navigateToFolder(file.path);
                      } else {
                        toggleSelect(file.path);
                      }
                    }}
                  >
                    <TableCell className="py-1.5">
                      {!file.is_dir &&
                        (selected.has(file.path) ? (
                          <CheckSquare className="h-4 w-4 text-primary" />
                        ) : (
                          <Square className="h-4 w-4 text-muted-foreground" />
                        ))}
                    </TableCell>
                    <TableCell className="py-1.5">
                      <div className="flex items-center gap-2">
                        {file.is_dir ? (
                          <FolderOpen className="h-4 w-4 text-amber-500 shrink-0" />
                        ) : (
                          <File className="h-4 w-4 text-muted-foreground shrink-0" />
                        )}
                        <span className="truncate">{file.name}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-1.5 text-right text-muted-foreground">
                      {file.is_dir ? "—" : formatSize(file.size)}
                    </TableCell>
                    <TableCell className="py-1.5 text-right text-muted-foreground text-xs">
                      {file.is_dir
                        ? `${folderItemCounts.get(file.path) || 0} items`
                        : getExt(file.name).toUpperCase()
                      }
                    </TableCell>
                    <TableCell className="py-1.5">
                      {!file.is_dir && isImageFile(file.name) && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 w-6 p-0"
                          title="Preview image"
                          onClick={(e) => {
                            e.stopPropagation();
                            openPreview(file.path);
                          }}
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </ScrollArea>
        )}
      </CardContent>
    </Card>

    <ImagePreviewModal
      open={previewIndex >= 0}
      onOpenChange={(open) => { if (!open) setPreviewIndex(-1); }}
      imageFiles={imageFiles}
      currentIndex={previewIndex >= 0 ? previewIndex : 0}
      onNavigate={setPreviewIndex}
    />
    </>
  );
}
