import { useCallback, useRef, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  FolderOpen,
  Plus,
  Clock,
  Shield,
  ChevronRight,
  Trash2,
} from "lucide-react";

export interface RecentDrive {
  path: string;
  name: string;
  lastOpened: string;
}

interface LandingProps {
  recentDrives: RecentDrive[];
  onOpenDrive: () => void;
  onOpenRecent: (path: string) => void;
  onRemoveRecent: (path: string) => void;
  onFileDrop: (path: string) => void;
}

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

export function Landing({
  recentDrives,
  onOpenDrive,
  onOpenRecent,
  onRemoveRecent,
  onFileDrop,
}: LandingProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const dropRef = useRef<HTMLDivElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragOver(false);
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        const file = files[0];
        if (file.name) {
          const path = (file as any).path || file.name;
          onFileDrop(path);
        }
      }
    },
    [onFileDrop]
  );

  return (
    <div
      ref={dropRef}
      className={`min-h-[calc(100vh-57px)] transition-colors ${
        isDragOver ? "bg-primary/5" : ""
      }`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <div className="mx-auto max-w-2xl px-6 py-12">
        {/* Hero */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10 mb-4">
            <Shield className="h-7 w-7 text-primary" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight">
            Welcome to SafeDrive
          </h2>
          <p className="text-muted-foreground mt-2 text-sm">
            Securely access and manage your encrypted TrueCrypt volumes
          </p>
        </div>

        {/* Actions */}
        <div className="grid grid-cols-2 gap-4 mb-8">
          <Card
            className="cursor-pointer hover:border-primary/50 hover:shadow-sm transition-all group"
            onClick={onOpenDrive}
          >
            <CardContent className="py-8 text-center">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-primary/10 mb-3 group-hover:bg-primary/15 transition-colors">
                <FolderOpen className="h-6 w-6 text-primary" />
              </div>
              <p className="font-semibold text-sm">Open Drive</p>
              <p className="text-xs text-muted-foreground mt-1">
                Browse for a .tc or .hc file
              </p>
            </CardContent>
          </Card>

          <Card className="opacity-50 cursor-not-allowed">
            <CardContent className="py-8 text-center">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-muted mb-3">
                <Plus className="h-6 w-6 text-muted-foreground" />
              </div>
              <p className="font-semibold text-sm">Create Drive</p>
              <p className="text-xs text-muted-foreground mt-1">
                Coming soon
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Drop zone hint */}
        <div
          className={`rounded-lg border-2 border-dashed py-4 text-center mb-8 transition-colors ${
            isDragOver
              ? "border-primary bg-primary/5"
              : "border-border/50 text-muted-foreground"
          }`}
        >
          <p className="text-xs">
            {isDragOver
              ? "Drop to open volume"
              : "Or drag & drop a volume file anywhere"}
          </p>
        </div>

        {/* Recent drives */}
        {recentDrives.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Clock className="h-4 w-4 text-muted-foreground" />
              <h3 className="text-sm font-medium">Recent</h3>
            </div>
            <Separator className="mb-2" />
            <div className="space-y-1">
              {recentDrives.map((drive) => (
                <div
                  key={drive.path}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-accent cursor-pointer group transition-colors"
                  onClick={() => onOpenRecent(drive.path)}
                >
                  <Shield className="h-4 w-4 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      {drive.name}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      {drive.path}
                    </p>
                  </div>
                  <span className="text-xs text-muted-foreground shrink-0">
                    {formatRelativeTime(drive.lastOpened)}
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0 opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                    onClick={(e) => {
                      e.stopPropagation();
                      onRemoveRecent(drive.path);
                    }}
                  >
                    <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                  </Button>
                  <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
