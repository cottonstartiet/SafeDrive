import { useState, useCallback, useRef } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { HardDrive, Upload } from "lucide-react";

interface HomeProps {
  filePath: string;
  onSelectFile: () => void;
  onFileDrop: (path: string) => void;
  onUnlock?: (password: string) => void;
}

export function Home({ filePath, onSelectFile, onFileDrop, onUnlock }: HomeProps) {
  const [password, setPassword] = useState("");
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
        // Tauri file drop gives the path via webview file protocol
        const file = files[0];
        if (file.name) {
          // Use the file path from dataTransfer
          const path = (file as any).path || file.name;
          onFileDrop(path);
        }
      }
    },
    [onFileDrop]
  );

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (onUnlock && password) {
        onUnlock(password);
      }
    },
    [onUnlock, password]
  );

  return (
    <div className="space-y-4">
      {/* Drop zone */}
      <Card
        ref={dropRef}
        className={`cursor-pointer transition-colors ${
          isDragOver
            ? "border-primary border-dashed bg-primary/5"
            : "border-dashed hover:border-primary/50"
        }`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={!filePath ? onSelectFile : undefined}
      >
        <CardContent className="py-12 text-center">
          {!filePath ? (
            <div className="space-y-3">
              <Upload className="h-10 w-10 mx-auto text-muted-foreground" />
              <div>
                <p className="text-foreground font-medium">
                  Drop a TrueCrypt volume here
                </p>
                <p className="text-sm text-muted-foreground mt-1">
                  or click to browse for a <code>.tc</code> file
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-1">
              <HardDrive className="h-8 w-8 mx-auto text-primary" />
              <p className="text-foreground font-medium text-sm truncate max-w-md mx-auto">
                {filePath.split("\\").pop() || filePath}
              </p>
              <p className="text-xs text-muted-foreground truncate max-w-lg mx-auto">
                {filePath}
              </p>
              <Button
                variant="ghost"
                size="sm"
                className="mt-2"
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectFile();
                }}
              >
                Change file
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Password form */}
      {filePath && onUnlock && (
        <Card>
          <CardContent className="py-4">
            <form onSubmit={handleSubmit} className="flex gap-3 items-end">
              <div className="flex-1 space-y-1.5">
                <label
                  htmlFor="password"
                  className="text-sm font-medium text-foreground"
                >
                  Password
                </label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter volume password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoFocus
                />
              </div>
              <Button type="submit" disabled={!password}>
                Unlock
              </Button>
            </form>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
