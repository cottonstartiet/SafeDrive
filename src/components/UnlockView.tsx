import { useState, useCallback, useRef } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Shield, ArrowLeft, Upload, Lock } from "lucide-react";

interface UnlockViewProps {
  filePath: string;
  onBack: () => void;
  onSelectFile: () => void;
  onUnlock: (password: string) => void;
  isUnlocking: boolean;
  onFileDrop: (path: string) => void;
}

export function UnlockView({
  filePath,
  onBack,
  onSelectFile,
  onUnlock,
  isUnlocking,
  onFileDrop,
}: UnlockViewProps) {
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
        const file = files[0];
        if (file.name) {
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
      if (password) {
        onUnlock(password);
      }
    },
    [onUnlock, password]
  );

  const fileName = filePath.split("\\").pop() || filePath;

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
      <div className="mx-auto max-w-md px-6 py-16">
        <Button
          variant="ghost"
          size="sm"
          onClick={onBack}
          className="mb-8 -ml-2 text-muted-foreground"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back
        </Button>

        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10 mb-4">
            <Lock className="h-7 w-7 text-primary" />
          </div>
          <h2 className="text-xl font-bold tracking-tight">Unlock Volume</h2>
          <p className="text-muted-foreground mt-1 text-sm">
            Enter your password to decrypt
          </p>
        </div>

        {/* File info */}
        <Card className="mb-4">
          <CardContent className="py-3">
            <div className="flex items-center gap-3">
              <Shield className="h-5 w-5 text-muted-foreground shrink-0" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium truncate">{fileName}</p>
                <p className="text-xs text-muted-foreground truncate">
                  {filePath}
                </p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="shrink-0 text-xs"
                onClick={onSelectFile}
              >
                Change
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Password form */}
        <Card>
          <CardContent className="py-5">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
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
                  disabled={isUnlocking}
                />
              </div>
              <Button
                type="submit"
                className="w-full"
                disabled={!password || isUnlocking}
              >
                {isUnlocking ? (
                  <>
                    <div className="animate-spin h-4 w-4 border-2 border-primary-foreground border-t-transparent rounded-full mr-2" />
                    Decrypting…
                  </>
                ) : (
                  "Unlock"
                )}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Drop hint */}
        <div
          className={`mt-6 rounded-lg border-2 border-dashed py-3 text-center transition-colors ${
            isDragOver
              ? "border-primary bg-primary/5"
              : "border-border/50"
          }`}
        >
          <p className="text-xs text-muted-foreground flex items-center justify-center gap-1.5">
            <Upload className="h-3 w-3" />
            Drop a different volume file to switch
          </p>
        </div>
      </div>
    </div>
  );
}
