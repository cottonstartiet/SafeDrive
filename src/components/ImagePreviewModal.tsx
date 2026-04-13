import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ImageIcon, ChevronLeft, ChevronRight } from "lucide-react";

interface ImagePreviewModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** All image file entries for navigation */
  imageFiles: { path: string; name: string }[];
  /** Index of the currently selected image */
  currentIndex: number;
  onNavigate: (index: number) => void;
}

interface ImagePreviewResult {
  data: string;
  mime_type: string;
}

export function ImagePreviewModal({
  open,
  onOpenChange,
  imageFiles,
  currentIndex,
  onNavigate,
}: ImagePreviewModalProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [imageSrc, setImageSrc] = useState<string | null>(null);

  const current = imageFiles[currentIndex];
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex < imageFiles.length - 1;

  const goNext = useCallback(() => {
    if (hasNext) onNavigate(currentIndex + 1);
  }, [hasNext, currentIndex, onNavigate]);

  const goPrev = useCallback(() => {
    if (hasPrev) onNavigate(currentIndex - 1);
  }, [hasPrev, currentIndex, onNavigate]);

  // Keyboard navigation
  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "ArrowRight") {
        e.preventDefault();
        goNext();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        goPrev();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, goNext, goPrev]);

  // Load image when current changes
  useEffect(() => {
    if (!open || !current) {
      setImageSrc(null);
      setError(null);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);
    setImageSrc(null);

    invoke<ImagePreviewResult>("preview_image", {
      volumePath: current.path,
    })
      .then((result) => {
        if (!cancelled) {
          setImageSrc(`data:${result.mime_type};base64,${result.data}`);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setError(String(e));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, current]);

  if (!current) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[calc(100%-1rem)] sm:max-w-[calc(100vw-1rem)] max-h-[calc(100vh-1rem)] w-full h-[calc(100vh-1rem)] flex flex-col p-3 gap-2">
        <DialogHeader className="shrink-0">
          <DialogTitle className="flex items-center gap-2 text-sm pr-6">
            <ImageIcon className="h-4 w-4 shrink-0" />
            <span className="truncate">{current.name}</span>
            {imageFiles.length > 1 && (
              <span className="text-muted-foreground font-normal shrink-0">
                ({currentIndex + 1}/{imageFiles.length})
              </span>
            )}
          </DialogTitle>
        </DialogHeader>

        <div className="relative flex-1 min-h-0 flex items-center justify-center">
          {/* Previous button */}
          {hasPrev && (
            <Button
              variant="outline"
              size="sm"
              className="absolute left-2 z-10 h-8 w-8 p-0 rounded-full shadow-sm"
              onClick={goPrev}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
          )}

          {/* Image area */}
          {loading && (
            <div className="text-center space-y-3">
              <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full mx-auto" />
              <p className="text-sm text-muted-foreground">
                Loading preview…
              </p>
            </div>
          )}

          {error && !loading && (
            <div className="text-center space-y-2 px-4">
              <ImageIcon className="h-10 w-10 mx-auto text-muted-foreground" />
              <p className="text-sm text-destructive">
                Failed to load preview
              </p>
              <p className="text-xs text-muted-foreground">{error}</p>
            </div>
          )}

          {imageSrc && !loading && (
            <img
              src={imageSrc}
              alt={current.name}
              className="max-w-full max-h-full object-contain rounded"
            />
          )}

          {/* Next button */}
          {hasNext && (
            <Button
              variant="outline"
              size="sm"
              className="absolute right-2 z-10 h-8 w-8 p-0 rounded-full shadow-sm"
              onClick={goNext}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
