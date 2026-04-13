import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { HardDrive, CircleStop, ShieldAlert, Loader2, ShieldCheck } from "lucide-react";

interface MountPanelProps {
  isMounted: boolean;
  isMounting: boolean;
  isUnmounting: boolean;
  mountProgress: number;
  mountStage: string;
  driveLetter: string | null;
  onMount: () => void;
  onUnmount: () => void;
}

function stageLabel(stage: string): string {
  switch (stage) {
    case "creating_vhd":
      return "Creating virtual disk…";
    case "mounting":
      return "Mounting drive…";
    case "detecting":
      return "Detecting drive letter…";
    default:
      return "Preparing…";
  }
}

export function MountPanel({
  isMounted,
  isMounting,
  isUnmounting,
  mountProgress,
  mountStage,
  driveLetter,
  onMount,
  onUnmount,
}: MountPanelProps) {
  return (
    <Card>
      <CardContent className="py-4">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {isMounted ? (
                <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-green-50">
                  <ShieldCheck className="h-5 w-5 text-green-600" />
                </div>
              ) : (
                <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-muted">
                  <HardDrive className="h-5 w-5 text-muted-foreground" />
                </div>
              )}
              <div>
                <p className="text-sm font-medium">Mount as Windows Drive</p>
                {isMounting ? (
                  <p className="text-xs text-blue-600 flex items-center gap-1">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    {stageLabel(mountStage)}
                  </p>
                ) : isUnmounting ? (
                  <p className="text-xs text-amber-600 flex items-center gap-1">
                    <Loader2 className="h-3 w-3 animate-spin" />
                    Unmounting and saving changes…
                  </p>
                ) : isMounted && driveLetter ? (
                  <p className="text-xs text-green-600 font-medium">
                    Mounted as {driveLetter}
                  </p>
                ) : isMounted ? (
                  <p className="text-xs text-amber-600">
                    Mounted (no drive letter assigned)
                  </p>
                ) : (
                  <p className="text-xs text-muted-foreground flex items-center gap-1">
                    <ShieldAlert className="h-3 w-3" />
                    Requires app to run as Administrator
                  </p>
                )}
              </div>
            </div>

            {isMounting || isUnmounting ? (
              <Button size="sm" disabled variant="outline">
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                {isMounting ? "Mounting…" : "Saving…"}
              </Button>
            ) : isMounted ? (
              <Button variant="outline" size="sm" onClick={onUnmount}>
                <CircleStop className="h-3.5 w-3.5 mr-1.5" />
                Unmount & Save
              </Button>
            ) : (
              <Button size="sm" onClick={onMount}>
                <HardDrive className="h-3.5 w-3.5 mr-1.5" />
                Mount Drive
              </Button>
            )}
          </div>

          {isMounting && (
            <div className="space-y-1.5 pl-12">
              <Progress
                value={mountProgress * 100}
                className="h-1.5"
              />
              <p className="text-xs text-muted-foreground text-right">
                {Math.round(mountProgress * 100)}%
              </p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
