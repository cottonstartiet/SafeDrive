import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Shield, HardDrive, Hash, Info, Database, Cpu } from "lucide-react";
import type { VolumeInfo } from "@/App";

interface VolumeInfoPanelProps {
  info: VolumeInfo;
  fsType: string;
  filePath: string;
}

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

interface DetailRowProps {
  icon?: React.ReactNode;
  label: string;
  value: string | React.ReactNode;
}

function DetailRow({ icon, label, value }: DetailRowProps) {
  return (
    <div className="flex items-center justify-between py-2.5">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="text-sm font-medium">{value}</div>
    </div>
  );
}

export function VolumeInfoPanel({ info, fsType, filePath }: VolumeInfoPanelProps) {
  const fileName = filePath.split("\\").pop() || filePath;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Info className="h-4 w-4" />
          Volume Details
          {info.is_hidden && (
            <Badge variant="outline" className="text-amber-600 border-amber-300">
              Hidden Volume
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <DetailRow
          icon={<HardDrive className="h-3.5 w-3.5" />}
          label="File"
          value={<span className="truncate max-w-xs" title={filePath}>{fileName}</span>}
        />
        <Separator />
        <DetailRow
          icon={<Shield className="h-3.5 w-3.5" />}
          label="Encryption"
          value={info.encryption}
        />
        <Separator />
        <DetailRow
          icon={<Hash className="h-3.5 w-3.5" />}
          label="Hash Algorithm"
          value={info.hash}
        />
        <Separator />
        <DetailRow
          icon={<Database className="h-3.5 w-3.5" />}
          label="Volume Size"
          value={formatSize(info.volume_size)}
        />
        <Separator />
        <DetailRow
          label="Filesystem"
          value={
            <Badge variant="secondary">{fsType || "Unknown"}</Badge>
          }
        />
        <Separator />
        <DetailRow
          icon={<Cpu className="h-3.5 w-3.5" />}
          label="Header Version"
          value={String(info.header_version)}
        />
        <Separator />
        <DetailRow
          label="Sector Size"
          value={`${info.sector_size} bytes`}
        />
      </CardContent>
    </Card>
  );
}
