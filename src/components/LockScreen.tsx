import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Shield, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface LockScreenProps {
  onUnlock: () => void;
}

export function LockScreen({ onUnlock }: LockScreenProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState(false);
  const [checking, setChecking] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    // Focus password input when lock screen appears
    const timer = setTimeout(() => inputRef.current?.focus(), 100);
    return () => clearTimeout(timer);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password || checking) return;

    setChecking(true);
    setError(false);

    try {
      const valid = await invoke<boolean>("verify_lock_password", { password });
      if (valid) {
        onUnlock();
      } else {
        setError(true);
        setPassword("");
        inputRef.current?.focus();
      }
    } catch {
      setError(true);
      setPassword("");
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-background">
      <div className="flex flex-col items-center gap-6 w-full max-w-xs px-4">
        {/* Branding */}
        <div className="flex flex-col items-center gap-3">
          <div className="h-16 w-16 rounded-2xl bg-primary/10 flex items-center justify-center">
            <Shield className="h-8 w-8 text-primary" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight">SafeDrive</h1>
        </div>

        {/* Lock message */}
        <div className="flex items-center gap-2 text-muted-foreground">
          <Lock className="h-4 w-4" />
          <span className="text-sm">Session locked</span>
        </div>

        {/* Password form */}
        <form onSubmit={handleSubmit} className="w-full space-y-3">
          <Input
            ref={inputRef}
            type="password"
            placeholder="Enter volume password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setError(false);
            }}
            className={error ? "border-destructive animate-shake" : ""}
            disabled={checking}
          />
          {error && (
            <p className="text-xs text-destructive text-center">
              Incorrect password
            </p>
          )}
          <Button type="submit" className="w-full" disabled={!password || checking}>
            {checking ? "Verifying…" : "Unlock"}
          </Button>
        </form>
      </div>
    </div>
  );
}
