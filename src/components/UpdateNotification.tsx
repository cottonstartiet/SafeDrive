import { useAutoUpdater } from '@/hooks/useAutoUpdater'

export function UpdateNotification() {
  // Drives sonner toasts — no rendered UI needed
  useAutoUpdater()
  return null
}
