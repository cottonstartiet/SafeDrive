import { useState, useCallback, useEffect, useRef } from 'react'
import { check } from '@tauri-apps/plugin-updater'
import { relaunch } from '@tauri-apps/plugin-process'
import { toast } from 'sonner'

export type UpdateStatus = 'idle' | 'checking' | 'downloading' | 'ready' | 'error'

export function useAutoUpdater() {
  const [status, setStatus] = useState<UpdateStatus>('idle')
  const hasChecked = useRef(false)

  const checkForUpdates = useCallback(async () => {
    setStatus('checking')
    try {
      const update = await check()
      if (!update) {
        setStatus('idle')
        return
      }

      setStatus('downloading')

      const toastId = toast.loading(
        `Downloading update v${update.version}…`,
        { duration: Infinity }
      )

      let downloaded = 0
      let total = 0

      await update.downloadAndInstall((event) => {
        if (event.event === 'Started' && event.data.contentLength) {
          total = event.data.contentLength
        } else if (event.event === 'Progress') {
          downloaded += event.data.chunkLength
          if (total > 0) {
            const percent = Math.round((downloaded / total) * 100)
            toast.loading(`Downloading update v${update.version}… ${percent}%`, {
              id: toastId,
              duration: Infinity,
            })
          }
        } else if (event.event === 'Finished') {
          toast.dismiss(toastId)
        }
      })

      setStatus('ready')

      toast.success(`Update v${update.version} ready`, {
        description: 'Restart to apply the update.',
        duration: Infinity,
        action: {
          label: 'Restart Now',
          onClick: () => relaunch(),
        },
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      const isNetworkError =
        message.includes('fetch') ||
        message.includes('network') ||
        message.includes('Could not fetch') ||
        message.includes('connect') ||
        message.includes('timeout') ||
        message.includes('404')

      if (isNetworkError) {
        setStatus('idle')
      } else {
        setStatus('error')
        toast.error('Update failed', { description: message })
      }
    }
  }, [])

  useEffect(() => {
    // Guard against StrictMode double-mount in dev
    if (hasChecked.current) return
    hasChecked.current = true
    checkForUpdates()
  }, [checkForUpdates])

  return { status, checkForUpdates }
}
