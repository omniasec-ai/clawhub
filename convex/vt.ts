import { v } from 'convex/values'
import { zipSync } from 'fflate'
import { internal } from './_generated/api'
import { internalAction } from './_generated/server'

export const scanWithVirusTotal = internalAction({
  args: {
    versionId: v.id('skillVersions'),
  },
  handler: async (ctx, args) => {
    const apiKey = process.env.VT_API_KEY
    if (!apiKey) {
      console.log('VT_API_KEY not configured, skipping scan')
      return
    }

    // Get the version details and files
    const version = await ctx.runQuery(internal.skills.getVersionByIdInternal, {
      versionId: args.versionId,
    })

    if (!version) {
      console.error(`Version ${args.versionId} not found for scanning`)
      return
    }

    // Build the ZIP in memory (replicating downloads.ts logic)
    const zipData: Record<string, Uint8Array> = {}
    for (const file of version.files) {
      const content = await ctx.storage.get(file.storageId)
      if (content) {
        zipData[file.path] = new Uint8Array(await content.arrayBuffer())
      }
    }

    if (Object.keys(zipData).length === 0) {
      console.warn(`No files found for version ${args.versionId}, skipping scan`)
      return
    }

    const zipped = zipSync(zipData)

    // Send to VirusTotal (v3 API)
    const formData = new FormData()
    // Convert to standard Uint8Array (same approach as downloads.ts)
    const zipArray = Uint8Array.from(zipped)
    const blob = new Blob([zipArray], { type: 'application/zip' })
    formData.append('file', blob, 'skill.zip')

    try {
      const response = await fetch('https://www.virustotal.com/api/v3/files', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
        },
        body: formData,
      })

      if (!response.ok) {
        const error = await response.text()
        console.error('VirusTotal API error:', error)
        return
      }

      const result = (await response.json()) as { data: { id: string } }
      console.log(`Successfully sent version ${args.versionId} to VT. Analysis ID: ${result.data.id}`)
    } catch (error) {
      console.error('Failed to send to VirusTotal:', error)
    }
  },
})
