import { v } from 'convex/values'
import { zipSync } from 'fflate'
import { internal } from './_generated/api'
import { internalAction } from './_generated/server'

<<<<<<< HEAD
type VTAIResult = {
  category: string
  verdict: string
  analysis?: string
  source?: string
}

type VTFileResponse = {
  data: {
    attributes: {
      sha256: string
      crowdsourced_ai_results?: VTAIResult[]
      last_analysis_stats?: {
        malicious: number
        suspicious: number
        undetected: number
        harmless: number
      }
    }
  }
}

=======
>>>>>>> b952099 (feat(vt): implement VirusTotal scan for skill versions and schedule scan on publish)
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

<<<<<<< HEAD
    // Fetch skill and owner info for _meta.json
    const skill = await ctx.runQuery(internal.skills.getSkillByIdInternal, {
      skillId: version.skillId,
    })
    const owner = skill
      ? await ctx.runQuery(internal.users.getByIdInternal, {
        userId: skill.ownerUserId,
      })
      : null
    const versions = skill
      ? await ctx.runQuery(internal.skills.listVersionsInternal, {
        skillId: skill._id,
      })
      : []

    // Build the ZIP in memory with deterministic settings 
    // Sort files alphabetically by path for consistent order
    const sortedFiles = [...version.files].sort((a, b) => a.path.localeCompare(b.path))

    // Use fixed timestamp (Jan 1, 1980 00:00:00 UTC - valid ZIP date range)
    const fixedDate = new Date('1980-01-01T00:00:00Z')

    type ZipInput = Record<string, Uint8Array | [Uint8Array, { mtime?: Date }]>
    const zipData: ZipInput = {}

    for (const file of sortedFiles) {
      const content = await ctx.storage.get(file.storageId)
      if (content) {
        const buffer = new Uint8Array(await content.arrayBuffer())
        zipData[file.path] = [buffer, { mtime: fixedDate }]
      }
    }

    // Add _meta.json to the ZIP
    if (skill) {
      const metaFile = {
        owner: owner?.handle || owner?.displayName || 'unknown',
        slug: skill.slug,
        displayName: skill.displayName,
        latest: {
          version: version.version,
          publishedAt: version.createdAt,
          commit: null,
        },
        history: versions
          .filter((v) => v.version !== version.version)
          .map((v) => ({
            version: v.version,
            publishedAt: v.createdAt,
            commit: null,
          }))
          .sort((a, b) => b.publishedAt - a.publishedAt),
      }
      const metaContent = new TextEncoder().encode(JSON.stringify(metaFile, null, 2))
      zipData['_meta.json'] = [metaContent, { mtime: fixedDate }]
    }

=======
    // Build the ZIP in memory (replicating downloads.ts logic)
    const zipData: Record<string, Uint8Array> = {}
    for (const file of version.files) {
      const content = await ctx.storage.get(file.storageId)
      if (content) {
        zipData[file.path] = new Uint8Array(await content.arrayBuffer())
      }
    }

>>>>>>> b952099 (feat(vt): implement VirusTotal scan for skill versions and schedule scan on publish)
    if (Object.keys(zipData).length === 0) {
      console.warn(`No files found for version ${args.versionId}, skipping scan`)
      return
    }

<<<<<<< HEAD
    // Use fixed compression level (same as downloads.ts)
    const zipped = zipSync(zipData, { level: 6 })
    const zipArray = Uint8Array.from(zipped)

    // Calculate SHA-256 of the ZIP (this hash includes _meta.json)
    const hashBuffer = await crypto.subtle.digest('SHA-256', zipArray)
    const sha256hash = Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')

    // Update version with hash and initial scan status
    await ctx.runMutation(internal.skills.updateVersionScanResultsInternal, {
      versionId: args.versionId,
      sha256hash,
      scanResults: { vt: { status: 'pending' } },
    })

    // Check if file already exists in VT and has AI analysis
    try {
      const existingFile = await checkExistingFile(apiKey, sha256hash)

      if (existingFile) {
        const aiResult = existingFile.data.attributes.crowdsourced_ai_results?.find(
          (r) => r.category === 'code_insight'
        )

        if (aiResult) {
          // File exists and has AI analysis - use the verdict
          const verdict = aiResult.verdict.toLowerCase()
          const status = verdict === 'malicious' ? 'malicious' : 'clean'

          console.log(
            `Version ${args.versionId} found in VT with AI analysis. Hash: ${sha256hash}. Verdict: ${verdict}`
          )

          await ctx.runMutation(internal.skills.updateVersionScanResultsInternal, {
            versionId: args.versionId,
            scanResults: {
              vt: {
                status,
                url: `https://www.virustotal.com/gui/file/${sha256hash}`,
                metadata: {
                  source: 'cached',
                  aiVerdict: verdict,
                  aiAnalysis: aiResult.analysis,
                  aiSource: aiResult.source,
                },
              },
            },
          })
          return
        }

        // File exists but no AI analysis - need to upload for fresh scan
        console.log(
          `Version ${args.versionId} found in VT but no AI analysis. Hash: ${sha256hash}. Uploading...`
        )
      } else {
        console.log(
          `Version ${args.versionId} not found in VT. Hash: ${sha256hash}. Uploading...`
        )
      }
    } catch (error) {
      console.error('Error checking existing file in VT:', error)
      // Continue to upload even if check fails
    }

    // Upload file to VirusTotal (v3 API)
    const formData = new FormData()
=======
    const zipped = zipSync(zipData)

    // Send to VirusTotal (v3 API)
    const formData = new FormData()
    // Convert to standard Uint8Array (same approach as downloads.ts)
    const zipArray = Uint8Array.from(zipped)
>>>>>>> b952099 (feat(vt): implement VirusTotal scan for skill versions and schedule scan on publish)
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
<<<<<<< HEAD
        console.error('VirusTotal upload error:', error)
        await ctx.runMutation(internal.skills.updateVersionScanResultsInternal, {
          versionId: args.versionId,
          scanResults: {
            vt: {
              status: 'error',
              url: `https://www.virustotal.com/gui/file/${sha256hash}`,
            },
          },
        })
=======
        console.error('VirusTotal API error:', error)
>>>>>>> b952099 (feat(vt): implement VirusTotal scan for skill versions and schedule scan on publish)
        return
      }

      const result = (await response.json()) as { data: { id: string } }
<<<<<<< HEAD
      console.log(
        `Successfully uploaded version ${args.versionId} to VT. Hash: ${sha256hash}. Analysis ID: ${result.data.id}`
      )

      // Update with pending status and URL (webhook will update final status)
      await ctx.runMutation(internal.skills.updateVersionScanResultsInternal, {
        versionId: args.versionId,
        scanResults: {
          vt: {
            status: 'pending',
            url: `https://www.virustotal.com/gui/file/${sha256hash}`,
            metadata: {
              analysisId: result.data.id,
            },
          },
        },
      })
    } catch (error) {
      console.error('Failed to upload to VirusTotal:', error)
      await ctx.runMutation(internal.skills.updateVersionScanResultsInternal, {
        versionId: args.versionId,
        scanResults: {
          vt: {
            status: 'failed',
            url: `https://www.virustotal.com/gui/file/${sha256hash}`,
          },
        },
      })
    }
  },
})

/**
 * Check if a file already exists in VirusTotal by hash
 */
async function checkExistingFile(
  apiKey: string,
  sha256hash: string
): Promise<VTFileResponse | null> {
  const response = await fetch(
    `https://www.virustotal.com/api/v3/files/${sha256hash}`,
    {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
      },
    }
  )

  if (response.status === 404) {
    // File not found in VT
    return null
  }

  if (!response.ok) {
    const error = await response.text()
    throw new Error(`VT API error: ${response.status} - ${error}`)
  }

  return (await response.json()) as VTFileResponse
}
=======
      console.log(`Successfully sent version ${args.versionId} to VT. Analysis ID: ${result.data.id}`)
    } catch (error) {
      console.error('Failed to send to VirusTotal:', error)
    }
  },
})
>>>>>>> b952099 (feat(vt): implement VirusTotal scan for skill versions and schedule scan on publish)
