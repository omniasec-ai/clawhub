import { v } from 'convex/values'
import { zipSync } from 'fflate'
import { api } from './_generated/api'
import { httpAction, mutation } from './_generated/server'
import { insertStatEvent } from './skillStatEvents'

export const downloadZip = httpAction(async (ctx, request) => {
  const url = new URL(request.url)
  const slug = url.searchParams.get('slug')?.trim().toLowerCase()
  const versionParam = url.searchParams.get('version')?.trim()
  const tagParam = url.searchParams.get('tag')?.trim()

  if (!slug) {
    return new Response('Missing slug', { status: 400 })
  }

  const skillResult = await ctx.runQuery(api.skills.getBySlug, { slug })
  if (!skillResult?.skill) {
    return new Response('Skill not found', { status: 404 })
  }

  const skill = skillResult.skill
  let version = skillResult.latestVersion

  if (versionParam) {
    version = await ctx.runQuery(api.skills.getVersionBySkillAndVersion, {
      skillId: skill._id,
      version: versionParam,
    })
  } else if (tagParam) {
    const versionId = skill.tags[tagParam]
    if (versionId) {
      version = await ctx.runQuery(api.skills.getVersionById, { versionId })
    }
  }

  if (!version) {
    return new Response('Version not found', { status: 404 })
  }
  if (version.softDeletedAt) {
    return new Response('Version not available', { status: 410 })
  }

  const sortedFiles = [...version.files].sort((a, b) => a.path.localeCompare(b.path))
  const fixedDate = new Date('1980-01-01T00:00:00Z')

  type ZipInput = Record<string, Uint8Array | [Uint8Array, { mtime?: Date }]>
  const zipData: ZipInput = {}

  for (const file of sortedFiles) {
    const blob = await ctx.storage.get(file.storageId)
    if (!blob) continue
    const buffer = new Uint8Array(await blob.arrayBuffer())
    zipData[file.path] = [buffer, { mtime: fixedDate }]
  }

  // Add _meta.json to the ZIP to match the hash in VirusTotal
  const owner = await ctx.runQuery(api.users.getById, { userId: skill.ownerUserId })
  const versions = await ctx.runQuery(api.skills.listVersions, { skillId: skill._id })

  const getCommit = () => 'https://github.com/clawdbot/skills'

  const metaFile = {
    owner: owner?.handle || owner?.displayName || 'unknown',
    slug: skill.slug,
    displayName: skill.displayName,
    latest: {
      version: version.version,
      publishedAt: version.createdAt,
      commit: getCommit(),
    },
    history: versions
      .filter((v: { version: string }) => v.version !== version.version)
      .map((v: any) => ({
        version: v.version,
        publishedAt: v.createdAt,
        commit: getCommit(),
      }))
      .sort(
        (a: { publishedAt: number }, b: { publishedAt: number }) => b.publishedAt - a.publishedAt,
      ),
  }
  const metaContent = new TextEncoder().encode(JSON.stringify(metaFile, null, 2))
  zipData['_meta.json'] = [metaContent, { mtime: fixedDate }]

  const zipped = zipSync(zipData, { level: 6 })
  const zipArray = Uint8Array.from(zipped)
  const zipBlob = new Blob([zipArray], { type: 'application/zip' })

  await ctx.runMutation(api.downloads.increment, { skillId: skill._id })

  return new Response(zipBlob, {
    status: 200,
    headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': `attachment; filename="${slug}-${version.version}.zip"`,
      'Cache-Control': 'private, max-age=60',
    },
  })
})

export const increment = mutation({
  args: { skillId: v.id('skills') },
  handler: async (ctx, args) => {
    const skill = await ctx.db.get(args.skillId)
    if (!skill) return
    await insertStatEvent(ctx, {
      skillId: skill._id,
      kind: 'download',
    })
  },
})
