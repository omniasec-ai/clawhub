export type VTScanResult = {
    status: 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error'
    maliciousCount: number
    suspiciousCount: number
    harmlessCount: number
    undetectedCount: number
}

export async function checkFileHash(sha256: string): Promise<VTScanResult> {
    const apiKey = process.env.VIRUSTOTAL_API_KEY
    if (!apiKey) {
        console.warn('VIRUSTOTAL_API_KEY is not configured')
        return { status: 'unknown', maliciousCount: 0, suspiciousCount: 0, harmlessCount: 0, undetectedCount: 0 }
    }

    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
            headers: {
                'x-apikey': apiKey,
            },
        })

        if (response.status === 404) {
            return { status: 'unknown', maliciousCount: 0, suspiciousCount: 0, harmlessCount: 0, undetectedCount: 0 }
        }

        if (!response.ok) {
            const errorText = await response.text()
            console.error(`VirusTotal API error: ${response.status} ${errorText}`)
            return { status: 'error', maliciousCount: 0, suspiciousCount: 0, harmlessCount: 0, undetectedCount: 0 }
        }

        const payload = await response.json()
        const stats = payload.data?.attributes?.last_analysis_stats

        if (!stats) {
            return { status: 'unknown', maliciousCount: 0, suspiciousCount: 0, harmlessCount: 0, undetectedCount: 0 }
        }

        const malicious = stats.malicious || 0
        const suspicious = stats.suspicious || 0
        const harmless = stats.harmless || 0
        const undetected = stats.undetected || 0

        let status: VTScanResult['status'] = 'clean'
        if (malicious > 0) {
            status = 'malicious'
        } else if (suspicious > 0) {
            status = 'suspicious'
        }

        return {
            status,
            maliciousCount: malicious,
            suspiciousCount: suspicious,
            harmlessCount: harmless,
            undetectedCount: undetected,
        }
    } catch (error) {
        console.error('Failed to check file hash with VirusTotal', error)
        return { status: 'error', maliciousCount: 0, suspiciousCount: 0, harmlessCount: 0, undetectedCount: 0 }
    }
}

export async function uploadFile(fileName: string, content: Blob): Promise<string | null> {
    const apiKey = process.env.VIRUSTOTAL_API_KEY
    if (!apiKey) return null

    try {
        const formData = new FormData()
        formData.append('file', content, fileName)

        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
            },
            body: formData,
        })

        if (!response.ok) {
            const errorText = await response.text()
            console.error(`VirusTotal upload error: ${response.status} ${errorText}`)
            return null
        }

        const payload = await response.json()
        return payload.data?.id
    } catch (error) {
        console.error('Failed to upload file to VirusTotal', error)
        return null
    }
}

export async function getAnalysisResult(
    analysisId: string,
): Promise<VTScanResult | { status: 'queued' | 'in_progress' }> {
    const apiKey = process.env.VIRUSTOTAL_API_KEY
    if (!apiKey) return { status: 'queued' }

    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: {
                'x-apikey': apiKey,
            },
        })

        if (!response.ok) {
            const errorText = await response.text()
            console.error(`VirusTotal analysis retrieval error: ${response.status} ${errorText}`)
            return { status: 'queued' }
        }

        const payload = await response.json()
        const attributes = payload.data?.attributes
        const status = attributes?.status

        if (status === 'queued' || status === 'in_progress') {
            return { status }
        }

        const stats = attributes?.stats
        if (!stats) return { status: 'queued' }

        const malicious = stats.malicious || 0
        const suspicious = stats.suspicious || 0
        const harmless = stats.harmless || 0
        const undetected = stats.undetected || 0

        let finalStatus: VTScanResult['status'] = 'clean'
        if (malicious > 0) {
            finalStatus = 'malicious'
        } else if (suspicious > 0) {
            finalStatus = 'suspicious'
        }

        return {
            status: finalStatus,
            maliciousCount: malicious,
            suspiciousCount: suspicious,
            harmlessCount: harmless,
            undetectedCount: undetected,
        }
    } catch (error) {
        console.error('Failed to get VirusTotal analysis result', error)
        return { status: 'queued' }
    }
}
