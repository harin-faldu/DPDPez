// API client. OWNER: Manan
import axios from 'axios'

const client = axios.create({
  baseURL: '/api',
  timeout: 120000,
})

/**
 * Normalise anything axios throws into { message, status, detail } so no
 * component ever has to reach into axios internals.
 */
function normaliseError(error) {
  const status = error?.response?.status ?? null
  const payload = error?.response?.data
  const detail =
    (typeof payload === 'string' && payload) ||
    payload?.detail ||
    payload?.message ||
    payload?.error ||
    null

  let message
  if (typeof detail === 'string' && detail.trim()) {
    message = detail
  } else if (Array.isArray(detail) && detail.length) {
    // FastAPI validation errors arrive as a list of objects.
    message = detail
      .map((item) => item?.msg || item?.message)
      .filter(Boolean)
      .join('; ')
  } else if (error?.code === 'ECONNABORTED') {
    message = 'The request timed out before the server replied.'
  } else if (!error?.response) {
    message = 'Could not reach the scanner API. Check that the backend is running.'
  } else if (status === 404) {
    message = 'That scan could not be found.'
  } else if (status >= 500) {
    message = 'The scanner API returned a server error.'
  } else {
    message = error?.message || 'Unexpected error.'
  }

  const normalised = new Error(message)
  normalised.status = status
  normalised.detail = detail
  return normalised
}

// Responses are unwrapped here, so every call below resolves with the body.
client.interceptors.response.use(
  (response) => response.data,
  (error) => Promise.reject(normaliseError(error)),
)

// policyScanId is optional on both: given one, that stage tests the policy
// scan's claims against what it observes and writes the verdict back onto it,
// which is how a flow run gets stage 2 and stage 3 to build on stage 1
// without the rules engine ever seeing two kinds of evidence at once.
export const startPolicyScan = (url, policyUrls = []) =>
  client.post('/scan/policy', { url, policy_urls: policyUrls })
export const startWebScan = (url, policyScanId = null) =>
  client.post('/scan/web', { url, policy_scan_id: policyScanId || undefined })
export const startCodeScan = (file, policyScanId = null) => {
  const form = new FormData()
  form.append('file', file)
  if (policyScanId) form.append('policy_scan_id', policyScanId)
  return client.post('/scan/code', form)
}
export const getScan = (scanId) => client.get(`/scan/${scanId}`)
export const getScorecard = (scanId) => client.get(`/scans/${scanId}/scorecard`)
export const getFindings = (scanId) => client.get(`/scans/${scanId}/findings`)
export const getDataFlows = (scanId) => client.get(`/scans/${scanId}/data-flows`)

// Stage 4. Every id is optional and independent; passing just policyScanId
// reads that stage's checks and claims with no rule verdicts, which is also
// how a lone policy scan's own results page renders.
export const getAggregate = ({ policyScanId, webScanId, codeScanId } = {}) =>
  client.get('/scans/aggregate', {
    params: {
      policy_scan_id: policyScanId || undefined,
      web_scan_id: webScanId || undefined,
      code_scan_id: codeScanId || undefined,
    },
  })

export default client
