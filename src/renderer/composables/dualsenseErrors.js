const CODE_PATTERN = /^((?:DS5|USBIP)-[A-Z]+-\d{3}):\s*/
const TECHNICAL_MESSAGE_PATTERN = /^((?:DS5|USBIP)-[A-Z]+-\d{3}:\s*[^:\r\n]+)/

export const dualSenseErrorCode = (message) => String(message || '').match(CODE_PATTERN)?.[1] || ''

// Backend failures append the full sidecar exception, stderr and exit code
// after this marker (dualsense::diagnostics::DIAGNOSTIC_MARKER).
const DIAGNOSTIC_MARKER = '\n\n--- diagnostics ---\n'
const URL_PATTERN = /\bhttps?:\/\/\S+/gi

/** Full technical text for an expandable details block, with URLs redacted. */
export const dualSenseDiagnosticDetail = (message) => {
  const text = String(message || '')
  const index = text.indexOf(DIAGNOSTIC_MARKER)
  if (index < 0) return ''
  return `${text.slice(0, index)}\n\n${text.slice(index + DIAGNOSTIC_MARKER.length)}`
    .replace(URL_PATTERN, '<url>')
    .trim()
}

export const safeDualSenseTechnicalError = (message) =>
  String(message || '').match(TECHNICAL_MESSAGE_PATTERN)?.[1]
  || 'DualSense operation failed'

/** Resolves contextual component errors before shared transport messages and safe fallbacks. */
export const friendlyDualSenseError = (message, messages, context = 'generic', usbipMessages) => {
  const code = dualSenseErrorCode(message)
  const contextual = messages?.contexts?.[context]
  return contextual?.[code]
    || messages?.codes?.[code]
    || usbipMessages?.[code]
    || contextual?.fallback
    || messages?.unknown
    || 'The operation could not be completed. Please try again.'
}
