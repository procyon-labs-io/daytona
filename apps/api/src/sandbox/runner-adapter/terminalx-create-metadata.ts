/*
 * Copyright 2026 TerminalX contributors
 * SPDX-License-Identifier: AGPL-3.0
 */

const TERMINALX_ARTIFACT_DIGEST_LABEL = 'terminalx.artifact'
const TERMINALX_REVISION_LABEL = 'terminalx.revision'
const TERMINALX_PLAN_DIGEST_LABEL = 'terminalx.plan'

const TERMINALX_CREATE_LABELS = [
  TERMINALX_ARTIFACT_DIGEST_LABEL,
  TERMINALX_REVISION_LABEL,
  TERMINALX_PLAN_DIGEST_LABEL,
] as const

const SHA256_DIGEST = /^[0-9a-f]{64}$/
const CANONICAL_REVISION = /^[1-9][0-9]*$/
const MAXIMUM_JAVASCRIPT_INTEGER = BigInt(Number.MAX_SAFE_INTEGER)
const MAXIMUM_CANONICAL_REVISION_LENGTH = String(Number.MAX_SAFE_INTEGER).length

/**
 * Projects the immutable TerminalX logical identity into runner create metadata.
 *
 * Daytona's public Sandbox labels live in the API database and are not normally
 * forwarded to the runner. A hardened Sandbox needs exactly these three values
 * on its Docker config before the container exists; Docker labels cannot be
 * changed during the later provider-bound activation phase.
 */
export function terminalXCreateMetadata(
  labels: Record<string, string> | null | undefined,
  ordinaryMetadata: Record<string, string> | undefined,
): Record<string, string> | undefined {
  const present = TERMINALX_CREATE_LABELS.filter((label) => labels?.[label] !== undefined)
  if (present.length === 0) {
    return ordinaryMetadata
  }
  if (present.length !== TERMINALX_CREATE_LABELS.length) {
    throw new Error('TerminalX Sandbox creation requires all immutable binding labels')
  }

  const artifactDigest = labels?.[TERMINALX_ARTIFACT_DIGEST_LABEL]
  const revision = labels?.[TERMINALX_REVISION_LABEL]
  const planDigest = labels?.[TERMINALX_PLAN_DIGEST_LABEL]
  if (
    artifactDigest === undefined ||
    revision === undefined ||
    planDigest === undefined ||
    !SHA256_DIGEST.test(artifactDigest) ||
    !SHA256_DIGEST.test(planDigest) ||
    !CANONICAL_REVISION.test(revision) ||
    revision.length > MAXIMUM_CANONICAL_REVISION_LENGTH ||
    BigInt(revision) > MAXIMUM_JAVASCRIPT_INTEGER
  ) {
    throw new Error('TerminalX Sandbox immutable binding labels are invalid')
  }

  return {
    [TERMINALX_ARTIFACT_DIGEST_LABEL]: artifactDigest,
    [TERMINALX_REVISION_LABEL]: revision,
    [TERMINALX_PLAN_DIGEST_LABEL]: planDigest,
  }
}
