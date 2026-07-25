/*
 * Copyright 2026 TerminalX contributors
 * SPDX-License-Identifier: AGPL-3.0
 */

import { terminalXCreateMetadata } from './terminalx-create-metadata'

const artifactDigest = '1'.repeat(64)
const planDigest = '2'.repeat(64)

describe('terminalXCreateMetadata', () => {
  it('leaves ordinary Daytona metadata unchanged', () => {
    const metadata = { organizationId: 'organization-1' }
    expect(terminalXCreateMetadata({ feature: 'ordinary' }, metadata)).toBe(metadata)
  })

  it('projects only the exact immutable TerminalX binding', () => {
    expect(
      terminalXCreateMetadata(
        {
          feature: 'ignored',
          'terminalx.artifact': artifactDigest,
          'terminalx.revision': '7',
          'terminalx.plan': planDigest,
        },
        { organizationId: 'must-not-cross-the-hardened-boundary' },
      ),
    ).toEqual({
      'terminalx.artifact': artifactDigest,
      'terminalx.revision': '7',
      'terminalx.plan': planDigest,
    })
  })

  it.each([
    [{ 'terminalx.artifact': artifactDigest }],
    [
      {
        'terminalx.artifact': artifactDigest,
        'terminalx.revision': '0',
        'terminalx.plan': planDigest,
      },
    ],
    [
      {
        'terminalx.artifact': artifactDigest,
        'terminalx.revision': '01',
        'terminalx.plan': planDigest,
      },
    ],
    [
      {
        'terminalx.artifact': artifactDigest,
        'terminalx.revision': String(Number.MAX_SAFE_INTEGER + 1),
        'terminalx.plan': planDigest,
      },
    ],
    [
      {
        'terminalx.artifact': artifactDigest,
        'terminalx.revision': `1${'0'.repeat(100_000)}`,
        'terminalx.plan': planDigest,
      },
    ],
    [
      {
        'terminalx.artifact': 'A'.repeat(64),
        'terminalx.revision': '1',
        'terminalx.plan': planDigest,
      },
    ],
  ])('rejects incomplete or non-canonical bindings', (labels) => {
    expect(() => terminalXCreateMetadata(labels, undefined)).toThrow()
  })
})
