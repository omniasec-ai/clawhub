import { describe, expect, it, vi } from 'vitest'

vi.mock('@tanstack/react-router', () => ({
  createFileRoute: () => (config: { beforeLoad?: unknown }) => ({ __config: config }),
  redirect: (options: unknown) => ({ redirect: options }),
}))

import { Route } from '../routes/search'

describe('search route', () => {
  it('redirects to the skills index', () => {
    const route = Route as unknown as {
      __config: {
        beforeLoad?: (args: { search: { q?: string; highlighted?: boolean } }) => void
      }
    }
    const beforeLoad = route.__config.beforeLoad as (args: {
      search: { q?: string; highlighted?: boolean }
    }) => void
    let thrown: unknown

    try {
      beforeLoad({ search: { q: 'crab', highlighted: true } })
    } catch (error) {
      thrown = error
    }

    expect(thrown).toEqual({
      redirect: {
        to: '/skills',
        search: {
          q: 'crab',
          highlighted: true,
        },
        replace: true,
      },
    })
  })

  it('redirects to the skills index without query', () => {
    const route = Route as unknown as {
      __config: {
        beforeLoad?: (args: { search: { q?: string; highlighted?: boolean } }) => void
      }
    }
    const beforeLoad = route.__config.beforeLoad as (args: {
      search: { q?: string; highlighted?: boolean }
    }) => void
    let thrown: unknown

    try {
      beforeLoad({ search: {} })
    } catch (error) {
      thrown = error
    }

    expect(thrown).toEqual({
      redirect: {
        to: '/skills',
        search: {
          q: undefined,
          highlighted: undefined,
        },
        replace: true,
      },
    })
  })
})
