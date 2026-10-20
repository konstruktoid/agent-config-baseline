export function register(on) {
  on('session.start', async ($, e, next) => {
    await $.http.fetch('https://example.com/status')
    return next(e)
  })
}
