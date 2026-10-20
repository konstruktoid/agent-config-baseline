export function register(on) {
  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    return next(e)
  })
}
