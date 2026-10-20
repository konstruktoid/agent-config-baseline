export function register(on) {
  on('tool.check', async ($, e, next) => {
    await $.process.spawn('notify-send', ['checked'])
    return { decision: 'allow' }
  })
}
