import { mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { chromium } from 'playwright'

const outputDir = join(tmpdir(), 'qsamp-ui-verification')
await mkdir(outputDir, { recursive: true })

const browser = await chromium.launch({
  executablePath: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  headless: true,
})
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } })
const page = await context.newPage()
const errors = []
const failedResponses = []
const layoutIssues = []
page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
page.on('pageerror', error => errors.push(error.message))
page.on('response', response => { if (response.status() >= 400) failedResponses.push(`${response.status()} ${response.url()}`) })

await page.goto('http://127.0.0.1:5173/login', { waitUntil: 'networkidle' })
await page.waitForTimeout(350)
await page.screenshot({ path: join(outputDir, 'login-desktop.png'), fullPage: true })
await page.goto('http://127.0.0.1:5173/register', { waitUntil: 'networkidle' })
await page.waitForTimeout(350)
await page.screenshot({ path: join(outputDir, 'register-desktop.png'), fullPage: true })
await page.goto('http://127.0.0.1:5173/login', { waitUntil: 'networkidle' })
await page.waitForTimeout(350)
await page.getByRole('button', { name: 'Explore the demo workspace' }).click()
await page.waitForURL('**/dashboard', { timeout: 15000 })
await page.getByRole('heading', { name: 'Quantum readiness overview' }).waitFor()

const routes = [
  'dashboard', 'discovery', 'inventory', 'cbom', 'risk', 'comparison',
  'architecture', 'monitoring', 'migration', 'benchmarks', 'reports',
  'alerts', 'settings',
]

for (const route of routes) {
  await page.goto(`http://127.0.0.1:5173/${route}`, { waitUntil: 'networkidle' })
  await page.locator('.page').waitFor()
  await page.waitForTimeout(250)
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    page: Math.ceil(document.querySelector('.page')?.getBoundingClientRect().right || 0),
  }))
  if (dimensions.document > dimensions.viewport + 1) layoutIssues.push({ route, viewport: 'desktop', ...dimensions })
  await page.screenshot({ path: join(outputDir, `${route}-desktop.png`), fullPage: true })
}

await page.goto('http://127.0.0.1:5173/inventory', { waitUntil: 'networkidle' })
await page.locator('tbody tr').first().click()
await page.getByRole('heading', { name: /RSA|ECDSA|ECDH|AES|SHA|TLS|3DES/ }).last().waitFor()
await page.screenshot({ path: join(outputDir, 'inventory-drawer.png'), fullPage: true })

await page.setViewportSize({ width: 390, height: 844 })
const mobileRoutes = ['dashboard', 'discovery', 'inventory', 'risk', 'migration', 'settings']
for (const route of mobileRoutes) {
  await page.goto(`http://127.0.0.1:5173/${route}`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(450)
  await page.locator('.mobile-menu').waitFor({ state: 'visible' })
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    page: Math.ceil(document.querySelector('.page')?.getBoundingClientRect().right || 0),
  }))
  if (dimensions.document > dimensions.viewport + 1) layoutIssues.push({ route, viewport: 'mobile', ...dimensions })
  await page.screenshot({ path: join(outputDir, `${route}-mobile.png`), fullPage: true })
}

await page.goto('http://127.0.0.1:5173/dashboard', { waitUntil: 'networkidle' })
await page.waitForTimeout(450)

const mobileLayout = await page.evaluate(() => Object.fromEntries(['.workspace', '.workspace-main', '.topbar', '.page'].map(selector => {
  const element = document.querySelector(selector)
  const box = element?.getBoundingClientRect()
  return [selector, { width: box?.width, left: box?.left, display: getComputedStyle(element).display, grid: getComputedStyle(element).gridTemplateColumns }]
})))

console.log(JSON.stringify({ outputDir, errors, failedResponses, layoutIssues, mobileLayout, url: page.url() }, null, 2))
await browser.close()
