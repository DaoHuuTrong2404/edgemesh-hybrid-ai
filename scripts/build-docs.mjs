import {
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const distDir = join(root, "dist");
const docsDir = join(root, "docs");

const distHtmlPath = join(distDir, "index.html");
if (!existsSync(distHtmlPath)) {
	throw new Error("dist/index.html missing — run `vite build` first.");
}

let html = readFileSync(distHtmlPath, "utf8");
const assetsDir = join(distDir, "assets");
const assetFiles = existsSync(assetsDir) ? readdirSync(assetsDir) : [];

for (const file of assetFiles) {
	const fullPath = join(assetsDir, file);
	if (file.endsWith(".css")) {
		const css = readFileSync(fullPath, "utf8");
		const cssRe = new RegExp(
			`<link[^>]+href=["'][^"']*${file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["'][^>]*>`,
			"i",
		);
		html = html.replace(cssRe, () => `<style>\n${css}\n</style>`);
	} else if (file.endsWith(".js")) {
		const js = readFileSync(fullPath, "utf8").replace(
			/<\/script>/gi,
			"<\\/script>",
		);
		const jsRe = new RegExp(
			`<script[^>]+src=["'][^"']*${file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["'][^>]*><\\/script>`,
			"i",
		);
		html = html.replace(jsRe, () => `<script type="module">\n${js}\n</script>`);
	}
}

mkdirSync(docsDir, { recursive: true });
const outPath = join(docsDir, "index.html");
writeFileSync(outPath, html, "utf8");
console.log(
	`Built standalone single-file demo -> ${outPath} (${html.length} bytes)`,
);
