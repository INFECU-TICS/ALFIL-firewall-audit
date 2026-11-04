import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import guia from "../content/guia.md?raw";

const slug = (text) =>
  String(text)
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");

const textOf = (children) =>
  [].concat(children).map((c) => (typeof c === "string" ? c : c?.props ? textOf(c.props.children) : "")).join("");

// Índice: encabezados ## y ### fuera de bloques de código
function buildToc(md) {
  let inCode = false;
  const toc = [];
  for (const line of md.split("\n")) {
    if (line.startsWith("```")) inCode = !inCode;
    if (inCode) continue;
    const m = /^(##|###)\s+(.+)$/.exec(line);
    if (m) toc.push({ level: m[1].length, text: m[2], id: slug(m[2]) });
  }
  return toc;
}

const heading = (Tag, cls) => ({ children }) => (
  <Tag id={slug(textOf(children))} className={`${cls} scroll-mt-20`}>{children}</Tag>
);

const components = {
  h1: heading("h1", "text-3xl font-bold text-gray-900 mb-4"),
  h2: heading("h2", "text-xl font-semibold text-gray-900 mt-10 mb-3 pb-2 border-b border-gray-200"),
  h3: heading("h3", "text-base font-semibold text-gray-800 mt-6 mb-2"),
  p: ({ children }) => <p className="text-sm text-gray-700 leading-relaxed my-3">{children}</p>,
  ul: ({ children }) => <ul className="list-disc pl-6 my-3 space-y-1 text-sm text-gray-700">{children}</ul>,
  ol: ({ children }) => <ol className="list-decimal pl-6 my-3 space-y-1 text-sm text-gray-700">{children}</ol>,
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noreferrer" className="text-blue-700 underline hover:text-blue-900">{children}</a>
  ),
  blockquote: ({ children }) => (
    <blockquote className="border-l-4 border-blue-300 bg-blue-50 px-4 py-1 my-4 rounded-r text-blue-900">{children}</blockquote>
  ),
  table: ({ children }) => (
    <div className="overflow-x-auto my-4 rounded-lg border border-gray-200">
      <table className="min-w-full text-sm">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-gray-50 text-left text-gray-700">{children}</thead>,
  th: ({ children }) => <th className="px-3 py-2 font-semibold border-b border-gray-200">{children}</th>,
  td: ({ children }) => <td className="px-3 py-2 border-b border-gray-100 align-top text-gray-700">{children}</td>,
  pre: ({ children }) => (
    <pre className="bg-gray-900 text-gray-100 text-xs rounded-lg p-4 my-4 overflow-x-auto">{children}</pre>
  ),
  code: ({ className, children }) =>
    className ? (
      <code className={className}>{children}</code>
    ) : (
      <code className="bg-gray-100 text-gray-800 rounded px-1 py-0.5 text-[0.85em] font-mono">{children}</code>
    ),
};

export default function DocsPage() {
  const toc = buildToc(guia);
  return (
    <div className="flex gap-8 items-start">
      <nav className="hidden lg:block w-64 flex-shrink-0 sticky top-4 max-h-[calc(100vh-2rem)] overflow-y-auto text-sm">
        <p className="font-semibold text-gray-500 uppercase text-xs tracking-wide mb-2">Contenido</p>
        <ul className="space-y-1">
          {toc.map((t) => (
            <li key={t.id} className={t.level === 3 ? "pl-4" : ""}>
              <a href={`#${t.id}`} className={t.level === 2 ? "text-gray-800 font-medium hover:text-blue-700" : "text-gray-500 hover:text-blue-700"}>
                {t.text}
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <article className="min-w-0 flex-1 max-w-4xl">
        <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>{guia}</ReactMarkdown>
      </article>
    </div>
  );
}
