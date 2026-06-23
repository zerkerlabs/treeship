import { NextResponse, type NextRequest } from 'next/server';

// "Append `.md` to any docs URL" -> serve that page as clean markdown.
// A next.config rewrite cannot do this: a slash-matching param followed by a
// `.md` suffix trips Next's "catch-all must be last" rule. Middleware has full
// rewrite control and no such restriction, so `/reference/predicates.md`
// rewrites to the markdown route handler at `/llms-content/reference/predicates`.
export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (pathname.endsWith('.md')) {
    const url = req.nextUrl.clone();
    url.pathname = `/llms-content${pathname.slice(0, -'.md'.length)}`;
    return NextResponse.rewrite(url);
  }
  return NextResponse.next();
}

// Run on everything except Next internals and static assets; the handler only
// acts on `.md` paths, so the common case is a cheap pass-through.
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
